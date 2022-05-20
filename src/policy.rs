#![allow(clippy::module_name_repetitions)]

use crate::error::Error;
use serde::{Deserialize, Deserializer, Serialize};
use sha3::{Digest, Sha3_256};
use std::{
    collections::{BinaryHeap, HashMap},
    convert::TryFrom,
    fmt::{Debug, Display},
    ops::{BitAnd, BitOr},
};

const OPERATOR_SIZE: usize = 2;

// An attribute in a policy group is characterized by the policy name (axis)
// and its own particular name
#[derive(Hash, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct Attribute {
    axis: String,
    name: String,
}

impl Attribute {
    /// Create a Policy Attribute.
    ///
    /// Shortcut for
    /// ```ignore
    /// Attribute {
    ///     axis: axis.to_owned(),
    ///     name: name.to_owned(),
    /// }
    /// ```
    pub fn new(axis: &str, name: &str) -> Self {
        Self {
            axis: axis.to_owned(),
            name: name.to_owned(),
        }
    }
    pub fn axis(&self) -> String {
        self.axis.to_owned()
    }

    pub fn name(&self) -> String {
        self.name.to_owned()
    }
}

impl Debug for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}::{}", &self.axis, &self.name))
    }
}

impl From<(&str, &str)> for Attribute {
    fn from(input: (&str, &str)) -> Self {
        Attribute {
            axis: input.0.to_owned(),
            name: input.1.to_owned(),
        }
    }
}

impl From<(String, String)> for Attribute {
    fn from(input: (String, String)) -> Self {
        Attribute {
            axis: input.0,
            name: input.1,
        }
    }
}

impl TryFrom<&str> for Attribute {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s.is_empty() {
            return Err(Error::InvalidAttribute(s.to_string()));
        }
        if s.matches("::").count() != 1 {
            return Err(Error::InvalidAttribute(format!(
                "separator '::' expected once in {s}"
            )));
        }

        let attribute_str = s.trim();
        let split = attribute_str
            .split("::")
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        if split[0].is_empty() || split[1].is_empty() {
            return Err(Error::InvalidAttribute(format!(
                "empty axis or empty name in {s}"
            )));
        }
        Ok(Self {
            axis: split[0].to_owned(),
            name: split[1].to_owned(),
        })
    }
}

impl std::fmt::Display for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.axis, self.name)
    }
}

impl serde::Serialize for Attribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Serialize::serialize(&format!("{}::{}", self.axis, self.name), serializer)
    }
}

impl<'de> Deserialize<'de> for Attribute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = String::deserialize(deserializer)?;
        let split = helper
            .split("::")
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        Ok(Attribute {
            axis: split[0].clone(),
            name: split[1].clone(),
        })
    }
}

// An `AccessPolicy` is a boolean expression over attributes
// Only `positive` literals are allowed (no negation)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AccessPolicy {
    Attr(Attribute),
    And(Box<AccessPolicy>, Box<AccessPolicy>),
    Or(Box<AccessPolicy>, Box<AccessPolicy>),
    All, // indicates we want the disjonction of all attributes
}

impl PartialEq for AccessPolicy {
    fn eq(&self, other: &Self) -> bool {
        let mut attributes_mapping = HashMap::<Attribute, u32>::new();
        let left_to_u32 = self.to_u32(&mut attributes_mapping);
        let right_to_u32 = other.to_u32(&mut attributes_mapping);
        if left_to_u32 != right_to_u32 {
            false
        } else {
            self.attributes() == other.attributes()
        }
    }
}

impl AccessPolicy {
    /// Create an Access Policy
    /// based on a single Policy Attribute.
    ///
    /// Shortcut for
    /// ```ignore
    /// AccessPolicy::Attr(Attribute {
    ///     axis: axis.to_owned(),
    ///     name: name.to_owned(),
    /// })
    /// ```
    ///
    /// Access Policies can easily be created using it
    /// ```ignore
    /// let access_policy =
    ///     ap("Security Level", "level 4") & (ap("Department", "MKG") | ap("Department", "FIN"));
    /// ```
    pub fn new(axis: &str, attribute: &str) -> Self {
        Self::Attr(Attribute {
            axis: axis.to_owned(),
            name: attribute.to_owned(),
        })
    }

    /// Returns the list of combinations that can be built using the values of
    /// each attribute in the given access policy. This corresponds to an OR
    /// expression of AND expressions.
    ///
    /// - `policy`  : global policy
    pub(crate) fn to_attribute_combinations(
        &self,
        policy: &Policy,
    ) -> Result<Vec<Vec<u32>>, Error> {
        match self {
            AccessPolicy::Attr(attr) => {
                let mut res = vec![];
                let (attribute_names, is_hierarchical) = policy
                    .store()
                    .get(&attr.axis())
                    .ok_or_else(|| Error::UnknownAuthorisation(attr.axis()))?;
                res.extend(
                    policy
                        .attribute_values(attr)?
                        .iter()
                        .map(|&value| vec![value])
                        .collect::<Vec<Vec<u32>>>(),
                );
                if *is_hierarchical {
                    // add attribute values for all attributes below the given one
                    for name in attribute_names.iter() {
                        if *name == attr.name() {
                            break;
                        }
                        res.extend(
                            policy
                                .attribute_values(&Attribute::new(&attr.axis(), name))?
                                .iter()
                                .map(|&value| vec![value])
                                .collect::<Vec<Vec<u32>>>(),
                        );
                    }
                }
                Ok(res)
            }
            AccessPolicy::And(attr1, attr2) => {
                let mut res = vec![];
                // avoid computing this many times
                let attribut_list_2 = attr2.to_attribute_combinations(policy)?;
                for value1 in attr1.to_attribute_combinations(policy)? {
                    for value2 in attribut_list_2.iter() {
                        let mut combined = Vec::with_capacity(value1.len() + value2.len());
                        combined.extend_from_slice(&value1);
                        combined.extend_from_slice(value2);
                        res.push(combined)
                    }
                }
                Ok(res)
            }
            AccessPolicy::Or(attr1, attr2) => {
                let mut res = attr1.to_attribute_combinations(policy)?;
                res.extend(attr2.to_attribute_combinations(policy)?);
                Ok(res)
            }
            // TODO: check if this is correct
            AccessPolicy::All => Ok(vec![vec![]]),
        }
    }

    /// Convert policy to integer value (for comparison).
    /// Each attribute is mapped to an integer value and the algebraic
    /// expression is applied with those values.
    /// We must keep a mapping of each attribute to the corresponding integer
    /// value in order to avoid having 2 different attributes with same integer
    /// value
    fn to_u32(&self, attribute_mapping: &mut HashMap<Attribute, u32>) -> u32 {
        match self {
            AccessPolicy::Attr(attr) => {
                if let Some(integer_value) = attribute_mapping.get(attr) {
                    *integer_value
                } else {
                    // To assign an integer value to a new attribute, we take the current max
                    // integer value + 1.
                    // Initial value starts at 1.
                    let max = attribute_mapping
                        .values()
                        .max()
                        .map(|max| *max + 1)
                        .unwrap_or(1);
                    attribute_mapping.insert(attr.clone(), max);
                    max
                }
            }
            AccessPolicy::And(l, r) => l.to_u32(attribute_mapping) * r.to_u32(attribute_mapping),
            AccessPolicy::Or(l, r) => l.to_u32(attribute_mapping) + r.to_u32(attribute_mapping),
            AccessPolicy::All => 0,
        }
    }

    /// Generate an access policy from a map of policy access names to policy
    /// attributes e.g.
    /// ```json
    /// {
    ///     "Department": ["HR","FIN"],
    ///     "Level": ["level_2"],
    /// }
    /// ```
    /// The axes are ORed between each others while the attributes
    /// of each axis are ANDed.
    ///
    /// The example above would generate the access policy
    ///
    /// `Department("HR" OR "FIN") AND Level("level_2")`
    pub fn from_axes(
        axes_attributes: &HashMap<String, Vec<String>>,
    ) -> Result<AccessPolicy, Error> {
        let mut access_policies: Vec<AccessPolicy> = Vec::with_capacity(axes_attributes.len());
        for (axis, attributes) in axes_attributes {
            access_policies.push(
                attributes
                    .iter()
                    .map(|x| Attribute::new(axis, x).into())
                    .reduce(BitOr::bitor)
                    .ok_or_else(|| Error::MissingAttribute {
                        item: None,
                        axis_name: Some(axis.to_owned()),
                    })?,
            );
        }
        let access_policy = access_policies
            .iter()
            .cloned()
            .reduce(BitAnd::bitand)
            .ok_or_else(|| Error::MissingAxis("Empty input!".to_string()))?;
        Ok(access_policy)
    }

    /// Convert a list of attributes into an AccessPolicy. For example,
    ///
    /// `[Security::Confidentiality, Department::HR, Department::FIN]`
    ///
    /// would give:
    ///
    /// `Security::Confidentiality && (Department::HR || Department::FIN)`
    ///
    /// - `attributes`  : list of attributes
    pub fn from_attribute_list(attributes: &[Attribute]) -> Result<Self, Error> {
        let mut map = HashMap::<String, Vec<String>>::new();
        for attribute in attributes.iter() {
            let entry = map.entry(attribute.axis()).or_insert(Vec::new());
            entry.push(attribute.name());
        }
        Self::from_axes(&map)
    }

    /// This function is finding the right closing parenthesis in the boolean
    /// expression given as a string
    fn find_next_parenthesis(boolean_expression: &str) -> Result<usize, Error> {
        let mut count = 0;
        let mut right_closing_parenthesis = 0;
        // Skip first parenthesis
        for (index, c) in boolean_expression.chars().enumerate() {
            match c {
                '(' => count += 1,
                ')' => count -= 1,
                _ => {}
            };
            if count < 0 {
                right_closing_parenthesis = index;
                break;
            }
        }
        if right_closing_parenthesis == 0 {
            return Err(Error::InvalidBooleanExpression(format!(
                "Missing closing parenthesis in boolean expression {boolean_expression}"
            )));
        }
        Ok(right_closing_parenthesis)
    }

    /// Sanitize spaces in boolean expression around parenthesis and operators
    /// but keep spaces inside axis & attribute names We remove useless
    /// spaces:
    /// * before and after operator. Example: `A && B` --> `A&&B`
    /// * before and after parenthesis. Example: `(A && B)` --> `(A&&B)`
    /// * But keep these spaces: `(A::b c || d e::F)` --> `(A::b c||d e::F)`
    fn sanitize_spaces(boolean_expression: &str) -> String {
        let trim_closure = |expr: &str, separator: &str| -> String {
            let expression = expr
                .split(separator)
                .collect::<Vec<_>>()
                .into_iter()
                .map(|s| s.trim())
                .collect::<Vec<_>>();
            let mut expression_chars = Vec::<char>::new();
            for (i, s) in expression.iter().enumerate() {
                if i == 0 && s.is_empty() {
                    expression_chars.append(&mut separator.chars().collect::<Vec<_>>());
                } else {
                    expression_chars.append(&mut s.chars().collect::<Vec<_>>());
                    if i != expression.len() - 1 {
                        expression_chars.append(&mut separator.chars().collect::<Vec<_>>());
                    }
                }
            }
            expression_chars.iter().collect::<String>()
        };

        // Remove successively spaces around `special` substrings
        let mut output = boolean_expression.to_string();
        for sep in ["(", ")", "||", "&&", "::"] {
            output = trim_closure(output.as_str(), sep);
        }

        output
    }

    /// This function takes a boolean expression and splits it into 3 parts:
    /// - left part
    /// - operator
    /// - right part
    ///
    /// Example: "Department::HR && Level::level_2" will be decomposed in:
    /// - Department::HR
    /// - &&
    /// - Level::level_2
    fn decompose_expression(
        boolean_expression: &str,
        split_position: usize,
    ) -> Result<(String, Option<String>, Option<String>), Error> {
        if split_position > boolean_expression.len() {
            return Err(Error::InvalidBooleanExpression(format!(
                "Cannot split boolean expression {boolean_expression} at position \
                 {split_position} since {split_position} is greater than the size of \
                 {boolean_expression}"
            )));
        }

        // Put aside `Department::HR` from `Department::HR && Level::level_2`
        let left_part = &boolean_expression[..split_position];
        if split_position == boolean_expression.len() {
            return Ok((left_part.to_string(), None, None));
        }

        // Put aside `&&` from `Department::HR && Level::level_2`
        let next_char = boolean_expression
            .chars()
            .nth(split_position)
            .unwrap_or_default();
        let mut split_position = split_position;
        if next_char == ')' {
            split_position += 1;
        }
        if split_position == boolean_expression.len() {
            return Ok((left_part.to_string(), None, None));
        }
        let operator = &boolean_expression[split_position..split_position + OPERATOR_SIZE];

        // Put aside `Level::level_2` from `Department::HR && Level::level_2`
        // Skip 2 next characters (parenthesis + next char)
        let right_part = &boolean_expression[split_position + OPERATOR_SIZE..];
        Ok((
            left_part.to_string(),
            Some(operator.to_string()),
            Some(right_part.to_string()),
        ))
    }

    /// Convert a boolean expression into `AccessPolicy`.
    /// Example:
    ///     input boolean expression: (Department::HR || Department::RnD) &&
    /// Level::level_2
    ///     output: corresponding access policy:
    /// And(Attr(Level::level2), Or(Attr(Department::HR),
    /// Attr(Department::RnD)))
    ///
    /// # Arguments
    ///
    /// * `boolean_expression`: expression with operators && and ||
    ///
    /// # Returns
    ///
    /// the corresponding `AccessPolicy`
    ///
    /// # Examples
    ///
    /// ```rust
    /// let boolean_expression = "(Department::HR || Department::RnD) && Level::level_2";
    /// let access_policy = cover_crypt::policy::AccessPolicy::from_boolean_expression(boolean_expression);
    /// ```
    /// # Errors
    ///
    /// Missing parenthesis or bad operators
    pub fn from_boolean_expression(boolean_expression: &str) -> Result<Self, Error> {
        let boolean_expression_example = "(Department::HR || Department::RnD) && Level::level_2";

        // Remove spaces around parenthesis and operators
        let boolean_expression = AccessPolicy::sanitize_spaces(boolean_expression);

        if !boolean_expression.contains("::") {
            return Err(Error::InvalidBooleanExpression(format!(
                "'{boolean_expression}' does not contain any attribute separator '::'. Example: \
                 {boolean_expression_example}"
            )));
        }

        // if first char is parenthesis
        let first_char = boolean_expression.chars().next().unwrap_or_default();
        if first_char == '(' {
            // Skip first parenthesis
            let boolean_expression = &boolean_expression[1..];
            // Check if formula contains a closing parenthesis
            let c = boolean_expression.matches(')').count();
            if c == 0 {
                return Err(Error::InvalidBooleanExpression(format!(
                    "closing parenthesis missing in {boolean_expression}"
                )));
            }
            // Search right closing parenthesis, avoiding false positive
            let matching_closing_parenthesis =
                AccessPolicy::find_next_parenthesis(boolean_expression)?;
            let (left_part, operator, right_part) =
                Self::decompose_expression(boolean_expression, matching_closing_parenthesis)?;
            if operator.is_none() {
                return AccessPolicy::from_boolean_expression(left_part.as_str());
            }

            let operator = operator.unwrap_or_default();
            let right_part = right_part.unwrap_or_default();
            let ap1 = Box::new(AccessPolicy::from_boolean_expression(left_part.as_str())?);
            let ap2 = Box::new(AccessPolicy::from_boolean_expression(right_part.as_str())?);
            let ap = match operator.as_str() {
                "&&" => Ok(AccessPolicy::And(ap1, ap2)),
                "||" => Ok(AccessPolicy::Or(ap1, ap2)),
                _ => Err(Error::UnsupportedOperator(operator.to_string())),
            }?;
            Ok(ap)
        } else {
            let or_position = boolean_expression.find("||");
            let and_position = boolean_expression.find("&&");

            // Get position of next operator
            let position = if or_position.is_none() && and_position.is_none() {
                0
            } else if or_position.is_none() {
                and_position.unwrap_or_default()
            } else if and_position.is_none() {
                or_position.unwrap_or_default()
            } else {
                std::cmp::min(
                    or_position.unwrap_or_default(),
                    and_position.unwrap_or_default(),
                )
            };

            if position == 0 {
                let attribute_vec = boolean_expression.split("::").collect::<Vec<_>>();

                if attribute_vec.len() != 2
                    || attribute_vec[0].is_empty()
                    || attribute_vec[1].is_empty()
                {
                    return Err(Error::InvalidBooleanExpression(format!(
                        "'{boolean_expression}' does not respect the format <axis::name>. \
                         Example: {boolean_expression_example}"
                    )));
                }
                return Ok(AccessPolicy::new(attribute_vec[0], attribute_vec[1]));
            }

            // Remove operator from input string
            let (left_part, operator, right_part) =
                Self::decompose_expression(&boolean_expression, position)?;
            if operator.is_none() {
                return AccessPolicy::from_boolean_expression(left_part.as_str());
            }
            let operator = operator.unwrap_or_default();
            let right_part = right_part.unwrap_or_default();

            let ap1 = Box::new(AccessPolicy::from_boolean_expression(left_part.as_str())?);
            let ap2 = Box::new(AccessPolicy::from_boolean_expression(right_part.as_str())?);
            let ap = match operator.as_str() {
                "&&" => Ok(AccessPolicy::And(ap1, ap2)),
                "||" => Ok(AccessPolicy::Or(ap1, ap2)),
                _ => Err(Error::UnsupportedOperator(operator.to_string())),
            }?;

            Ok(ap)
        }
    }

    pub fn attributes(&self) -> Vec<Attribute> {
        let mut attributes = self._attributes();
        attributes.sort();
        attributes
    }

    fn _attributes(&self) -> Vec<Attribute> {
        match self {
            AccessPolicy::Attr(att) => vec![att.clone()],
            AccessPolicy::And(a1, a2) | AccessPolicy::Or(a1, a2) => {
                let mut v = AccessPolicy::_attributes(a1);
                v.extend(AccessPolicy::_attributes(a2));
                v
            }

            AccessPolicy::All => vec![],
        }
    }
}

// use A & B to construct And(A, B)
impl BitAnd for AccessPolicy {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self::And(Box::new(self), Box::new(rhs))
    }
}

// use A | B to construct Or(A, B)
impl BitOr for AccessPolicy {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self::Or(Box::new(self), Box::new(rhs))
    }
}

impl From<Attribute> for AccessPolicy {
    fn from(attribute: Attribute) -> Self {
        AccessPolicy::Attr(attribute)
    }
}

// Define a policy axis by its name and its underlying attribute names
// If `hierarchical` is `true`, we assume a lexicographical order based on the
// attribute name
#[derive(Clone)]
pub(crate) struct PolicyAxis {
    name: String,
    attributes: Vec<String>,
    hierarchical: bool,
}

impl PolicyAxis {
    #[must_use]
    pub fn new(name: &str, attributes: &[&str], hierarchical: bool) -> Self {
        Self {
            name: name.to_owned(),
            attributes: attributes.iter().map(|s| s.to_string()).collect(),
            hierarchical,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.attributes.len()
    }
}

// A policy is a set of fixed policy axes, defining an inner attribute
// element for each policy axis attribute a fixed number of revocation
// addition of attributes is allowed
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Policy {
    pub(crate) last_attribute_value: u32,
    pub(crate) max_attribute_value: u32,
    // store the policies by name
    pub(crate) store: HashMap<String, (Vec<String>, bool)>,
    // mapping between (policy_name, policy_attribute) -> integer
    pub(crate) attribute_to_int: HashMap<Attribute, BinaryHeap<u32>>,
}

impl Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string(&self);
        match json {
            Ok(string) => write!(f, "{}", string),
            Err(err) => write!(f, "{}", err),
        }
    }
}

impl Policy {
    #[must_use]
    pub fn new(nb_revocation: u32) -> Self {
        Self {
            last_attribute_value: 0,
            max_attribute_value: nb_revocation,
            store: HashMap::new(),
            attribute_to_int: HashMap::new(),
        }
    }

    pub fn store(&self) -> &HashMap<String, (Vec<String>, bool)> {
        &self.store
    }

    #[must_use]
    pub fn max_attr(&self) -> u32 {
        self.max_attribute_value
    }

    /// Add a policy axis, mapping each attribute to a unique number in this
    /// `Policy`
    ///
    /// When the axis is hierarchical, attributes must be provided in descending
    /// order
    pub fn add_axis(
        mut self,
        name: &str,
        attributes: &[&str],
        hierarchical: bool,
    ) -> Result<Self, Error> {
        let axis = PolicyAxis::new(name, attributes, hierarchical);
        if axis.len() > u32::MAX as usize {
            return Err(Error::CapacityOverflow);
        }
        if (axis.len() as u32) + self.last_attribute_value > self.max_attribute_value {
            return Err(Error::CapacityOverflow);
        }
        // insert new policy
        if let Some(attr) = self.store.insert(
            axis.name.clone(),
            (axis.attributes.clone(), axis.hierarchical),
        ) {
            // already exists, reinsert previous one
            self.store.insert(axis.name.clone(), attr);
            return Err(Error::ExistingPolicy(axis.name));
        } else {
            for attr in &axis.attributes {
                self.last_attribute_value += 1;
                if self
                    .attribute_to_int
                    .insert(
                        (axis.name.clone(), attr.clone()).into(),
                        vec![self.last_attribute_value].into(),
                    )
                    .is_some()
                {
                    // must never occurs as policy is a new one
                    return Err(Error::ExistingPolicy(axis.name));
                }
            }
        }
        Ok(self)
    }

    /// Rotate an attribute, changing its underlying value with that of an
    /// unused slot
    pub fn rotate(&mut self, attr: &Attribute) -> Result<(), Error> {
        if self.last_attribute_value + 1 > self.max_attribute_value {
            return Err(Error::CapacityOverflow);
        }
        if let Some(uint) = self.attribute_to_int.get_mut(attr) {
            self.last_attribute_value += 1;
            uint.push(self.last_attribute_value);
        } else {
            return Err(Error::AttributeNotFound(format!("{:?}", attr)));
        }
        Ok(())
    }

    /// Returns the list of Attributes of this Policy
    pub fn attributes(&self) -> Vec<Attribute> {
        self.attribute_to_int.keys().cloned().collect()
    }

    /// Returns the list of all attributes values given to this Attribute
    /// over the time after rotations. The current value is returned first
    pub fn attribute_values(&self, attribute: &Attribute) -> Result<Vec<u32>, Error> {
        let mut v = self
            .attribute_to_int
            .get(attribute)
            .cloned()
            .ok_or_else(|| Error::AttributeNotFound(attribute.to_string()))?
            .into_sorted_vec();
        v.reverse();
        Ok(v)
    }

    /// Retrieve the current attributes values for the `Attribute` list
    pub fn current_values(&self, attributes: &[Attribute]) -> Result<Vec<u32>, Error> {
        let mut values: Vec<u32> = Vec::with_capacity(attributes.len());
        for att in attributes {
            let v = self
                .attribute_to_int
                .get(att)
                .and_then(std::collections::BinaryHeap::peek)
                .ok_or_else(|| Error::AttributeNotFound(format!("{:?}", att)))?;
            values.push(*v);
        }
        Ok(values)
    }
}

/// Compute the key hash of a given attribute combination. This key hash is
/// used to select a KEM key.
///
/// - `combination` : attribute combination
pub(crate) fn get_key_hash(combination: &[u32]) -> Vec<u8> {
    let mut combination = combination.to_owned();
    // the sort operation allows to get the same hash for :
    // `Department::HR || Department::FIN`
    // and
    // `Department::FIN || Department::HR`
    combination.sort_unstable();
    let mut bytes = Vec::with_capacity(combination.len() * 4);
    for value in combination {
        bytes.extend(value.to_be_bytes())
    }
    Sha3_256::digest(bytes).to_vec()
}

/// For all attributes in the given axis, return the combination of its values
/// with the values of all other remaining axes. The combination is made by
/// concatenating the Big Endian bytes of the attributes values.
///
/// - `current_axis`    : index of the axis being processed in the list of axes
/// - `axes`            : list of axes
/// - `policy`          : global policy
pub(crate) fn walk_hypercube(
    current_axis: usize,
    axes: &[&String],
    policy: &Policy,
) -> Result<Vec<Vec<u32>>, Error> {
    if current_axis == axes.len() {
        // stop if we past the last axis
        Ok(vec![])
    } else {
        // extract all attribute values from this axis
        let axis_name = axes[current_axis];
        let mut res: Vec<Vec<u32>> = vec![];
        if let Some((attribute_names, _)) = &policy.store().get(axis_name) {
            for name in attribute_names.iter() {
                res.extend(
                    policy
                        .attribute_values(&Attribute::new(axis_name, name))?
                        .iter()
                        .map(|&u| vec![u])
                        .collect::<Vec<Vec<u32>>>(),
                );
            }
        } else {
            return Err(Error::UnknownAuthorisation(format!("{:?}", axis_name)));
        }

        // combine these values with all attribute values from the next axis
        let mut combinations: Vec<Vec<u32>> = vec![];
        for v in res {
            let other_values = walk_hypercube(current_axis + 1, axes, policy)?;
            if !other_values.is_empty() {
                for ov in other_values {
                    let mut combined = Vec::with_capacity(ov.len() + v.len());
                    combined.extend_from_slice(&v);
                    combined.extend_from_slice(&ov);
                    combinations.push(combined);
                }
            } else {
                combinations.push(v);
            }
        }
        Ok(combinations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn test_policy_attributes() -> Result<(), Error> {
        let sec_level_attributes = vec!["Protected", "Confidential", "Top Secret"];
        let dept_attributes = vec!["R&D", "HR", "MKG", "FIN"];
        let mut policy = Policy::new(100)
            .add_axis("Security Level", &sec_level_attributes, true)?
            .add_axis("Department", &dept_attributes, false)?;
        let attributes = policy.attributes();
        assert_eq!(
            sec_level_attributes.len() + dept_attributes.len(),
            attributes.len()
        );
        for att in sec_level_attributes {
            assert!(attributes.contains(&Attribute::new("Security Level", att)))
        }
        for att in dept_attributes {
            assert!(attributes.contains(&Attribute::new("Department", att)))
        }
        for attribute in &attributes {
            assert_eq!(
                policy.attribute_values(attribute)?[0],
                policy.current_values(&[attribute.to_owned()])?[0]
            )
        }
        // rotate few attributes
        policy.rotate(&attributes[0])?;
        assert_eq!(2, policy.attribute_values(&attributes[0])?.len());
        policy.rotate(&attributes[2])?;
        assert_eq!(2, policy.attribute_values(&attributes[2])?.len());
        println!("policy: {:?}", policy);
        for attribute in &attributes {
            assert_eq!(
                policy.attribute_values(attribute)?[0],
                policy.current_values(&[attribute.to_owned()])?[0]
            )
        }
        Ok(())
    }

    #[test]
    fn test_hypercube() -> Result<(), Error> {
        let sec_level_attributes = vec!["Protected", "Confidential", "Top Secret"];
        let dept_attributes = vec!["R&D", "HR", "MKG", "FIN"];
        let mut policy = Policy::new(100)
            .add_axis("Security Level", &sec_level_attributes, true)?
            .add_axis("Department", &dept_attributes, false)?;
        // rotate an attributes
        policy.rotate(&Attribute::new("Department", "FIN"))?;
        let axes: Vec<&String> = policy.store().keys().collect();
        let walk = walk_hypercube(0, &axes, &policy)?;
        assert!(
            walk == [
                // Protected && R&D
                [1, 4],
                // Protected && HR
                [1, 5],
                // Protected && MKG
                [1, 6],
                // Protected && FIN after rotation
                [1, 8],
                // Protected && FIN before rotation
                [1, 7],
                // Confidential && R&D
                [2, 4],
                // Confidential && HR
                [2, 5],
                // Confidential && MKG
                [2, 6],
                // Confidential && FIN after rotation
                [2, 8],
                // Confidential && FIN before rotation
                [2, 7],
                // Top Secret && R&D
                [3, 4],
                // Top Secret && HR
                [3, 5],
                // Top Secret && MKG
                [3, 6],
                // Top Secret && FIN after rotation
                [3, 8],
                // Top Secret && FIN before rotation
                [3, 7]
            ] || walk
                == [
                    [4, 1],
                    [4, 2],
                    [4, 3],
                    [5, 1],
                    [5, 2],
                    [5, 3],
                    [6, 1],
                    [6, 2],
                    [6, 3],
                    [8, 1],
                    [8, 2],
                    [8, 3],
                    [7, 1],
                    [7, 2],
                    [7, 3],
                ]
        );
        Ok(())
    }

    #[test]
    fn test_to_attribute_combinations() -> Result<(), Error> {
        let sec_level_attributes = vec!["Protected", "Confidential", "Top Secret"];
        let dept_attributes = vec!["R&D", "HR", "MKG", "FIN"];
        let mut policy = Policy::new(100)
            .add_axis("Security Level", &sec_level_attributes, true)?
            .add_axis("Department", &dept_attributes, false)?;
        policy.rotate(&Attribute::new("Department", "FIN"))?;
        let access_policy = (AccessPolicy::new("Department", "HR")
            | AccessPolicy::new("Department", "FIN"))
            & AccessPolicy::new("Security Level", "Confidential");
        let combinations = access_policy.to_attribute_combinations(&policy)?;
        let axes: Vec<&String> = policy.store().keys().collect();
        let world = walk_hypercube(0, &axes, &policy)?;
        println!("{combinations:?}");
        println!("{world:?}");
        Ok(())
    }
}
