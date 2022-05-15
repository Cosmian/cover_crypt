#![allow(clippy::module_name_repetitions)]
// #![allow(dead_code)]
use crate::error::Error;
use serde::{Deserialize, Deserializer, Serialize};
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
    pub fn name(&self) -> String {
        self.name.clone()
    }
}

impl Debug for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}::{}", &self.axis, &self.name))
    }
}

/// Create a Policy Attribute.
///
/// Shortcut for
/// ```ignore
/// Attribute {
///     axis: axis.to_owned(),
///     name: name.to_owned(),
/// }
/// ```
pub fn attr(axis: &str, name: &str) -> Attribute {
    Attribute {
        axis: axis.to_owned(),
        name: name.to_owned(),
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
    /// Create an access policy from a single attribute
    pub fn from(axis_name: &str, attribute_name: &str) -> AccessPolicy {
        AccessPolicy::Attr(Attribute {
            axis: axis_name.to_owned(),
            name: attribute_name.to_owned(),
        })
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
                    .map(|x| attr(axis, x).into())
                    .reduce(BitOr::bitor)
                    .ok_or_else(|| Error::MissingAttribute {
                        item: None,
                        axis_name: Some(axis.to_owned()),
                    })?,
            );
        }
        let access_policy = access_policies
            .iter()
            .map(|ap| ap.to_owned())
            .reduce(BitAnd::bitand)
            .ok_or_else(|| Error::MissingAxis("axis".to_string()))?;
        Ok(access_policy)
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
                return Ok(ap(attribute_vec[0], attribute_vec[1]));
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

    /// Verify if an access policy is compliant with the ABE policy.
    /// Function will verify if axis and attributes given in the boolean
    /// expression are declared in the ABE policy
    ///
    /// # Arguments
    ///
    /// * `boolean_expression`: access policy expressed with operators && and ||
    /// * `policy`: the ABE policy
    ///
    /// # Returns
    ///
    /// Nothing if access policy is valid. A `MissingAxis` or `MissingAttribute`
    /// error otherwise
    ///
    /// # Examples
    ///
    /// ```rust
    /// let access_policy_str = "(Department::HR || Department::R&D) && Level::level 2";
    /// let access_policy = cover_crypt::policy::AccessPolicy::from_boolean_expression(access_policy_str).unwrap();

    pub fn attributes(&self) -> Vec<Attribute> {
        let mut attributes = AccessPolicy::_attributes(self);
        attributes.sort();
        attributes
    }

    fn _attributes(access_policy: &AccessPolicy) -> Vec<Attribute> {
        match access_policy {
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
pub fn ap(axis: &str, name: &str) -> AccessPolicy {
    AccessPolicy::Attr(Attribute {
        axis: axis.to_owned(),
        name: name.to_owned(),
    })
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
            attributes: attributes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
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
    pub(crate) last_attribute: usize,
    pub(crate) max_attribute: usize,
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
    pub fn new(nb_revocation: usize) -> Self {
        Self {
            last_attribute: 0,
            max_attribute: nb_revocation,
            store: HashMap::new(),
            attribute_to_int: HashMap::new(),
        }
    }

    pub fn store(&self) -> HashMap<String, (Vec<String>, bool)> {
        self.store.clone()
    }

    #[must_use]
    pub fn max_attr(&self) -> usize {
        self.max_attribute
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
        if axis.len() + self.last_attribute > self.max_attribute {
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
                self.last_attribute += 1;
                if self
                    .attribute_to_int
                    .insert(
                        (axis.name.clone(), attr.clone()).into(),
                        vec![u32::try_from(self.last_attribute)?].into(),
                    )
                    .is_some()
                {
                    // must never occurs as policy is a new one
                    return Err(Error::ExistingPolicy(axis.name));
                }
            }
            // add attribute is not a revocation
            self.max_attribute += axis.attributes.len();
        }
        Ok(self)
    }

    /// Rotate an attribute, changing its underlying value with that of an
    /// unused slot
    pub fn rotate(&mut self, attr: &Attribute) -> Result<(), Error> {
        if self.last_attribute + 1 > self.max_attribute {
            return Err(Error::CapacityOverflow);
        }
        if let Some(uint) = self.attribute_to_int.get_mut(attr) {
            self.last_attribute += 1;
            uint.push(u32::try_from(self.last_attribute)?);
        } else {
            return Err(Error::AttributeNotFound(format!("{:?}", attr)));
        }
        Ok(())
    }

    /// Retrieve the current attributes values for the `Attribute` list
    pub fn attributes_values(&self, attributes: &[Attribute]) -> Result<Vec<u32>, Error> {
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
