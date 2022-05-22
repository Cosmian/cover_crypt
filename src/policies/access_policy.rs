#![allow(clippy::module_name_repetitions)]

use super::{attribute::Attribute, policy::Policy};
use crate::error::Error;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Debug,
    ops::{BitAnd, BitOr},
};

/// the number of characters taken by an operator in the Access Policy string
/// in this case the operators are : || and &&
const OPERATOR_SIZE: usize = 2;

// An `AccessPolicy` is a boolean expression over attributes
// Only `positive` literals are allowed (no negation)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AccessPolicy {
    Attr(Attribute),
    And(Box<AccessPolicy>, Box<AccessPolicy>),
    Or(Box<AccessPolicy>, Box<AccessPolicy>),
    All, // indicates we want the disjunction of all attributes
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
    /// AccessPolicy::Attr(Attribute::new(axis, attribute))
    /// ```
    ///
    /// Access Policies can easily be created using it
    /// ```ignore
    /// let access_policy =
    ///     ap("Security Level", "level 4") & (ap("Department", "MKG") | ap("Department", "FIN"));
    /// ```
    pub fn new(axis: &str, attribute: &str) -> Self {
        Self::Attr(Attribute::new(axis, attribute))
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
                    .as_map()
                    .get(&attr.axis())
                    .ok_or_else(|| Error::UnknownPartition(attr.axis()))?;
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
                let attribute_list_2 = attr2.to_attribute_combinations(policy)?;
                for value1 in attr1.to_attribute_combinations(policy)? {
                    for value2 in attribute_list_2.iter() {
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
                    let max = (attribute_mapping.len() + 1) as u32;
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
            .ok_or(Error::MissingAxis)?;
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
        let mut right_closing_parenthesis = None;
        // Skip first parenthesis
        for (index, c) in boolean_expression.chars().enumerate() {
            match c {
                '(' => count += 1,
                ')' => count -= 1,
                _ => {}
            };
            if count < 0 {
                right_closing_parenthesis = Some(index);
                break;
            }
        }

        right_closing_parenthesis.ok_or_else(|| {
            Error::InvalidBooleanExpression(format!(
                "Missing closing parenthesis in boolean expression {boolean_expression}"
            ))
        })
    }

    /// Sanitize spaces in boolean expression around parenthesis and operators
    /// but keep spaces inside axis & attribute names We remove useless
    /// spaces:
    /// - before and after operator. Example: `A && B` --> `A&&B`
    /// - before and after parenthesis. Example: `(A && B)` --> `(A&&B)`
    /// - But keep these spaces: `(A::b c || d e::F)` --> `(A::b c||d e::F)`
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
    /// - `boolean_expression`: expression with operators && and ||
    ///
    /// # Returns
    ///
    /// the corresponding `AccessPolicy`
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let boolean_expression = "(Department::HR || Department::RnD) && Level::level_2";
    /// let access_policy = crate::policy::AccessPolicy::from_boolean_expression(boolean_expression);
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

/// Create an axis policy from a simple attribute
///
/// Shorthand for
/// ```ignore
/// AccessPolicy::new(axis, attribute_name)
/// ```
///
/// Used to easily build access policies programmatically
/// ```ignore
/// let access_policy =
///     ap("Security Level", "level 4") & (ap("Department", "MKG") | ap("Department", "FIN"));
/// ```
pub fn ap(axis: &str, attribute_name: &str) -> AccessPolicy {
    AccessPolicy::new(axis, attribute_name)
}
