//! This module defines methods to parse and manipulate access policies.
//!
//! Access policies are boolean equations of *attributes*. Attributes are
//! defined as a combination of a dimension name and a component name (belonging
//! to the named dimension).
//!
//! The abstract grammar used to represent such policies as string is:
//! - AP: [ attribute | block [ operator AP ]]
//! - group: ( AP )
//! - attribute: dimension_name name_separator component_name
//! - operator: OR | AND
//! - OR: "||"
//! - AND: "&&"
//! - name_separator: "::"
//! - dimension_name: arbitrary string without leading or trailing space
//! - component_name: arbitrary string without leading or trailing space
//!
//! Space may or may not be inserted between each element.
//!
//! For example the following expression define valid access policies:
//! - "Department::MKG && (Country::FR || Country::DE)"
//! - ""
//! - "Security Level::Low Secret && Country::FR"

use std::{
    fmt::Debug,
    ops::{BitAnd, BitOr},
};

use crate::{abe_policy::Attribute, Error};

/// An access policy is a boolean expression of attributes.
///
/// TODO: is this a subset-cover limitation? It seems possible to subtract
/// coordinates from the set of positively generated ones.
///
/// Only `positive` literals are allowed (no negation).
#[derive(Debug, Clone)]
pub enum AccessPolicy {
    Attr(Attribute),
    And(Box<AccessPolicy>, Box<AccessPolicy>),
    Or(Box<AccessPolicy>, Box<AccessPolicy>),
    Any,
}

impl AccessPolicy {
    /// Creates an Access Policy based on a single Policy Attribute.
    ///
    /// Shortcut for
    /// ```ignore
    /// AccessPolicy::Attr(Attribute::new(dimension, attribute))
    /// ```
    ///
    /// Access Policies can easily be created using it
    /// ```ignore
    /// let access_policy =
    ///     AccessPolicy::new("Security Level", "level 4")
    ///         & (AccessPolicy::new("Department", "MKG") | AccessPolicy::new("Department", "FIN"));
    /// ```
    #[must_use]
    pub fn new(dimension: &str, attribute: &str) -> Self {
        Self::Attr(Attribute::new(dimension, attribute))
    }

    /// Finds the corresponding closing parenthesis in the boolean expression
    /// given as a string.
    fn find_next_parenthesis(boolean_expression: &str) -> Result<usize, Error> {
        let mut count = 0;
        let mut right_closing_parenthesis = None;
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

    /// Converts a boolean expression into `AccessPolicy`.
    ///
    /// # Arguments
    ///
    /// - `boolean_expression`: expression with operators && and ||
    ///
    /// # Returns
    ///
    /// the corresponding `AccessPolicy`
    ///
    /// # Errors
    ///
    /// Missing parenthesis or bad operators
    pub fn from_boolean_expression(boolean_expression: &str) -> Result<Self, Error> {
        Self::parse(boolean_expression)
    }

    pub fn parse(mut e: &str) -> Result<Self, Error> {
        let seeker = |c: &char| !"()|&".contains(*c);
        let mut prev = None;
        loop {
            e = e.trim();
            if e.is_empty() {
                return Ok(prev.unwrap_or(Self::Any));
            } else {
                match &e[..1] {
                    "(" => {
                        if prev.is_none() {
                            let match_pos = Self::find_next_parenthesis(&e[1..])? + 1;
                            prev = Some(Self::parse(&e[1..match_pos]).map_err(|err| {
                                Error::InvalidBooleanExpression(format!(
                                    "error while parsing '{e}': {err}"
                                ))
                            })?);
                            e = &e[match_pos + 1..];
                        } else {
                            return Err(Error::InvalidBooleanExpression(format!(
                                "access policies cannot be concatenated without operator: '{e}'"
                            )));
                        }
                    }
                    "|" => {
                        if e[1..].is_empty() || &e[1..2] != "|" {
                            return Err(Error::InvalidBooleanExpression(format!(
                                "invalid separator in: '{e}'"
                            )));
                        }
                        if let Some(ap) = prev {
                            return Ok(Self::Or(
                                Box::new(ap),
                                Box::new(Self::parse(&e[2..]).map_err(|err| {
                                    Error::InvalidBooleanExpression(format!(
                                        "error while parsing '{e}': {err}"
                                    ))
                                })?),
                            ));
                        } else {
                            return Err(Error::InvalidBooleanExpression(format!(
                                "leading operators are invalid: '{e}'"
                            )));
                        }
                    }
                    "&" => {
                        if e[1..].is_empty() || &e[1..2] != "&" {
                            return Err(Error::InvalidBooleanExpression(format!(
                                "invalid leading separator in: '{e}'"
                            )));
                        }
                        if let Some(ap) = prev {
                            return Ok(Self::And(
                                Box::new(ap),
                                Box::new(Self::parse(&e[2..]).map_err(|err| {
                                    Error::InvalidBooleanExpression(format!(
                                        "error while parsing '{e}': {err}"
                                    ))
                                })?),
                            ));
                        } else {
                            return Err(Error::InvalidBooleanExpression(format!(
                                "leading operators are invalid: '{e}'"
                            )));
                        }
                    }
                    _ => {
                        if prev.is_none() {
                            let attr: String = e.chars().take_while(seeker).collect();
                            prev = Some(Self::Attr(Attribute::try_from(attr.as_str())?));
                            e = &e[attr.len()..];
                        } else {
                            return Err(Error::InvalidBooleanExpression(format!(
                                "access policies cannot be concatenated without operator: '{e}'"
                            )));
                        }
                    }
                }
            }
        }
    }

    /// Returns the sorted sequence of attributes used in the access policy.
    #[must_use]
    pub fn ordered_attributes(&self) -> Vec<Attribute> {
        let mut attributes = self.clone().into_attributes();
        attributes.sort_unstable();
        attributes
    }

    /// Returns the sequence of attributes used in the access policy.
    pub fn into_attributes(self) -> Vec<Attribute> {
        match self {
            Self::Attr(att) => vec![att],
            Self::And(lhs, rhs) | Self::Or(lhs, rhs) => {
                [lhs.into_attributes(), rhs.into_attributes()].concat()
            }
            Self::Any => vec![],
        }
    }

    /// Converts the access policy into the Disjunctive Normal Form (DNF) of its attributes.
    #[must_use]
    pub fn to_dnf(&self) -> Vec<Vec<Attribute>> {
        match self {
            Self::Attr(attr) => vec![vec![attr.clone()]],
            Self::And(lhs, rhs) => {
                let combinations_left = lhs.to_dnf();
                let combinations_right = rhs.to_dnf();
                let mut res =
                    Vec::with_capacity(combinations_left.len() * combinations_right.len());
                for value_left in combinations_left {
                    for value_right in &combinations_right {
                        res.push([value_left.as_slice(), value_right.as_slice()].concat());
                    }
                }
                res
            }
            Self::Or(lhs, rhs) => [lhs.to_dnf(), rhs.to_dnf()].concat(),
            Self::Any => vec![vec![]],
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
        Self::Attr(attribute)
    }
}

#[cfg(test)]
mod tests {
    use super::AccessPolicy;

    #[test]
    fn test_from_boolean_expression() {
        //let ap = AccessPolicy::from_boolean_expression("(D1::A && (D2::A) || D2::B)").unwrap();
        //println!("{ap:#?}");
        //let ap = AccessPolicy::from_boolean_expression("").unwrap();
        //println!("{ap:#?}");
        let ap = AccessPolicy::parse("(D1::A && (D2::A) || D2::B)").unwrap();
        println!("{ap:#?}");
    }
}
