//! This module defines methods to parse and manipulate access policies.
//!
//! Access policies are boolean equations of *attributes*. Attributes are
//! defined as a combination of a dimension name and a component name (belonging
//! to the named dimension).
//!

use std::{
    collections::LinkedList,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessPolicy {
    Attr(Attribute),
    And(Box<AccessPolicy>, Box<AccessPolicy>),
    Or(Box<AccessPolicy>, Box<AccessPolicy>),
    Any,
}

impl AccessPolicy {
    /// Finds the corresponding closing parenthesis in the boolean expression
    /// given as a string.
    fn find_next_parenthesis(boolean_expression: &str) -> Result<usize, Error> {
        let mut count = 0;
        for (index, c) in boolean_expression.chars().enumerate() {
            match c {
                '(' => count += 1,
                ')' => count -= 1,
                _ => {}
            };
            if count < 0 {
                return Ok(index);
            }
        }
        Err(Error::InvalidBooleanExpression(format!(
            "Missing closing parenthesis in boolean expression {boolean_expression}"
        )))
    }

    /// Parses the given string into an access policy.
    ///
    /// # Abstract grammar
    ///
    /// The following abstract grammar describes the valid access policies
    /// syntax. The brackets are used to denote optional elements, the pipes
    /// ('|') to denote options, slashes to denote REGEXP, and spaces to denote
    /// concatenation. Spaces may be interleaved with elements. They are simply
    /// ignored by the parser.
    ///
    /// - access_policy: [ attribute | group [ operator access_policy ]]
    /// - attribute: dimension [ separator component ]
    /// - group: ( access_policy )
    /// - operator: OR | AND
    /// - OR: ||
    /// - AND: &&
    /// - separator: ::
    /// - dimension: /[^&|: ]+/
    /// - component: /[^&|: ]+/
    ///
    /// The REGEXP used to describe the dimension and the component stands for:
    /// "at least one character that is neither '&', '|', ':' nor ' '".
    ///
    /// # Precedence rule
    ///
    /// Note that the usual precedence rules hold in expressing an access
    /// policy:
    /// 1. grouping takes precedence over all operators;
    /// 2. the logical AND takes precedence over the logical OR.
    ///
    /// # Examples
    ///
    /// The following expressions define valid access policies:
    ///
    /// - "Department::MKG && (Country::FR || Country::DE)"
    /// - ""
    /// - "Security Level::Low Secret && Country::FR"
    ///
    /// Notice that the arity of the operators is two. Therefore the following
    /// access policy is *invalid*:
    ///
    /// - "Department::MKG (&& Country::FR || Country::DE)"
    ///
    /// It is not possible to concatenate attributes. Therefore the following
    /// access policy is *invalid*:
    ///
    /// - "Department::MKG Department::FIN"
    pub fn parse(mut e: &str) -> Result<Self, Error> {
        let seeker = |c: &char| !"()|&".contains(*c);
        let mut q = LinkedList::<Self>::new();
        loop {
            e = e.trim();
            if e.is_empty() {
                return Ok(Self::conjugate(Self::Any, q.into_iter()));
            } else {
                match &e[..1] {
                    "(" => {
                        let offset = Self::find_next_parenthesis(&e[1..])?;
                        q.push_back(Self::parse(&e[1..1 + offset]).map_err(|err| {
                            Error::InvalidBooleanExpression(format!(
                                "error while parsing '{e}': {err}"
                            ))
                        })?);
                        e = &e[2 + offset..];
                    }
                    "|" => {
                        if e[1..].is_empty() || &e[1..2] != "|" {
                            return Err(Error::InvalidBooleanExpression(format!(
                                "invalid separator in: '{e}'"
                            )));
                        }
                        let base = q.pop_front().ok_or_else(|| {
                            Error::InvalidBooleanExpression(format!("leading OR operand in '{e}'"))
                        })?;
                        let lhs = Self::conjugate(base, q.into_iter());
                        return Ok(lhs | Self::parse(&e[2..])?);
                    }
                    "&" => {
                        if e[1..].is_empty() || &e[1..2] != "&" {
                            return Err(Error::InvalidBooleanExpression(format!(
                                "invalid leading separator in: '{e}'"
                            )));
                        }
                        if q.is_empty() {
                            return Err(Error::InvalidBooleanExpression(format!(
                                "leading AND operand in '{e}'"
                            )));
                        }
                        e = &e[2..];
                    }
                    ")" => {
                        return Err(Error::InvalidBooleanExpression(format!(
                            "unmatched closing parenthesis in '{e}'"
                        )))
                    }
                    _ => {
                        let attr: String = e.chars().take_while(seeker).collect();
                        q.push_back(Self::Attr(Attribute::try_from(attr.as_str())?));
                        e = &e[attr.len()..];
                    }
                }
            }
        }
    }

    /// Conjugate the access policies from the given iterator.
    fn conjugate(first: Self, policies: impl Iterator<Item = Self>) -> Self {
        policies.fold(first, |mut res, operand| {
            res = res & operand;
            res
        })
    }

    /// Converts the access policy into the Disjunctive Normal Form (DNF) of its
    /// attributes. Returns the DNF as the list of its conjunctions, themselves
    /// represented as the list of their attributes.
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

impl BitAnd for AccessPolicy {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        if self == Self::Any {
            rhs
        } else if rhs == Self::Any {
            self
        } else {
            Self::And(Box::new(self), Box::new(rhs))
        }
    }
}

impl BitOr for AccessPolicy {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        if self == Self::Any {
            self
        } else if rhs == Self::Any {
            rhs
        } else {
            Self::Or(Box::new(self), Box::new(rhs))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AccessPolicy;

    #[test]
    fn test_access_policy_parsing() {
        // These are valid access policies.
        let ap = AccessPolicy::parse("(D1::A && (D2::A) || D2::B)").unwrap();
        println!("{ap:#?}");
        let ap = AccessPolicy::parse("D1::A && D2::A || D2::B").unwrap();
        println!("{ap:#?}");
        let ap = AccessPolicy::parse("D1::A && (D2::A || D2::B)").unwrap();
        println!("{ap:#?}");
        let ap = AccessPolicy::parse("D1::A (D2::A || D2::B)").unwrap();
        println!("{ap:#?}");
        assert_eq!(AccessPolicy::parse("").unwrap(), AccessPolicy::Any);

        // These are invalid access policies.
        // TODO: make this one valid (change the parsing rule of the attribute).
        assert!(AccessPolicy::parse("D1").is_err());
        assert!(AccessPolicy::parse("D1::A (&& D2::A || D2::B)").is_err());
        assert!(AccessPolicy::parse("|| D2::B").is_err());
    }
}
