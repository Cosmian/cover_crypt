//! This module defines methods to parse and manipulate access policies.
//!
//! Access policies are boolean equations of *qualified attributes*. Attributes are
//! defined as a combination of a dimension name and a component name (belonging
//! to the named dimension).

use crate::{Error, abe::policy::QualifiedAttribute};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use pest::iterators::{Pair, Pairs};
use pest_derive::Parser;
use std::{
    fmt::Debug,
    num::ParseIntError,
    ops::{BitAnd, BitOr, Deref},
};

#[allow(dead_code)]
#[derive(Parser)]
#[grammar = "abe/policy/access_policy.pest"]
pub struct AccessPolicyParser;

/// An access policy is a boolean expression of qualified attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessPolicy {
    Broadcast,
    Term(QualifiedAttribute),
    Conjunction(Box<AccessPolicy>, Box<AccessPolicy>),
    Disjunction(Box<AccessPolicy>, Box<AccessPolicy>),
}

impl AccessPolicy {
    /// Parses the given string into an access policy.
    ///
    /// The abstract grammar defining what is a valid access policy can be found
    /// in (access_policy.pest)[./access_policy.pest].
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
    /// - "DPT::MKG && (CTR::FR || CTR::DE)"
    /// - "SEC::Low Secret && CTR::FR"
    ///
    /// Notice that the arity of the operators is two. Therefore the following
    /// access policy is *invalid*:
    ///
    /// - "DPT::MKG (&& CTR::FR || CTR::DE)"
    ///
    /// It is not possible to concatenate attributes. Therefore the following
    /// access policy is *invalid*:
    ///
    /// - "DPT::MKG DPT::FIN"
    pub fn parse(ap: &str) -> Result<Self, Error> {
        use crate::abe::policy::attribute::Version;
        use pest::Parser;

        enum Operator {
            Conj,
            Disj,
        }

        fn get_operator(pair: Pair<Rule>) -> Result<Operator, Error> {
            match pair.as_rule() {
                Rule::and => Ok(Operator::Conj),
                Rule::or => Ok(Operator::Disj),
                _ => Err(Error::InvalidAccessPolicy(
                    "unexpected rule".to_owned(),
                )),
            }
        }

        fn get_version(pair: Pair<Rule>) -> Result<Version, Error> {
            match pair.as_rule() {
                Rule::tag => Ok(Version::Tag(pair.as_str().to_owned())),
                Rule::version_number => Ok(Version::Num(
                    pair.as_str().parse().map_err(|e: ParseIntError| {
                        Error::InvalidAccessPolicy(format!(
                            "invalid version number: {:?} ({:?})",
                            pair.as_str(),
                            e.to_string()
                        ))
                    })?,
                )),
                _ => Err(Error::InvalidAccessPolicy(format!(
                    "not a valid tag: '{:?}'",
                    pair.as_str()
                ))),
            }
        }

        fn get_qualified_attribute(
            pair: Pair<Rule>,
        ) -> Result<AccessPolicy, Error> {
            match pair.as_rule() {
                Rule::qualified_attribute => {
                    let mut pairs = pair.into_inner();

                    let dimension = pairs
                        .next()
                        .ok_or_else(|| {
                            Error::InvalidAccessPolicy(
                                "missing dimension name".to_owned(),
                            )
                        })?
                        .as_str()
                        .to_string();

                    let attribute = pairs
                        .next()
                        .ok_or_else(|| {
                            Error::InvalidAccessPolicy(
                                "missing dimension name".to_owned(),
                            )
                        })?
                        .as_str()
                        .to_string();

                    let version = pairs.next().map(get_version).transpose()?;

                    Ok(AccessPolicy::Term(QualifiedAttribute {
                        dimension,
                        attribute,
                        version,
                    }))
                }
                _ => Err(Error::InvalidAccessPolicy(format!(
                    "not a qualified attribute {:?}",
                    pair.as_str()
                ))),
            }
        }

        fn get_block(pair: Pair<Rule>) -> Result<AccessPolicy, Error> {
            match pair.as_rule() {
                Rule::qualified_attribute => get_qualified_attribute(pair),
                Rule::eq => get_eq(&mut pair.into_inner()),
                _ => Err(Error::InvalidAccessPolicy(format!(
                    "not a block {:?}",
                    pair.as_str()
                ))),
            }
        }

        fn get_eq(pairs: &mut Pairs<Rule>) -> Result<AccessPolicy, Error> {
            let mut access_policy =
                get_block(pairs.next().ok_or_else(|| {
                    Error::InvalidAccessPolicy(format!(
                        "missing block in {}",
                        pairs
                    ))
                })?)?;

            while !Pairs::is_empty(pairs) {
                let op = pairs.next().expect("iterator is not empty");

                match get_operator(op)? {
                    Operator::Conj => {
                        // Conjunction is eager since it takes precedence.
                        let block = pairs.next().ok_or_else(|| {
                            Error::InvalidAccessPolicy(format!(
                                "missing block in {}",
                                pairs
                            ))
                        })?;

                        access_policy = AccessPolicy::Conjunction(
                            Box::new(access_policy),
                            Box::new(get_block(block)?),
                        )
                    }
                    Operator::Disj => {
                        // Conjunction is eager since it takes precedence.
                        access_policy = AccessPolicy::Disjunction(
                            Box::new(access_policy),
                            Box::new(get_eq(pairs)?),
                        )
                    }
                }
            }

            Ok(access_policy)
        }

        let ap = ap.trim();

        let policy = AccessPolicyParser::parse(Rule::policy, ap)
            .map_err(|_| Error::InvalidAccessPolicy(ap.to_owned()))?
            .next()
            .ok_or_else(|| Error::InvalidAccessPolicy(ap.to_owned()))?;

        if ap != policy.as_span().as_str() {
            return Err(Error::InvalidAccessPolicy(format!(
                "failed to match a valid token in '{}' after '{}'",
                ap.to_owned(),
                policy.as_span().as_str()
            )));
        }

        match policy.as_rule() {
            Rule::eq => get_eq(&mut policy.into_inner()),
            Rule::broadcast => Ok(AccessPolicy::Broadcast),
            _ => Err(Error::InvalidAccessPolicy(format!(
                "not a policy {:?}",
                policy.as_str()
            ))),
        }
    }

    /// Converts the access policy into the Disjunctive Normal Form (DNF) of its
    /// attributes. Returns the DNF as the list of its conjunctions, themselves
    /// represented as the list of their attributes.
    #[must_use]
    pub fn to_dnf(&self) -> Vec<Vec<QualifiedAttribute>> {
        match self {
            Self::Term(attr) => vec![vec![attr.clone()]],
            Self::Conjunction(lhs, rhs) => {
                let combinations_left = lhs.to_dnf();
                let combinations_right = rhs.to_dnf();
                let mut res = Vec::with_capacity(
                    combinations_left.len() * combinations_right.len(),
                );
                for value_left in combinations_left {
                    for value_right in &combinations_right {
                        res.push(
                            [value_left.as_slice(), value_right.as_slice()]
                                .concat(),
                        );
                    }
                }
                res
            }
            Self::Disjunction(lhs, rhs) => {
                [lhs.to_dnf(), rhs.to_dnf()].concat()
            }
            Self::Broadcast => vec![vec![]],
        }
    }
}

impl BitAnd for AccessPolicy {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        if self == Self::Broadcast {
            rhs
        } else if rhs == Self::Broadcast {
            self
        } else {
            Self::Conjunction(Box::new(self), Box::new(rhs))
        }
    }
}

impl BitOr for AccessPolicy {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        if self == Self::Broadcast {
            self
        } else if rhs == Self::Broadcast {
            rhs
        } else {
            Self::Disjunction(Box::new(self), Box::new(rhs))
        }
    }
}

impl Serializable for AccessPolicy {
    type Error = Error;

    fn length(&self) -> usize {
        match self {
            AccessPolicy::Broadcast => 1,
            AccessPolicy::Term(qualified_attribute) => {
                1 + qualified_attribute.length()
            }
            AccessPolicy::Conjunction(access_policy, access_policy1) => {
                1 + access_policy.length() + access_policy1.length()
            }
            AccessPolicy::Disjunction(access_policy, access_policy1) => {
                1 + access_policy.length() + access_policy1.length()
            }
        }
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        match self {
            AccessPolicy::Broadcast => ser.write(&0_u64).map_err(Error::from),
            AccessPolicy::Term(qualified_attribute) => {
                Ok(ser.write(&1_u64)? + ser.write(qualified_attribute)?)
            }
            AccessPolicy::Conjunction(access_policy, access_policy1) => Ok(ser
                .write(&2_u64)?
                + ser.write(access_policy.deref())?
                + ser.write(access_policy1.deref())?),
            AccessPolicy::Disjunction(access_policy, access_policy1) => Ok(ser
                .write(&3_u64)?
                + ser.write(access_policy.deref())?
                + ser.write(access_policy1.deref())?),
        }
    }

    fn read(
        de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer,
    ) -> Result<Self, Self::Error> {
        match de.read::<u64>()? {
            0 => Ok(Self::Broadcast),
            1 => Ok(Self::Term(de.read()?)),
            2 => Ok(Self::Conjunction(
                Box::new(de.read()?),
                Box::new(de.read()?),
            )),
            3 => Ok(Self::Disjunction(
                Box::new(de.read()?),
                Box::new(de.read()?),
            )),
            n => Err(Error::ConversionFailed(format!(
                "{n} is not a valid access policy tag"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::bytes_ser_de::test_serialization;

    use crate::{QualifiedAttribute, abe::policy::attribute::Version};

    use super::AccessPolicy;

    #[test]
    fn test_access_policy_parsing() {
        //
        // These are valid access policies.
        //

        let ap = AccessPolicy::parse("*").unwrap();
        test_serialization(&ap).unwrap();
        assert_eq!(ap, AccessPolicy::Broadcast);

        let ap = AccessPolicy::parse("(D1::A)").unwrap();
        assert_eq!(ap, AccessPolicy::Term(QualifiedAttribute::new("D1", "A")));

        let ap = AccessPolicy::parse("D1::A && (D2::B)").unwrap();
        assert_eq!(
            ap,
            AccessPolicy::Conjunction(
                Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                    "D1", "A"
                ),)),
                Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                    "D2", "B"
                ),))
            ),
        );

        let ap = AccessPolicy::parse("D1::A && (D2::B) && (D3::C)").unwrap();
        assert_eq!(
            ap,
            AccessPolicy::Conjunction(
                Box::new(AccessPolicy::Conjunction(
                    Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                        "D1", "A"
                    ),)),
                    Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                        "D2", "B"
                    ),))
                )),
                Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                    "D3", "C"
                ),))
            ),
        );

        let ap = AccessPolicy::parse("(D1::A && ((D2::A) && D2::B))").unwrap();
        println!("{ap:#?}");
        test_serialization(&ap).unwrap();
        assert_eq!(
            ap,
            AccessPolicy::Conjunction(
                Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                    "D1", "A"
                ),)),
                Box::new(AccessPolicy::Conjunction(
                    Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                        "D2", "A"
                    ),)),
                    Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                        "D2", "B"
                    ),)),
                )),
            )
        );

        let ap = AccessPolicy::parse("D1::A && D2::A || D2::B").unwrap();
        println!("{ap:#?}");
        test_serialization(&ap).unwrap();
        assert_eq!(
            ap,
            AccessPolicy::Disjunction(
                Box::new(AccessPolicy::Conjunction(
                    Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                        "D1", "A"
                    ),)),
                    Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                        "D2", "A"
                    ),)),
                )),
                Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                    "D2", "B"
                ),)),
            )
        );

        let ap = AccessPolicy::parse("D1::A || D2::A && D2::B").unwrap();
        println!("{ap:#?}");
        test_serialization(&ap).unwrap();
        assert_eq!(
            ap,
            AccessPolicy::Disjunction(
                Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                    "D1", "A"
                ),)),
                Box::new(AccessPolicy::Conjunction(
                    Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                        "D2", "A"
                    ),)),
                    Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                        "D2", "B"
                    ),)),
                ))
            )
        );

        let ap = AccessPolicy::parse("D1::A && (D2::A || D2::B)").unwrap();
        println!("{ap:#?}");
        test_serialization(&ap).unwrap();
        assert_eq!(
            ap,
            AccessPolicy::Conjunction(
                Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                    "D1", "A"
                ),)),
                Box::new(AccessPolicy::Disjunction(
                    Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                        "D2", "A"
                    ),)),
                    Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                        "D2", "B"
                    )))
                ),)
            )
        );

        let ap = AccessPolicy::parse("(D1::A && (D2::A) || D2::B)").unwrap();
        println!("{ap:#?}");
        assert_eq!(
            ap,
            AccessPolicy::Disjunction(
                Box::new(AccessPolicy::Conjunction(
                    Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                        "D1", "A"
                    ),)),
                    Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                        "D2", "A"
                    ),))
                )),
                Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                    "D2", "B"
                ),)),
            )
        );

        let ap =
            AccessPolicy::parse("D-1::A@1 && (D-2::A@version-1 || D-2::B)")
                .unwrap();
        println!("{ap:#?}");
        assert_eq!(
            ap,
            AccessPolicy::Conjunction(
                Box::new(AccessPolicy::Term(QualifiedAttribute {
                    dimension: "D-1".to_string(),
                    attribute: "A".to_string(),
                    version: Some(Version::Num(1)),
                })),
                Box::new(AccessPolicy::Disjunction(
                    Box::new(AccessPolicy::Term(QualifiedAttribute {
                        dimension: "D-2".to_string(),
                        attribute: "A".to_string(),
                        version: Some(Version::Tag("version-1".to_string()))
                    })),
                    Box::new(AccessPolicy::Term(QualifiedAttribute::new(
                        "D-2", "B"
                    )))
                ),)
            )
        );

        //
        // These are invalid access policies.
        //

        assert!(AccessPolicy::parse("").is_err());
        assert!(AccessPolicy::parse("()").is_err());
        assert!(AccessPolicy::parse("D1").is_err());
        assert!(AccessPolicy::parse("D1::A || ").is_err());
        assert!(AccessPolicy::parse("D1::A && ").is_err());
        assert!(AccessPolicy::parse("D1::A (&& D2::A || D2::B)").is_err());
        assert!(AccessPolicy::parse("|| D2::B").is_err());
        assert!(AccessPolicy::parse("(é::à && (ó::ï) || ø::ú)").is_err());
        assert!(AccessPolicy::parse("D1::A (D2::A || D2::B)").is_err());
    }
}
