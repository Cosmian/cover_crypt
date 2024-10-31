use std::{
    convert::TryFrom,
    fmt::Debug,
    ops::{BitOr, Deref},
};

use serde::{Deserialize, Serialize};

use crate::Error;

/// Hint the user about which kind of encryption to use.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionHint {
    /// Hybridized encryption should be used.
    Hybridized,
    /// Classic encryption should be used.
    Classic,
}

impl BitOr for EncryptionHint {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        if self == Self::Hybridized || rhs == Self::Hybridized {
            Self::Hybridized
        } else {
            Self::Classic
        }
    }
}

impl EncryptionHint {
    #[must_use]
    pub fn new(is_hybridized: bool) -> Self {
        if is_hybridized {
            Self::Hybridized
        } else {
            Self::Classic
        }
    }
}

impl From<EncryptionHint> for bool {
    fn from(val: EncryptionHint) -> Self {
        val == EncryptionHint::Hybridized
    }
}

/// Whether to provide an encryption key in the master public key for this
/// attribute.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttributeStatus {
    EncryptDecrypt,
    DecryptOnly,
}

impl BitOr for AttributeStatus {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        if self == Self::DecryptOnly || rhs == Self::DecryptOnly {
            Self::DecryptOnly
        } else {
            Self::EncryptDecrypt
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Attribute representation used to create an attribute and add it to a dimension.
pub struct AttributeBuilder {
    pub name: String,
    pub encryption_hint: EncryptionHint,
}

/// A policy attribute is composed of a dimension name and a component
/// name.
#[derive(Hash, PartialEq, Eq, Clone, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "&str", into = "String")]
pub struct Attribute {
    pub dimension: String,
    pub name: String,
}

impl Attribute {
    /// Create a Policy Attribute.
    ///
    /// - `dimension`    : policy dimension the attributes belongs to
    /// - `name`         : unique attribute name within this dimension
    #[must_use]
    pub fn new(dimension: &str, name: &str) -> Self {
        Self {
            dimension: dimension.to_owned(),
            name: name.to_owned(),
        }
    }
}

impl Debug for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}::{}", &self.dimension, &self.name))
    }
}

impl From<(&str, &str)> for Attribute {
    fn from(input: (&str, &str)) -> Self {
        Self {
            dimension: input.0.to_owned(),
            name: input.1.to_owned(),
        }
    }
}

impl From<(String, String)> for Attribute {
    fn from(input: (String, String)) -> Self {
        Self {
            dimension: input.0,
            name: input.1,
        }
    }
}

impl TryFrom<&str> for Attribute {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let (dimension, component) = s.split_once("::").ok_or_else(|| {
            Error::InvalidAttribute(format!("at least one separator '::' expected in {s}"))
        })?;

        if component.contains("::") {
            return Err(Error::InvalidAttribute(format!(
                "separator '::' expected only once in {s}"
            )));
        }

        if dimension.is_empty() || component.is_empty() {
            return Err(Error::InvalidAttribute(format!(
                "empty dimension or empty name in {s}"
            )));
        }

        Ok(Self::new(dimension.trim(), component.trim()))
    }
}

impl std::fmt::Display for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:  :{}", self.dimension, self.name)
    }
}

impl From<Attribute> for String {
    fn from(attr: Attribute) -> Self {
        attr.to_string()
    }
}

/// The `Attributes` struct is used to simplify the parsing of a list of
/// `Attribute`s.
#[derive(Debug, PartialEq, Eq)]
pub struct Attributes {
    attributes: Vec<Attribute>,
}

impl Deref for Attributes {
    type Target = Vec<Attribute>;

    fn deref(&self) -> &Self::Target {
        &self.attributes
    }
}

impl From<Vec<Attribute>> for Attributes {
    fn from(attributes: Vec<Attribute>) -> Self {
        Self { attributes }
    }
}

impl TryFrom<&str> for Attributes {
    type Error = Error;

    fn try_from(attributes_str: &str) -> Result<Self, Self::Error> {
        if attributes_str.is_empty() {
            return Err(Error::InvalidAttribute(attributes_str.to_string()));
        }

        // Convert a Vec<Result<Attribute,FormatErr>> into a Result<Vec<Attribute>>
        let attributes: Result<Vec<_>, _> = attributes_str
            .trim()
            .split(',')
            .map(Attribute::try_from)
            .collect();

        Ok(Self {
            attributes: attributes?,
        })
    }
}
