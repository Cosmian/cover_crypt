use std::{convert::TryFrom, fmt::Debug, ops::BitOr};

use cosmian_crypto_core::bytes_ser_de::Serializable;
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

impl From<AttributeStatus> for bool {
    fn from(val: AttributeStatus) -> Self {
        val == AttributeStatus::EncryptDecrypt
    }
}

/// A qualified attribute is composed of a dimension an attribute name.
#[derive(Hash, PartialEq, Eq, Clone, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "&str", into = "String")]
pub struct QualifiedAttribute {
    pub dimension: String,
    pub name: String,
}

impl QualifiedAttribute {
    /// Creates a qualified attribute with the given dimension and attribute names.
    #[must_use]
    pub fn new(dimension: &str, name: &str) -> Self {
        Self {
            dimension: dimension.to_owned(),
            name: name.to_owned(),
        }
    }
}

impl Debug for QualifiedAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}::{}", &self.dimension, &self.name))
    }
}

impl std::fmt::Display for QualifiedAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.dimension, self.name)
    }
}

impl From<QualifiedAttribute> for String {
    fn from(attr: QualifiedAttribute) -> Self {
        attr.to_string()
    }
}

impl From<(&str, &str)> for QualifiedAttribute {
    fn from(input: (&str, &str)) -> Self {
        Self {
            dimension: input.0.to_owned(),
            name: input.1.to_owned(),
        }
    }
}

impl From<(String, String)> for QualifiedAttribute {
    fn from(input: (String, String)) -> Self {
        Self {
            dimension: input.0,
            name: input.1,
        }
    }
}

impl TryFrom<&str> for QualifiedAttribute {
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

impl Serializable for EncryptionHint {
    type Error = Error;

    fn length(&self) -> usize {
        1
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        match self {
            EncryptionHint::Classic => ser.write(&0usize),
            EncryptionHint::Hybridized => ser.write(&1usize),
        }
        .map_err(Error::from)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let hint = de.read::<usize>()?;
        match hint {
            0 => Ok(EncryptionHint::Classic),
            1 => Ok(EncryptionHint::Hybridized),
            n => Err(Error::ConversionFailed(format!(
                "invalid encryption-hint value: {}",
                n
            ))),
        }
    }
}

impl Serializable for AttributeStatus {
    type Error = Error;

    fn length(&self) -> usize {
        1
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        match self {
            AttributeStatus::DecryptOnly => ser.write(&0usize),
            AttributeStatus::EncryptDecrypt => ser.write(&1usize),
        }
        .map_err(Error::from)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let status = de.read::<usize>()?;
        match status {
            0 => Ok(AttributeStatus::DecryptOnly),
            1 => Ok(AttributeStatus::EncryptDecrypt),
            n => Err(Error::ConversionFailed(format!(
                "invalid attribute-status value: {}",
                n
            ))),
        }
    }
}

impl Serializable for QualifiedAttribute {
    type Error = Error;

    fn length(&self) -> usize {
        self.dimension.length() + self.name.length()
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        Ok(ser.write(&self.dimension)? + ser.write(&self.name)?)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        Ok(Self {
            dimension: de.read()?,
            name: de.read()?,
        })
    }
}
