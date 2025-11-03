use std::{convert::TryFrom, fmt::Debug, ops::BitOr};

use cosmian_crypto_core::bytes_ser_de::Serializable;
use serde::{Deserialize, Serialize};

use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityMode {
    Classic,
    Quantum,
    Hybridized,
}

impl Serializable for SecurityMode {
    type Error = Error;

    fn length(&self) -> usize {
        1
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        match self {
            Self::Classic => ser.write(&0usize),
            Self::Quantum => ser.write(&1usize),
            Self::Hybridized => ser.write(&2usize),
        }
        .map_err(Error::from)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let status = de.read::<usize>()?;
        match status {
            0 => Ok(Self::Classic),
            1 => Ok(Self::Quantum),
            2 => Ok(Self::Hybridized),
            n => Err(Error::ConversionFailed(format!(
                "invalid security-mode value: {}",
                n
            ))),
        }
    }
}

/// Whether to provide an encryption key in the master public key for this
/// attribute.
#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionStatus {
    #[default]
    EncryptDecrypt,
    DecryptOnly,
}

impl BitOr for EncryptionStatus {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        if self == Self::DecryptOnly || rhs == Self::DecryptOnly {
            Self::DecryptOnly
        } else {
            Self::EncryptDecrypt
        }
    }
}

impl From<EncryptionStatus> for bool {
    fn from(val: EncryptionStatus) -> Self {
        val == EncryptionStatus::EncryptDecrypt
    }
}

impl Serializable for EncryptionStatus {
    type Error = Error;

    fn length(&self) -> usize {
        1
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        match self {
            Self::DecryptOnly => ser.write(&0usize),
            Self::EncryptDecrypt => ser.write(&1usize),
        }
        .map_err(Error::from)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let status = de.read::<usize>()?;
        match status {
            0 => Ok(Self::DecryptOnly),
            1 => Ok(Self::EncryptDecrypt),
            n => Err(Error::ConversionFailed(format!(
                "invalid attribute-status value: {}",
                n
            ))),
        }
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
