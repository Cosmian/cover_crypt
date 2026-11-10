mod access_policy;
mod access_structure;
mod attribute;
mod dimension;
mod rights;

#[cfg(any(test, feature = "test-utils"))]
mod tests;

use std::{borrow::Borrow, collections::HashSet, ops::Deref};

#[cfg(feature = "test-utils")]
pub use access_structure::omega_size;

pub use access_policy::AccessPolicy;
pub use access_structure::AccessStructure;
pub use attribute::{
    EncryptionStatus, HybridizationStatus, QualifiedAttribute,
};
pub use dimension::{Attribute, Dimension};
pub use rights::Right;

use serde::{Deserialize, Serialize};
#[cfg(any(test, feature = "test-utils"))]
pub use tests::gen_structure;

use crate::Error;
use cosmian_crypto_core::bytes_ser_de::{
    Deserializer, Serializable, Serializer,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
    V1,
}

impl Serializable for Version {
    type Error = Error;

    fn length(&self) -> usize {
        1
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        match self {
            Version::V1 => Ok(ser.write(&1usize)?),
        }
    }

    fn read(
        de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer,
    ) -> Result<Self, Self::Error> {
        let version = de.read::<usize>()?;
        match version {
            1 => Ok(Self::V1),
            n => Err(Error::ConversionFailed(format!("invalid version: {n}"))),
        }
    }
}

pub const BROADCAST: &str = "*";

fn validate_name(name: &str) -> Result<(), Error> {
    let valid_characters = ('a'..='z')
        .chain('A'..='Z')
        .chain('0'..='9')
        .chain(['-'])
        .collect::<HashSet<char>>();

    if name == BROADCAST {
        Err(Error::InvalidName(name.to_owned()))
    } else {
        for c in name.chars() {
            if !valid_characters.contains(&c) {
                return Err(Error::InvalidName(name.to_owned()));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct NameRef<'a>(&'a str);

impl<'a> Deref for NameRef<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> TryFrom<&'a str> for NameRef<'a> {
    type Error = Error;

    fn try_from(name: &'a str) -> Result<Self, Self::Error> {
        validate_name(name).map(|_| Self(name))
    }
}

#[derive(
    Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize,
)]
#[serde(try_from = "String", into = "String")]
pub struct Name(String);

impl Deref for Name {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Borrow<str> for Name {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl From<Name> for String {
    fn from(name: Name) -> Self {
        name.0
    }
}

impl TryFrom<String> for Name {
    type Error = Error;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        validate_name(&name).map(|_| Self(name))
    }
}

impl<'a> From<&'a Name> for NameRef<'a> {
    fn from(name: &'a Name) -> Self {
        NameRef(&name.0)
    }
}

impl<'a> From<NameRef<'a>> for Name {
    fn from(value: NameRef<'a>) -> Self {
        Self(value.to_string())
    }
}

impl Serializable for Name {
    type Error = Error;

    fn length(&self) -> usize {
        self.0.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write(&self.0).map_err(Error::from)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        de.read().map(Self).map_err(Error::from)
    }
}
