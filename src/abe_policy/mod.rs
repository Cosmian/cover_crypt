mod access_policy;
mod access_structure;
mod attribute;
mod dimension;
mod rights;

#[cfg(any(test, feature = "test-utils"))]
mod tests;

pub use access_policy::AccessPolicy;
pub use access_structure::AccessStructure;
pub use attribute::{EncryptionStatus, QualifiedAttribute, SecurityMode};
use cosmian_crypto_core::bytes_ser_de::Serializable;
pub use dimension::{Attribute, Dimension};
pub use rights::Right;
#[cfg(any(test, feature = "test-utils"))]
pub use tests::gen_structure;

use crate::Error;

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

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let version = de.read::<usize>()?;
        match version {
            1 => Ok(Self::V1),
            n => Err(Error::ConversionFailed(format!("invalid version: {n}"))),
        }
    }
}
