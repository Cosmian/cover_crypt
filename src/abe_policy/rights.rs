use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable, Serializer, to_leb128_len};
use std::{hash::Hash, ops::Deref};

use crate::Error;

/// A right is a combination of the IDs of its associated attributes.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Right(pub(crate) Vec<u8>);

impl Right {
    /// Returns the right associated to the given point.
    ///
    /// A point is defined as a sequence of attribute IDs while a right is some compact
    /// representation of it, that is a fixed-point for the permutation.
    pub fn from_point(mut attribute_ids: Vec<usize>) -> Result<Self, Error> {
        // A set of attribute has no order. Enforcing an order here allows having a unique
        // representation for all permutations.
        attribute_ids.sort_unstable();
        // Allocate an upper-bound on the actual space required.
        let mut ser = Serializer::with_capacity(4 * attribute_ids.len());
        for value in attribute_ids {
            ser.write_leb128_u64(u64::try_from(value)?)?;
        }
        Ok(Self(ser.finalize().to_vec()))
    }
}

impl Deref for Right {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for Right {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for Right {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl Serializable for Right {
    type Error = Error;

    fn length(&self) -> usize {
        to_leb128_len(self.len()) + self.len()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write_vec(self).map_err(Self::Error::from)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let bytes = de.read_vec()?;
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{bytes_ser_de::Deserializer, reexport::rand_core::CryptoRngCore};

    use super::*;

    impl Right {
        pub fn random(rng: &mut impl CryptoRngCore) -> Self {
            let mut r = Self(vec![0; 16]);
            rng.fill_bytes(&mut r.0);
            r
        }
    }

    #[test]
    fn test_rights() -> Result<(), Error> {
        let mut values: Vec<usize> = vec![12, 0, usize::MAX, 1];
        let r = Right::from_point(values.clone())?;
        values.sort_unstable();
        let mut de = Deserializer::new(&r);
        for v in values {
            let val = de.read_leb128_u64().unwrap() as usize;
            assert_eq!(v, val);
        }
        Ok(())
    }
}
