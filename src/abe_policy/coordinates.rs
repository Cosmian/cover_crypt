use std::{hash::Hash, ops::Deref};

use cosmian_crypto_core::bytes_ser_de::{to_leb128_len, Serializable, Serializer};

use crate::Error;

/// Space coordinate.
///
/// It is a representation of a given combination of one component per
/// dimension.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Coordinate(Vec<u8>);

impl Coordinate {
    /// Computes the coordinate associated to the given list of IDs of dimension
    /// component.
    ///
    /// Coordinates are defined using one component per dimension. But in
    /// practice, neutral elements may be omitted: no component from a given
    /// dimension means a neutral component.
    ///
    /// The current implementation simply uses a sorted sequence of `u32` IDs.
    ///
    /// This is bad because:
    /// - it creates *coupling* between the internal coordinate representation
    ///   (ID serialization) and the way dimension coordinates are represented
    ///   in the policy object (needs to provide the unique ID).
    /// - this means coordinates are variable-length variables, and thus heap
    ///   allocated.
    ///
    /// This is good because:
    /// - it minimizes coordinate size (e.g. hashing would creates 16-byte long
    ///   coordinates) ...
    ///   ... *only* when components IDs and the number of non-neutral
    ///   components are kept small (btw, the number of such components is
    ///   limited to 200; this is OK since the dimensionality is an upper
    ///   bound).
    ///
    /// => good for small dimensionality and young policies (not many
    /// deletions/creations) but do not scale well.
    ///
    /// Alternative implementation could simply use hashing. This allows using
    /// arbitrary representations for dimension components (strings? ->
    /// attribute names). This releases the constraint that policy need to
    /// produce (thus store) unique IDs for dimension components. Coordinates
    /// would then be fixed size 16-byte long values.
    ///
    /// However:
    /// - this means that hash need to be *commutative* and *associative* or
    ///   that sorting is used before hashing (and sorting arbitrary types may
    ///   be less efficient than sorting `u32`, even though it may be negligible
    ///   compared to the crypto operation times)
    /// - recreating a deleted components will result in the same coordinate.
    ///   This is
    pub fn from_attribute_ids(mut attribute_ids: Vec<u32>) -> Result<Self, Error> {
        // guard against overflow of the 1024 bytes buffer below
        if attribute_ids.len() > 200 {
            return Err(Error::InvalidAttribute(
                "The current implementation does not currently support more than 200 attributes for a coordinate".to_string(),
            ));
        }
        // the sort operation allows to get the same `Coordinate` for :
        // `Department::HR && Level::Secret`
        // and
        // `Level::Secret && Department::HR`
        attribute_ids.sort_unstable();
        // the actual size in bytes will be at least equal to the length
        let mut ser = Serializer::with_capacity(attribute_ids.len());
        for value in attribute_ids {
            ser.write_leb128_u64(u64::from(value))?;
        }
        Ok(Self(ser.finalize().to_vec()))
    }
}

impl Deref for Coordinate {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for Coordinate {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for Coordinate {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl Serializable for Coordinate {
    type Error = Error;

    fn length(&self) -> usize {
        to_leb128_len(self.len()) + self.len()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write_vec(self).map_err(Self::Error::from)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let bytes =  de.read_vec()?;
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{bytes_ser_de::Deserializer, reexport::rand_core::CryptoRngCore};

    use super::*;

    impl Coordinate {
        pub fn random(rng: &mut impl CryptoRngCore) -> Self {
            let mut coordinate = Self(vec![0; 16]);
            rng.fill_bytes(&mut coordinate.0);
            coordinate
        }
    }

    #[test]
    fn test_coordinates() -> Result<(), Error> {
        let mut values: Vec<u32> = vec![12, 0, u32::MAX, 1];
        let coordinate = Coordinate::from_attribute_ids(values.clone())?;
        values.sort_unstable();
        let mut de = Deserializer::new(&coordinate);
        for v in values {
            let val = de.read_leb128_u64().unwrap() as u32;
            assert_eq!(v, val);
        }
        Ok(())
    }
}
