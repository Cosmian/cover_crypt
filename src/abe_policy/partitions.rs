use std::{hash::Hash, ops::Deref};

use cosmian_crypto_core::bytes_ser_de::Serializer;

use crate::Error;

/// Partition associated to a subset. It corresponds to a combination
/// of attributes across all axes.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct Partition(pub(crate) Vec<u8>);

impl Partition {
    /// Creates a `Partition` from the given list of values.
    pub fn from_attribute_values(mut attribute_values: Vec<u32>) -> Result<Self, Error> {
        // guard against overflow of the 1024 bytes buffer below
        if attribute_values.len() > 200 {
            return Err(Error::InvalidAttribute(
                "The current implementation does not currently support more than 200 attributes \
                 for a partition"
                    .to_string(),
            ));
        }
        // the sort operation allows to get the same `Partition` for :
        // `Department::HR || Level::Secret`
        // and
        // `Level::Secret || Department::HR`
        attribute_values.sort_unstable();
        // the actual size in bytes will be at least equal to the length
        let mut ser = Serializer::with_capacity(attribute_values.len());
        for value in attribute_values {
            ser.write_leb128_u64(u64::from(value))?;
        }
        Ok(Self(ser.finalize()))
    }
}

impl Deref for Partition {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for Partition {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for Partition {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::bytes_ser_de::Deserializer;

    use super::*;

    #[test]
    fn test_partitions() -> Result<(), Error> {
        let mut values: Vec<u32> = vec![12, 0, u32::MAX, 1];
        let partition = Partition::from_attribute_values(values.clone())?;
        // values are sorted n Partition
        values.sort_unstable();
        let mut de = Deserializer::new(&partition);
        for v in values {
            let val = de.read_leb128_u64().unwrap() as u32;
            assert_eq!(v, val);
        }
        Ok(())
    }
}
