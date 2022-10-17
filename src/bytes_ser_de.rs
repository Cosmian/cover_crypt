//! Implement the `Serializer` and `Deserializer` objects using LEB128.

use crate::error::Error;
use std::io::{Read, Write};

pub trait Serializable: Sized {
    /// Writes to the given `Serializer`.
    fn write(&self, ser: &mut Serializer) -> Result<usize, Error>;

    /// Reads from the given `Deserializer`.
    fn read(de: &mut Deserializer) -> Result<Self, Error>;

    /// Serializes the object.
    fn try_to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut ser = Serializer::new();
        self.write(&mut ser)?;
        Ok(ser.finalize())
    }

    /// Deserializes the object.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::InvalidSize("Given byte string is empty".to_string()));
        }
        let mut de = Deserializer::new(bytes);
        Self::read(&mut de)
    }
}

pub struct Deserializer<'a> {
    readable: &'a [u8],
}

impl<'a> Deserializer<'a> {
    /// Generates a new `Deserializer` from the given bytes.
    ///
    /// - `bytes`   : bytes to deserialize
    pub const fn new(bytes: &'a [u8]) -> Deserializer<'a> {
        Deserializer { readable: bytes }
    }

    /// Reads a `u64` from the `Deserializer`.
    pub fn read_u64(&mut self) -> Result<u64, Error> {
        leb128::read::unsigned(&mut self.readable).map_err(|e| {
            Error::InvalidSize(format!(
                "Deserializer: failed reading the size of the next array: {}",
                e
            ))
        })
    }

    /// Reads an array of bytes of length `LENGTH` from the `Deserializer`.
    pub fn read_array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], Error> {
        let mut buf = [0; LENGTH];
        self.readable.read_exact(&mut buf).map_err(|_| {
            Error::InvalidSize(format!(
                "Deserializer: failed reading array of: {LENGTH} bytes",
            ))
        })?;
        Ok(buf)
    }

    /// Reads a vector of bytes from the `Deserializer`.
    ///
    /// Vectors serialization overhead is `size_of(LEB128(vector_size))`, where
    /// `LEB128()` is the LEB128 serialization function.
    pub fn read_vec(&mut self) -> Result<Vec<u8>, Error> {
        // the size of the vector is written is prefixed to the serialization
        let len_u64 = self.read_u64()?;
        if len_u64 == 0 {
            return Ok(vec![]);
        };
        let len = usize::try_from(len_u64).map_err(|_| {
            Error::InvalidSize(format!(
                "Deserializer: size of array is too big: {} bytes",
                len_u64
            ))
        })?;
        let mut buf = vec![0_u8; len];
        self.readable.read_exact(&mut buf).map_err(|_| {
            Error::InvalidSize(format!(
                "Deserializer: failed reading array of: {} bytes",
                len
            ))
        })?;
        Ok(buf)
    }

    /// Consumes the `Deserializer` and returns the remaining bytes.
    pub fn finalize(self) -> Vec<u8> {
        self.readable.to_vec()
    }
}

pub struct Serializer {
    writable: Vec<u8>,
}

impl Serializer {
    /// Generates a new `Serializer`.
    pub const fn new() -> Self {
        Self { writable: vec![] }
    }

    /// Writes a `u64` to the `Serializer`.
    ///
    /// - `n`   : `u64` to write
    pub fn write_u64(&mut self, n: u64) -> Result<usize, Error> {
        leb128::write::unsigned(&mut self.writable, n).map_err(|e| {
            Error::InvalidSize(format!(
                "Serializer: unexpected LEB128 error writing {} bytes: {}",
                n, e
            ))
        })
    }

    /// Writes an array of bytes to the `Serializer`.
    ///
    /// - `array`   : array of bytes to write
    pub fn write_array(&mut self, array: &[u8]) -> Result<usize, Error> {
        self.writable.write(array).map_err(|e| {
            Error::InvalidSize(format!(
                "Serializer: unexpected error writing {} bytes: {}",
                array.len(),
                e
            ))
        })
    }

    /// Writes a vector of bytes to the `Serializer`.
    ///
    /// Vectors serialization overhead is `size_of(LEB128(vector_size))`, where
    /// `LEB128()` is the LEB128 serialization function.
    ///
    /// - `vector`  : vector of bytes to write
    pub fn write_vec(&mut self, vector: &[u8]) -> Result<usize, Error> {
        let mut len = self.write_u64(vector.len() as u64)?;
        len += self.write_array(vector)?;
        Ok(len)
    }

    /// Consumes the `Serializer` and returns the serialized bytes.
    pub fn finalize(self) -> Vec<u8> {
        self.writable
    }
}

impl Default for Serializer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{Deserializer, Serializer};
    use crate::error::Error;

    #[test]
    pub fn test_ser_de() -> Result<(), Error> {
        let a1 = b"azerty".to_vec();
        let a2 = b"".to_vec();
        let a3 = "nbvcxwmlkjhgfdsqpoiuytreza)àç_è-('é&".as_bytes().to_vec();

        let mut ser = Serializer::new();
        assert_eq!(7, ser.write_vec(&a1)?);
        assert_eq!(1, ser.write_vec(&a2)?);
        assert_eq!(41, ser.write_vec(&a3)?);
        assert_eq!(49, ser.writable.len());

        let mut de = Deserializer::new(&ser.writable);
        let a1_ = de.read_vec()?;
        assert_eq!(a1, a1_);
        let a2_ = de.read_vec()?;
        assert_eq!(a2, a2_);
        let a3_ = de.read_vec()?;
        assert_eq!(a3, a3_);

        Ok(())
    }
}
