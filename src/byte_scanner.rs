use std::convert::TryInto;

use crate::error::Error;

/// Scans a slice sequentially, updating the cursor position on the fly
pub struct BytesScanner<'a> {
    bytes: &'a [u8],
    start: usize,
}

impl<'a> BytesScanner<'a> {
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        BytesScanner { bytes, start: 0 }
    }

    /// Returns a slice of the next `size` bytes or an error if less is
    /// available
    pub fn next(&mut self, size: usize) -> Result<&'a [u8], Error> {
        let end = self.start + size;
        if self.bytes.len() < end {
            return Err(Error::InvalidSize(format!(
                "Invalid size: {}, only {} bytes available",
                size,
                self.bytes.len() - self.start
            )));
        }
        let chunk = &self.bytes[self.start..end];
        self.start = end;
        Ok(chunk)
    }

    /// Read the next 4 big endian bytes to return an u32
    pub fn read_u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.next(4)?.try_into().map_err(
            |_e| Error::InvalidSize("invalid u32".to_string()),
        )?))
    }

    /// Returns the remainder of the slice
    #[allow(dead_code)]
    pub fn remainder(&mut self) -> Option<&'a [u8]> {
        if self.start >= self.bytes.len() {
            None
        } else {
            let remainder = &self.bytes[self.start..];
            self.start = self.bytes.len();
            Some(remainder)
        }
    }

    /// Whether there are more bytes to read
    pub fn has_more(&self) -> bool {
        self.start < self.bytes.len()
    }
}
