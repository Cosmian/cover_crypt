//! Error type for the crate

use std::{array::TryFromSliceError, fmt::Debug, num::TryFromIntError};

use cosmian_crypto_core::CryptoCoreError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unknown partition {0}")]
    UnknownPartition(String),
    #[error("{0}")]
    CryptoError(CryptoCoreError),
    #[error(transparent)]
    PolicyError(#[from] abe_policy::Error),
    #[error("attribute not found: {0}")]
    AttributeNotFound(String),
    #[error("Combination {0} already exists")]
    ExistingCombination(String),
    #[error("invalid size")]
    InvalidSize(String),
    #[error("Empty private key")]
    EmptyPrivateKey,
    #[error("Empty ciphertext")]
    EmptyCiphertext,
    #[error("Empty plaintext")]
    EmptyPlaintext,
    #[error("Header length must be at least 4 bytes. Found {0}")]
    InvalidHeaderSize(usize),
    #[error("could not decode number of attributes in encrypted message")]
    DecodingAttributeNumber,
    #[error(
        "Unable to decrypt the header size. User decryption key has not the right policy to \
         decrypt this input."
    )]
    InsufficientAccessPolicy,
    #[error("conversion failed")]
    ConversionFailed,
    #[error("invalid boolean expression: {0}")]
    InvalidAttribute(String),
    #[error("json parsing error: {0}")]
    JsonParsing(String),
    #[error("{0}")]
    Other(String),
}

impl From<TryFromIntError> for Error {
    fn from(_e: TryFromIntError) -> Self {
        Self::ConversionFailed
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::JsonParsing(e.to_string())
    }
}

impl From<TryFromSliceError> for Error {
    fn from(_e: TryFromSliceError) -> Self {
        Self::ConversionFailed
    }
}

impl From<CryptoCoreError> for Error {
    fn from(e: CryptoCoreError) -> Self {
        match e {
            CryptoCoreError::SizeError { given, expected } => {
                Self::InvalidSize(format!("expected: {}, given: {}", expected, given))
            }
            CryptoCoreError::InvalidSize(e) => Self::InvalidSize(e),
            e => Self::CryptoError(e),
        }
    }
}

#[cfg(feature = "ffi")]
impl From<std::ffi::NulError> for Error {
    fn from(e: std::ffi::NulError) -> Self {
        Self::Other(format!("FFI error: {}", e))
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::Other(format!("UTF8 error: {}", e))
    }
}
