use std::{
    array::TryFromSliceError,
    fmt::Debug,
    num::{ParseIntError, TryFromIntError},
};

use cosmian_crypto_base_anssi::CryptoBaseError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unknown partition {0}")]
    UnknownPartition(String),
    #[error("{0}")]
    CryptoError(CryptoBaseError),
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
        Error::ConversionFailed
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::JsonParsing(e.to_string())
    }
}

impl From<TryFromSliceError> for Error {
    fn from(_e: TryFromSliceError) -> Self {
        Error::ConversionFailed
    }
}

impl From<ParseIntError> for Error {
    fn from(_e: ParseIntError) -> Self {
        Error::ConversionFailed
    }
}

impl From<CryptoBaseError> for Error {
    fn from(e: CryptoBaseError) -> Self {
        match e {
            CryptoBaseError::SizeError { given, expected } => {
                Error::InvalidSize(format!("expected: {}, given: {}", expected, given))
            }
            CryptoBaseError::InvalidSize(e) => Error::InvalidSize(e),
            e => Error::CryptoError(e),
        }
    }
}

#[cfg(feature = "ffi")]
impl From<std::ffi::NulError> for Error {
    fn from(e: std::ffi::NulError) -> Self {
        Error::Other(format!("FFI error: {}", e))
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Error::Other(format!("UTF8 error: {}", e))
    }
}
