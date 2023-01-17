//! Error type for the crate

use std::{array::TryFromSliceError, fmt::Debug, num::TryFromIntError};

use cosmian_crypto_core::CryptoCoreError;
#[cfg(feature = "hybrid")]
use cosmian_kyber::KyberError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unknown partition {0}")]
    UnknownPartition(String),
    #[error("{0}")]
    CryptoCoreError(CryptoCoreError),
    #[error("{0}")]
    KeyError(String),
    #[error(transparent)]
    PolicyError(#[from] abe_policy::Error),
    #[error("attribute not found: {0}")]
    AttributeNotFound(String),
    #[error("Combination {0} already exists")]
    ExistingCombination(String),
    #[error("invalid size: {0}")]
    InvalidSize(String),
    #[error("Empty secret key")]
    EmptySecretKey,
    #[error("Empty ciphertext")]
    EmptyCiphertext,
    #[error("Empty plaintext")]
    EmptyPlaintext,
    #[error("Header length must be at least 4 bytes. Found {0}")]
    InvalidHeaderSize(usize),
    #[error("could not decode number of attributes in encrypted message")]
    DecodingAttributeNumber,
    #[error(
        "Unable to decrypt the header. User decryption key has not the right policy to \
         decrypt this input."
    )]
    InsufficientAccessPolicy,
    #[error("Conversion failed: {0}")]
    ConversionFailed(String),
    #[error("Invalid boolean expression: {0}")]
    InvalidAttribute(String),
    #[error("json parsing error: {0}")]
    JsonParsing(String),
    #[error("{0}")]
    Other(String),
}

impl From<TryFromIntError> for Error {
    fn from(e: TryFromIntError) -> Self {
        Self::ConversionFailed(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::JsonParsing(e.to_string())
    }
}

impl From<TryFromSliceError> for Error {
    fn from(e: TryFromSliceError) -> Self {
        Self::ConversionFailed(e.to_string())
    }
}

#[cfg(feature = "hybrid")]
impl From<KyberError> for Error {
    fn from(e: KyberError) -> Self {
        Self::CryptoError(e.to_string())
    }
}

impl From<CryptoCoreError> for Error {
    fn from(e: CryptoCoreError) -> Self {
        Self::CryptoCoreError(e)
    }
}

#[cfg(feature = "ffi")]
impl From<std::ffi::NulError> for Error {
    fn from(e: std::ffi::NulError) -> Self {
        Self::Other(format!("FFI error: {e}"))
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::Other(format!("UTF8 error: {e}"))
    }
}

#[cfg(feature = "python")]
impl From<Error> for pyo3::PyErr {
    fn from(e: Error) -> Self {
        pyo3::exceptions::PyException::new_err(format!("{e}"))
    }
}
