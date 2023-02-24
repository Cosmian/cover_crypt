//! Error type for the crate

use std::{array::TryFromSliceError, fmt::Debug, num::TryFromIntError};

use cosmian_crypto_core::CryptoCoreError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unknown partition {0}")]
    UnknownPartition(String),
    #[error("{0}")]
    CryptoCoreError(CryptoCoreError),
    #[error("{0}")]
    KeyError(String),
    #[error("attribute not found: {0}")]
    AttributeNotFound(String),
    #[error("{} is missing{}",
        .item.clone().unwrap_or_else(|| "attribute".to_string()),
        match .axis_name {
            Some(axis) => format!(" in axis {axis}"),
            None => String::new(),
    })]
    MissingAttribute {
        item: Option<String>,
        axis_name: Option<String>,
    },
    #[error("No axis given")]
    MissingAxis,
    #[error("unsupported operator {0}")]
    UnsupportedOperator(String),
    #[error("attribute capacity overflow")]
    CapacityOverflow,
    #[error("policy {0} already exists")]
    ExistingPolicy(String),
    #[error("invalid boolean expression: {0}")]
    InvalidBooleanExpression(String),
    #[error("invalid attribute: {0}")]
    InvalidAttribute(String),
    #[error("invalid axis: {0}")]
    InvalidAxis(String),
    #[error("deserialization error: {0}")]
    DeserializationError(serde_json::Error),
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
        "Unable to decrypt the header. User decryption key has not the right policy to decrypt \
         this input."
    )]
    InsufficientAccessPolicy,
    #[error("Conversion failed: {0}")]
    ConversionFailed(String),
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

impl From<CryptoCoreError> for Error {
    fn from(e: CryptoCoreError) -> Self {
        Self::CryptoCoreError(e)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::Other(format!("UTF8 error: {e}"))
    }
}
