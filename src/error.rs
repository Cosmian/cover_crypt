use cosmian_crypto_base::Error as CryptoError;
use std::{
    array::TryFromSliceError,
    fmt::Debug,
    num::{ParseIntError, TryFromIntError},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unknown authorisation {0}")]
    UnknownAuthorisation(String),
    #[error("{0}")]
    CryptoError(CryptoError),
    #[error("attribute not found: {0}")]
    AttributeNotFound(String),
    #[error("{} is missing{}",
        .item.clone().unwrap_or_else(|| "attribute".to_string()),
        match .axis_name {
            Some(axis) => format!(" in axis {}", axis),
            None => "".to_string(),
    })]
    MissingAttribute {
        item: Option<String>,
        axis_name: Option<String>,
    },
    #[error("{0} is missing")]
    MissingAxis(String),
    #[error("attribute {0} expected in {1:?}")]
    ExpectedAttribute(String, Vec<String>),
    #[error("unsupported operand {0}")]
    UnsupportedOperand(String),
    #[error("unsupported operator {0}")]
    UnsupportedOperator(String),
    #[error("attribute capacity overflow")]
    CapacityOverflow,
    #[error("attribute {0} for {1} already exists")]
    ExistingAttribute(String, String),
    #[error("policy {0} already exists")]
    ExistingPolicy(String),
    #[error("invalid size")]
    InvalidSize(String),
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
    InvalidBooleanExpression(String),
    #[error("invalid attribute: {0}")]
    InvalidAttribute(String),
}

impl From<TryFromIntError> for Error {
    fn from(_e: TryFromIntError) -> Self {
        Error::ConversionFailed
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
