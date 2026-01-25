//! Error type for the crate.

use core::{fmt::Display, num::TryFromIntError};

use cosmian_crypto_core::CryptoCoreError;

#[derive(Debug)]
pub enum Error {
    Kem(String),
    CryptoCoreError(CryptoCoreError),
    KeyError(String),
    AttributeNotFound(String),
    ExistingDimension(String),
    OperationNotPermitted(String),
    InvalidBooleanExpression(String),
    InvalidAttribute(String),
    DimensionNotFound(String),
    ConversionFailed(String),
    Tracing(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kem(err) => write!(f, "Kyber error: {err}"),
            Self::CryptoCoreError(err) => write!(f, "CryptoCore error: {err}"),
            Self::KeyError(err) => write!(f, "{err}"),
            Self::AttributeNotFound(err) => write!(f, "attribute not found: {err}"),
            Self::ExistingDimension(dimension) => {
                write!(f, "dimension {dimension} already exists")
            }
            Self::InvalidBooleanExpression(expr_str) => {
                write!(f, "invalid boolean expression: {expr_str}")
            }
            Self::InvalidAttribute(attr) => write!(f, "invalid attribute: {attr}"),
            Self::DimensionNotFound(dim_str) => write!(f, "cannot find dimension: {dim_str}"),
            Self::ConversionFailed(err) => write!(f, "Conversion failed: {err}"),
            Self::OperationNotPermitted(err) => write!(f, "Operation not permitted: {err}"),
            Self::Tracing(err) => write!(f, "tracing error: {err}"),
        }
    }
}

impl From<TryFromIntError> for Error {
    fn from(e: TryFromIntError) -> Self {
        Self::ConversionFailed(e.to_string())
    }
}

impl From<CryptoCoreError> for Error {
    fn from(e: CryptoCoreError) -> Self {
        Self::CryptoCoreError(e)
    }
}

impl std::error::Error for Error {}
