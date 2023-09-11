//! Error type for the crate.

use core::{fmt::Display, num::TryFromIntError};

use cosmian_crypto_core::CryptoCoreError;

#[derive(Debug)]
pub enum Error {
    CryptoCoreError(CryptoCoreError),
    KeyError(String),
    AttributeNotFound(String),
    UnsupportedOperator(String),
    CapacityOverflow,
    ExistingPolicy(String),
    OperationNotPermitted(String),
    InvalidBooleanExpression(String),
    InvalidAttribute(String),
    AxisNotFound(String),
    DeserializationError(serde_json::Error),
    ExistingCombination(String),
    InsufficientAccessPolicy,
    ConversionFailed(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CryptoCoreError(err) => write!(f, "{err}"),
            Self::KeyError(err) => write!(f, "{err}"),
            Self::AttributeNotFound(err) => write!(f, "attribute not found: {err}"),
            Self::UnsupportedOperator(err) => write!(f, "unsupported operator {err}"),
            Self::CapacityOverflow => write!(f, "attribute capacity overflow"),
            Self::ExistingPolicy(policy_str) => write!(f, "policy {policy_str} already exists"),
            Self::InvalidBooleanExpression(expr_str) => {
                write!(f, "invalid boolean expression: {expr_str}")
            }
            Self::InvalidAttribute(attr) => write!(f, "invalid attribute: {attr}"),
            Self::AxisNotFound(axis_str) => write!(f, "cannot find axis: {axis_str}"),
            Self::DeserializationError(err) => write!(f, "deserialization error: {err}"),
            Self::ExistingCombination(combination) => {
                write!(f, "Combination {combination} already exists")
            }
            Self::InsufficientAccessPolicy => write!(
                f,
                "Unable to decrypt the header. User decryption key has not the right policy to \
                 decrypt this input."
            ),
            Self::ConversionFailed(err) => write!(f, "Conversion failed: {err}"),
            Self::OperationNotPermitted(err) => write!(f, "Operation not permitted: {err}"),
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
