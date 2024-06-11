//! Error type for the crate.

use core::{fmt::Display, num::TryFromIntError};

use cosmian_crypto_core::CryptoCoreError;
use pqc_kyber::KyberError;

#[derive(Debug)]
pub enum Error {
    KyberError(KyberError),
    CryptoCoreError(CryptoCoreError),
    KeyError(String),
    AttributeNotFound(String),
    UnsupportedOperator(String),
    CapacityOverflow,
    ExistingPolicy(String),
    OperationNotPermitted(String),
    InvalidBooleanExpression(String),
    InvalidAttribute(String),
    DimensionNotFound(String),
    DeserializationError(serde_json::Error),
    ExistingCombination(String),
    InsufficientAccessPolicy,
    ConversionFailed(String),
    Tracing(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KyberError(err) => write!(f, "Kyber error: {err}"),
            Self::CryptoCoreError(err) => write!(f, "CryptoCore error{err}"),
            Self::KeyError(err) => write!(f, "{err}"),
            Self::AttributeNotFound(err) => write!(f, "attribute not found: {err}"),
            Self::UnsupportedOperator(err) => write!(f, "unsupported operator {err}"),
            Self::CapacityOverflow => write!(f, "attribute capacity overflow"),
            Self::ExistingPolicy(policy_str) => write!(f, "policy {policy_str} already exists"),
            Self::InvalidBooleanExpression(expr_str) => {
                write!(f, "invalid boolean expression: {expr_str}")
            }
            Self::InvalidAttribute(attr) => write!(f, "invalid attribute: {attr}"),
            Self::DimensionNotFound(dim_str) => write!(f, "cannot find dimension: {dim_str}"),
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

impl From<KyberError> for Error {
    fn from(e: KyberError) -> Self {
        Self::KyberError(e)
    }
}

impl std::error::Error for Error {}
