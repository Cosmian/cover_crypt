//! Define this crate error type.

use thiserror::Error;

/// Crate error type.
#[derive(Error, Debug)]
pub enum Error {
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
}
