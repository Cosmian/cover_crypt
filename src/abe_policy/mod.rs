//! This crate defines the `Policy` logic, the basis for Attribute Based
//! Encryption (ABE).
//!
//! A `Policy` is a set of axes. Each dimension is defined by its name and its list
//! of associated attribute names.
//!
//! An `Attribute` is composed by an dimension name and an attribute name within
//! this dimension.

mod access_policy;
mod attribute;
mod coordinates;
mod dimension;
mod policy;
mod policy_versions;

pub use access_policy::AccessPolicy;
pub use attribute::{Attribute, AttributeStatus, Attributes, EncryptionHint};
pub use coordinates::Coordinate;
pub use dimension::{AttributeParameters, Dimension, DimensionBuilder};
pub use policy_versions::{LegacyPolicy, PolicyV1, PolicyV2 as Policy};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyVersion {
    V1,
    V2,
}
