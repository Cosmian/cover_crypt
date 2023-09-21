//! This crate defines the `Policy` logic, the basis for Attribute Based
//! Encryption (ABE).
//!
//! A `Policy` is a set of axes. Each axis is defined by its name and its list
//! of associated attribute names.
//!
//! An `Attribute` is composed by an axis name and an attribute name within
//! this axis.

mod access_policy;
mod attribute;
mod dimension;
mod legacy_policy;
mod partitions;
mod policy;

pub use access_policy::AccessPolicy;
pub use attribute::{Attribute, AttributeStatus, Attributes, EncryptionHint};
pub use dimension::{AttributeParameters, Dimension, DimensionBuilder};
pub use legacy_policy::{LegacyPolicy, PolicyV1};
pub use partitions::Partition;
pub use policy::Policy;
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyVersion {
    V1,
    V2,
}
