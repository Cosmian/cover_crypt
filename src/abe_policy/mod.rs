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
mod partitions;
mod policy;

pub use access_policy::AccessPolicy;
pub use attribute::{Attribute, Attributes};
pub use partitions::Partition;
pub use policy::{EncryptionHint, LegacyPolicy, Policy, PolicyAxis};

#[cfg(test)]
mod tests;
