//! This crate defines the `Policy` logic, the basis for Attribute Based
//! Encryption (ABE).
//!
//! A `Policy` is a set of axes. Each dimension is defined by its name and its
//! list of associated attribute names.
//!
//! An `Attribute` is composed by an dimension name and an attribute name within
//! this dimension.

mod access_policy;
mod attribute;
mod coordinates;
mod dimension;
mod policy;

#[cfg(any(test, feature = "test-utils"))]
mod tests;

pub use access_policy::AccessPolicy;
pub use attribute::{AttributeStatus, EncryptionHint, QualifiedAttribute};
pub use coordinates::Coordinate;
pub use dimension::{AttributeParameters, Dimension};
pub use policy::Policy;

#[cfg(any(test, feature = "test-utils"))]
pub use tests::gen_policy;
