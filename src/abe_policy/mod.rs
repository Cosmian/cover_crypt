mod access_policy;
mod access_structure;
mod attribute;
mod dimension;
mod rights;

#[cfg(any(test, feature = "test-utils"))]
mod tests;

pub use access_policy::AccessPolicy;
pub use access_structure::AccessStructure;
pub use attribute::{AttributeStatus, EncryptionHint, QualifiedAttribute};
pub use dimension::{Attribute, Dimension};
pub use rights::Right;

#[cfg(any(test, feature = "test-utils"))]
pub use tests::gen_structure;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
    V1,
}
