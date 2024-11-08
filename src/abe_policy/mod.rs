mod access_policy;
mod attribute;
mod dimension;
mod policy;
mod rights;

#[cfg(any(test, feature = "test-utils"))]
mod tests;

pub use access_policy::AccessPolicy;
pub use attribute::{AttributeStatus, EncryptionHint, QualifiedAttribute};
pub use dimension::{Attribute, Dimension};
pub use policy::AccessStructure;
pub use rights::Right;

#[cfg(any(test, feature = "test-utils"))]
pub use tests::gen_structure;
