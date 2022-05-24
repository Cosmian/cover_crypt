#![allow(clippy::module_name_repetitions)]

mod access_policy;
mod attribute;
mod policy;

pub use access_policy::{ap, AccessPolicy};
pub use attribute::Attribute;
pub use policy::{Policy, PolicyAxis};

#[cfg(test)]
mod tests;
