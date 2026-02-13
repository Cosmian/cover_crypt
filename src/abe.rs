mod policy;

pub mod api;
pub mod core;
pub mod traits;

pub mod encrypted_header;

pub use api::Covercrypt;
pub use core::{MasterPublicKey, MasterSecretKey, UserSecretKey, XEnc};
pub use policy::{
    AccessPolicy, AccessStructure, Attribute, Dimension, EncryptionHint, EncryptionStatus,
    QualifiedAttribute,
};

#[cfg(any(test, feature = "test-utils"))]
pub use policy::gen_structure;
