//! This crate implements the `Covercrypt` cryptographic scheme which allows to:
//! - encrypt messages for a given set of policy attributes;
//! - decrypt messages if the decryptor has been assigned one of these policy
//!   attributes;
//! - "rotate" policy attributes;
//! - "refresh" user keys.
//!
//! A rotations prevents decryption of pre-rotation ciphertexts by a
//! post-rotation key and decryption of post-rotation ciphertexts by a
//! pre-rotation key. A pre-rotation key can be refreshed to be granted
//! decryption rights for the post-rotation ciphertexts. A post-rotation key
//! cannot be granted decryption rights for the pre-rotation ciphertexts.
//!
//! Covercrypt encryption offers 128 bits of both pre- and post-quantum
//! security.
//!
//! The `api` module exposes the generic definition of `Covercrypt`.
//!
//! The `interface::statics` module exposes instantiates `Covercrypt`
//! using a DEM scheme build on top of AES256-GCM and a asymmetric key pair
//! built on top of Curve25519.
//!
//! # Example
//!
//! See `examples/runme.rs`.

mod error;

pub mod abe_policy;
pub mod core;
pub mod data_struct;
#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;

pub use error::Error;

pub use self::core::{
    Encapsulation, MasterPublicKey, MasterSecretKey, UserSecretKey,
    api::{CleartextHeader, Covercrypt, EncryptedHeader},
};
