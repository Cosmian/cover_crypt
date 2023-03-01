//! This crate implements the `CoverCrypt` cryptographic scheme which allows to:
//! - encrypt messages for a given set of policy attributes;
//! - decrypt messages if the decryptor has been assigned one of these policy
//! attributes;
//! - "rotate" policy attributes, which allows to prevent decryption of older
//! ciphertexts for a new user and decryption of new ciphertexts by old users.
//! Old users can be granted decryption right for new ciphertexts after a key
//! refresh.
//!
//! The `api` module exposes the generic definition of `CoverCrypt`.
//!
//! The `interface::statics` module exposes instantiates `CoverCrypt` using
//! a DEM scheme build on top of AES256-GCM and a asymmetric key pair built on
//! top of Curve25519.
//!
//! # Example
//!
//! See `examples/runme.rs`.

mod error;

pub mod abe_policy;
pub mod core;
pub mod statics;
pub mod test_utils;

pub use error::Error;

pub use self::core::api::{CleartextHeader, CoverCrypt, EncryptedHeader};
