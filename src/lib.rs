//! This crate implements the CoverCrypt cryptographic scheme which allows to:
//! - encrypt messages for a given set of policy attributes;
//! - decrypt messages if the decryptor has been assigned one of these policy
//! attributes;
//! - "rotate" policy attributes, which allows to prevent decryption of older
//! ciphertexts for a new user and decryption of new ciphertexts by old users.
//! Old users can be granted decryption right for new ciphertexts after a key
//! refresh.
//!
//! The `api` module exposes the generic definition of CoverCrypt.
//!
//! The `interface::statics` module exposes instantiates CoverCrypt using
//! a DEM scheme build on top of AES256-GCM and a asymmetric key pair built on
//! top of Curve25519.
//!
//! # Example
//!
//! ```
//! use abe_policy::{AccessPolicy, Attribute, Policy, PolicyAxis};
//! use cosmian_cover_crypt::{
//!     interfaces::statics::{CoverCryptX25519Aes256, EncryptedHeader},
//!     CoverCrypt,
//! };
//!
//! // The first attribute axis will be a security level.
//! // This axis is hierarchical, i.e. users matching
//! // `Security Level::Confidential` can also decrypt
//! // messages encrypted for `Security Level::Protected`.
//! let sec_level = PolicyAxis::new(
//!     "Security Level",
//!     &["Protected", "Confidential", "Top Secret"],
//!     true,
//! );
//!
//! // Another attribute axis will be department names.
//! // This axis is *not* hierarchical.
//! let department = PolicyAxis::new("Department", &["R&D", "HR", "MKG", "FIN"], false);
//!
//! // Generate a new `Policy` object with a 100 revocations allowed.
//! let mut policy = Policy::new(100);
//!
//! // Add the two generated axes to the policy
//! policy.add_axis(&sec_level).unwrap();
//! policy.add_axis(&department).unwrap();
//!
//! // Setup CoverCrypt and generate master keys
//! let cover_crypt = CoverCryptX25519Aes256::default();
//! let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy).unwrap();
//!
//! // The user has a security clearance `Security Level::Top Secret`,
//! // and belongs to the finance department (`Department::FIN`).
//! let access_policy =
//!     AccessPolicy::from_boolean_expression("Security Level::Top Secret && Department::FIN")
//!         .unwrap();
//! let mut usk = cover_crypt
//!     .generate_user_secret_key(&msk, &access_policy, &policy)
//!     .unwrap();
//!
//! // Encrypt
//! let (_, encrypted_header) = EncryptedHeader::generate(
//!     &cover_crypt,
//!     &policy,
//!     &mpk,
//!     &access_policy,
//!     None,
//!     None,
//! )
//! .unwrap();
//!
//! // The user is able to decrypt the encrypted header.
//! assert!(encrypted_header.decrypt(&cover_crypt, &usk, None).is_ok());
//!
//! //
//! // Rotate the `Security Level::Top Secret` attribute
//! policy
//!     .rotate(&Attribute::from(("Security Level", "Top Secret")))
//!     .unwrap();
//!
//! // Master keys need to be updated to take into account the policy rotation
//! cover_crypt
//!     .update_master_keys(&policy, &mut msk, &mut mpk)
//!     .unwrap();
//!
//! // Encrypt with rotated attribute
//! let (_, new_encrypted_header) = EncryptedHeader::generate(
//!     &cover_crypt,
//!     &policy,
//!     &mpk,
//!     &AccessPolicy::new("Security Level", "Top Secret"),
//!     None,
//!     None,
//! )
//! .unwrap();
//!
//! // user cannot decrypt the newly encrypted header
//! assert!(new_encrypted_header
//!     .decrypt(&cover_crypt, &usk, None)
//!     .is_err());
//!
//! // refresh user secret key, do not grant old encryption access
//! cover_crypt
//!     .refresh_user_secret_key(&mut usk, &access_policy, &msk, &policy, false)
//!     .unwrap();
//!
//! // The user with refreshed key is able to decrypt the newly encrypted header.
//! assert!(new_encrypted_header
//!     .decrypt(&cover_crypt, &usk, None)
//!     .is_ok());
//!
//! // But it cannot decrypt old ciphertexts
//! assert!(encrypted_header.decrypt(&cover_crypt, &usk, None).is_err());
//! ```

pub mod api;
mod cover_crypt_core;
pub mod error;
pub mod interfaces;
#[macro_use]
mod macros;
pub mod partitions;

pub use api::{CleartextHeader, CoverCrypt, EncryptedHeader};
pub use error::Error;
pub use interfaces::statics::CoverCryptX25519Aes256 as CoverCryptStruct;
