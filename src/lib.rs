//! This crate implements the CoverCrypt scheme. This cryptographic scheme
//! allows to:
//!
//! - encrypt messages for a given set of policy attributes;
//! - decrypt messages if the decryptor corresponds to one of the policy
//! attributes;
//! - "rotate" policy attributes, which allows to prevent decryption of older
//! ciphertexts for a new user and decryption of new ciphertexts by old users.
//! Old users can be granted decryption right for new ciphertexts after a key
//! refresh.
//!
//! The `api` module exposes the KEM built on top of CoverCrypt.
//! The `interface::statics` module exposes hybrid methods to encrypt and
//! decrypt headers and blocks using the `api` KEM and a `DEM` based on
//! AES 256 GCM.
//!
//! # Example
//!
//! ```
//! use abe_policy::{AccessPolicy, Attribute, Policy, PolicyAxis};
//! use cosmian_crypto_core::symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto;
//! use cover_crypt::{CoverCrypt, interfaces::statics::*};
//!
//! //
//! // Declare a new policy
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
//! policy.add_axis(&sec_level)
//!     .unwrap();
//! policy.add_axis(&department)
//!     .unwrap();
//!
//! //
//! // Setup CoverCrypt and generate master keys
//! let cc = CoverCrypt::default();
//! let (mut master_private_key, mut master_public_key) = cc.generate_master_keys(&policy)
//!     .unwrap();
//!
//! //
//! // Generate user private key
//!
//! // The user has a security clearance `Security Level::Top Secret`,
//! // and belongs to the finance department (`Department::FIN`).
//! let access_policy =
//!     AccessPolicy::from_boolean_expression("Security Level::Top Secret && Department::FIN")
//!         .unwrap();
//! let mut user_key =
//!     cc.generate_user_private_key(&master_private_key, &access_policy, &policy)
//!         .unwrap();
//!
//! //
//! // Encrypt
//! let encrypted_header = encrypt_hybrid_header::<Aes256GcmCrypto>(
//!     &policy,
//!     &master_public_key,
//!     &[Attribute::from(("Security Level", "Top Secret"))],
//!     None,
//! ).unwrap();
//!
//! //
//! // Decryption
//!
//! // The user is able to decrypt the encrypted header.
//! assert!(decrypt_hybrid_header::<Aes256GcmCrypto>(
//!     &user_key,
//!     &encrypted_header.header_bytes,
//! )
//! .is_ok());
//!
//! //
//! // Rotate the `Security Level::Top Secret` attribute
//! policy.rotate(&Attribute::from(("Security Level", "Top Secret")))
//!     .unwrap();
//!
//! // Master keys need to be updated to take into account the policy rotation
//! cc.update_master_keys(&policy, &mut master_private_key, &mut master_public_key)
//!     .unwrap();
//!
//! //
//! // Encrypt with rotated attribute
//! let new_encrypted_header = encrypt_hybrid_header::<Aes256GcmCrypto>(
//!     &policy,
//!     &master_public_key,
//!     &[Attribute::from(("Security Level", "Top Secret"))],
//!     None,
//! ).unwrap();
//!
//! // user cannot decrypt the newly encrypted header
//! assert!(decrypt_hybrid_header::<Aes256GcmCrypto>(
//!     &user_key,
//!     &new_encrypted_header.header_bytes,
//! )
//! .is_err());
//!
//! // refresh user private key, do not grant old encryption access
//! cc.refresh_user_private_key
//!     (&mut user_key, &access_policy, &master_private_key, &policy, false)
//!     .unwrap();
//!
//! // The user with refreshed key is able to decrypt the newly encrypted header.
//! assert!(decrypt_hybrid_header::<Aes256GcmCrypto>(
//!     &user_key,
//!     &new_encrypted_header.header_bytes,
//! )
//! .is_ok());
//!
//! // But it cannot decrypt old ciphertexts
//! assert!(decrypt_hybrid_header::<Aes256GcmCrypto>(
//!     &user_key,
//!     &encrypted_header.header_bytes,
//! )
//! .is_err());
//! ```

pub mod api;
pub mod bytes_ser_de;
mod cover_crypt_core;
pub mod error;
pub mod interfaces;

pub use api::CoverCrypt;
pub use cover_crypt_core::{Encapsulation, MasterPrivateKey, PublicKey, SecretKey, UserPrivateKey};
