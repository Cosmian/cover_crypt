pub mod api;
pub mod core;
mod policy;

pub mod encrypted_header;

pub use api::Covercrypt;
pub use core::{MasterPublicKey, MasterSecretKey, UserSecretKey, XEnc};
pub use policy::{
    AccessPolicy, AccessStructure, Attribute, Dimension, EncryptionHint, EncryptionStatus,
    QualifiedAttribute,
};

#[cfg(any(test, feature = "test-utils"))]
pub use policy::gen_structure;

use cosmian_crypto_core::{traits::AE, Secret};

pub trait KemAc<const LENGTH: usize> {
    type EncapsulationKey;
    type DecapsulationKey;
    type Encapsulation;
    type Error: std::error::Error;

    /// Generates a new encapsulation for the given access policy.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is not valid.
    fn encaps(
        &self,
        ek: &Self::EncapsulationKey,
        ap: &AccessPolicy,
    ) -> Result<(Secret<LENGTH>, Self::Encapsulation), Self::Error>;

    /// Attempts opening the given encapsulation with the given key.
    ///
    /// Returns the encapsulated secret upon success or `None` if this key was
    /// not authorized to open this encapsulation.
    fn decaps(
        &self,
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<Option<Secret<LENGTH>>, Self::Error>;
}

pub trait PkeAc<const KEY_LENGTH: usize, E: AE<KEY_LENGTH>> {
    type EncryptionKey;
    type DecryptionKey;
    type Ciphertext;
    type Error: std::error::Error;

    /// Encrypts the given plaintext under the given access policy.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is not valid.
    fn encrypt(
        &self,
        ek: &Self::EncryptionKey,
        ap: &AccessPolicy,
        ptx: &[u8],
    ) -> Result<Self::Ciphertext, Self::Error>;

    /// Attempts decrypting the given ciphertext with the given key.
    ///
    /// Returns the plaintext upon success, or `None` if this key was not
    /// authorized to decrypt this ciphertext.
    fn decrypt(
        &self,
        dk: &Self::DecryptionKey,
        ctx: &Self::Ciphertext,
    ) -> Result<Option<E::Plaintext>, Self::Error>;
}
