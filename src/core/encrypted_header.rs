use cosmian_crypto_core::{
    kdf256, Aes256Gcm, Dem, Instantiable, Nonce, RandomFixedSizeCBytes, Secret, SymmetricKey,
};

use crate::{
    abe_policy::{AccessPolicy, Policy},
    api::{Covercrypt, CovercryptKEM},
    core::SEED_LENGTH,
    Encapsulation, Error, MasterPublicKey, UserSecretKey,
};

/// Encrypted header holding a `Covercrypt` encapsulation of a 256-byte seed, and metadata
/// encrypted under the scheme AES256Gcm using a key derived from the encapsulated seed.
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedHeader {
    pub encapsulation: Encapsulation,
    pub encrypted_metadata: Option<Vec<u8>>,
}

impl EncryptedHeader {
    /// Generates an encrypted header for a random seed and the given metadata.
    /// Returns the encrypted header along with the encapsulated seed.
    ///
    /// - `cover_crypt`         : `Covercrypt` object
    /// - `policy`              : global policy
    /// - `public_key`          : `Covercrypt` public key
    /// - `encryption_policy`   : access policy used for the encapsulation
    /// - `header_metadata`     : additional data symmetrically encrypted in the
    ///   header
    /// - `authentication_data` : authentication data used in the DEM encryption
    pub fn generate(
        cover_crypt: &Covercrypt,
        policy: &Policy,
        public_key: &MasterPublicKey,
        encryption_policy: &AccessPolicy,
        metadata: Option<&[u8]>,
        authentication_data: Option<&[u8]>,
    ) -> Result<(Secret<SEED_LENGTH>, Self), Error> {
        let (seed, encapsulation) = cover_crypt.encaps(public_key, policy, encryption_policy)?;

        let encrypted_metadata = metadata
            .map(|bytes| {
                let mut key = SymmetricKey::<{ Aes256Gcm::KEY_LENGTH }>::default();
                kdf256!(&mut key, &seed, &[0u8]);
                let mut rng = cover_crypt.rng();
                let nonce = Nonce::<{ Aes256Gcm::NONCE_LENGTH }>::new(&mut *rng);
                let aes = Aes256Gcm::new(&key);
                aes.encrypt(&nonce, bytes, authentication_data)
            })
            .transpose()?;

        // Generating a new seed adding a variant component 1, to prevent reusing
        // seed used for the metadata encryption.
        let mut new_seed = Secret::<SEED_LENGTH>::default();
        kdf256!(&mut new_seed, &seed, &[1u8]);

        Ok((
            new_seed,
            Self {
                encapsulation,
                encrypted_metadata,
            },
        ))
    }

    /// Decrypts the header with the given user secret key.
    ///
    /// - `cover_crypt`         : `Covercrypt` object
    /// - `usk`                 : `Covercrypt` user secret key
    /// - `authentication_data` : authentication data used in the DEM encryption
    pub fn decrypt(
        &self,
        cover_crypt: &Covercrypt,
        usk: &UserSecretKey,
        authentication_data: Option<&[u8]>,
    ) -> Result<Option<CleartextHeader>, Error> {
        cover_crypt
            .decaps(usk, &self.encapsulation)?
            .map(|seed| {
                let metadata = self
                    .encrypted_metadata
                    .as_ref()
                    .map(|ctx| {
                        let mut key = SymmetricKey::<{ Aes256Gcm::KEY_LENGTH }>::default();
                        kdf256!(&mut key, &seed, &[0u8]);
                        let mut rng = cover_crypt.rng();
                        let nonce = Nonce::<{ Aes256Gcm::NONCE_LENGTH }>::new(&mut *rng);
                        let aes = Aes256Gcm::new(&key);
                        aes.decrypt(&nonce, ctx, authentication_data)
                    })
                    .transpose()?;

                let mut new_seed = Secret::<SEED_LENGTH>::default();
                kdf256!(&mut new_seed, &seed, &[1u8]);

                Ok(CleartextHeader {
                    seed: new_seed,
                    metadata,
                })
            })
            .transpose()
    }
}

/// Structure containing all data encrypted in an `EncryptedHeader`.
///
/// - `symmetric_key`   : DEM key
/// - `metadata`        : additional data symmetrically encrypted in a header
#[derive(Debug, PartialEq, Eq)]
pub struct CleartextHeader {
    pub seed: Secret<SEED_LENGTH>,
    pub metadata: Option<Vec<u8>>,
}
