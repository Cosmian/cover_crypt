use cosmian_crypto_core::{
    kdf256, Aes256Gcm, Dem, Instantiable, Nonce, RandomFixedSizeCBytes, Secret, SymmetricKey,
};

use crate::{
    abe_policy::AccessPolicy,
    api::{Covercrypt, KemAc},
    core::SHARED_SECRET_LENGTH,
    Error, MasterPublicKey, UserSecretKey, XEnc,
};

/// Encrypted header holding a `Covercrypt` encapsulation of a 256-byte secret, and metadata
/// encrypted under the scheme AES256Gcm using a key derived from the encapsulated secret.
#[derive(Debug, PartialEq)]
pub struct EncryptedHeader {
    pub encapsulation: XEnc,
    pub encrypted_metadata: Option<Vec<u8>>,
}

impl EncryptedHeader {
    /// Generates a new encrypted header for a random secret and the given metadata.
    /// Returns the encrypted header along with the secret.
    ///
    /// - `cc`                  : `Covercrypt` object
    /// - `mpk`                 : `Covercrypt` public key
    /// - `ap`                  : access policy used for the encapsulation
    /// - `header_metadata`     : additional data symmetrically encrypted in the header
    /// - `authentication_data` : authentication data used in the DEM encryption
    pub fn generate(
        cc: &Covercrypt,
        mpk: &MasterPublicKey,
        ap: &AccessPolicy,
        metadata: Option<&[u8]>,
        authentication_data: Option<&[u8]>,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, Self), Error> {
        let (seed, encapsulation) = cc.encaps(mpk, ap)?;

        let encrypted_metadata = metadata
            .map(|bytes| {
                let key = SymmetricKey::derive(&seed, &[0])?;
                let nonce = Nonce::new(&mut *cc.rng());
                Aes256Gcm::new(&key).encrypt(&nonce, bytes, authentication_data)
            })
            .transpose()?;

        let mut secret = Secret::default();
        kdf256!(&mut *secret, &*seed, &[1u8]);

        Ok((
            secret,
            Self {
                encapsulation,
                encrypted_metadata,
            },
        ))
    }

    /// Decrypts the header with the given user secret key.
    ///
    /// - `cc`                  : `Covercrypt` object
    /// - `usk`                 : `Covercrypt` user secret key
    /// - `authentication_data` : authentication data used in the DEM encryption
    pub fn decrypt(
        &self,
        cc: &Covercrypt,
        usk: &UserSecretKey,
        authentication_data: Option<&[u8]>,
    ) -> Result<Option<CleartextHeader>, Error> {
        cc.decaps(usk, &self.encapsulation)?
            .map(|seed| {
                let metadata = self
                    .encrypted_metadata
                    .as_ref()
                    .map(|ctx| {
                        let key = SymmetricKey::derive(&seed, &[0])?;
                        let nonce = Nonce::<{ Aes256Gcm::NONCE_LENGTH }>::new(&mut *cc.rng());
                        Aes256Gcm::new(&key).decrypt(&nonce, ctx, authentication_data)
                    })
                    .transpose()?;

                let mut secret = Secret::<SHARED_SECRET_LENGTH>::default();
                kdf256!(&mut *secret, &*seed, &[1u8]);

                Ok(CleartextHeader { secret, metadata })
            })
            .transpose()
    }
}

/// Structure containing all data encrypted in an `EncryptedHeader`.
#[derive(Debug, PartialEq, Eq)]
pub struct CleartextHeader {
    pub secret: Secret<SHARED_SECRET_LENGTH>,
    pub metadata: Option<Vec<u8>>,
}
