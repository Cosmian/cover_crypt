//! Defines the `Covercrypt` API.

use std::{fmt::Debug, sync::Mutex};

use cosmian_crypto_core::{
    reexport::rand_core::SeedableRng, Aes256Gcm, CsRng, Dem, FixedSizeCBytes, Instantiable, Nonce,
    RandomFixedSizeCBytes, SymmetricKey,
};

use crate::{
    abe_policy::{AccessPolicy, Policy},
    core::{
        primitives::{decaps, encaps, keygen, refresh, setup, update},
        Encapsulation, MasterPublicKey, MasterSecretKey, UserSecretKey, SYM_KEY_LENGTH,
    },
    Error,
};

/// Instantiate a `Covercrypt` type with AES GCM 256 as DEM
#[derive(Debug)]
pub struct Covercrypt {
    rng: Mutex<CsRng>,
}

impl Default for Covercrypt {
    fn default() -> Self {
        Self {
            rng: Mutex::new(CsRng::from_entropy()),
        }
    }
}

impl PartialEq for Covercrypt {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Covercrypt {
    /// Generates the master authority keys for supplied Policy
    ///
    ///  - `policy` : Policy to use to generate the keys
    pub fn generate_master_keys(
        &self,
        policy: &Policy,
    ) -> Result<(MasterSecretKey, MasterPublicKey), Error> {
        Ok(setup(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            &policy.generate_all_partitions()?,
        ))
    }

    /// Updates the master keys according to this new policy.
    ///
    /// When a partition exists in the new policy but not in the master keys,
    /// a new key pair is added to the master keys for that partition.
    /// When a partition exists on the master keys, but not in the new policy,
    /// it is removed from the master keys.
    ///
    ///  - `policy` : Policy to use to generate the keys
    ///  - `msk`    : master secret key
    ///  - `mpk`    : master public key
    pub fn update_master_keys(
        &self,
        policy: &Policy,
        msk: &mut MasterSecretKey,
        mpk: &mut MasterPublicKey,
    ) -> Result<(), Error> {
        update(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            mpk,
            &policy.generate_all_partitions()?,
        )
    }

    /// Generates a user secret key.
    ///
    /// A new user secret key does NOT include to old (i.e. rotated) partitions.
    ///
    /// - `msk`         : master secret key
    /// - `user_policy` : user access policy
    /// - `policy`      : global policy
    pub fn generate_user_secret_key(
        &self,
        msk: &MasterSecretKey,
        access_policy: &AccessPolicy,
        policy: &Policy,
    ) -> Result<UserSecretKey, Error> {
        Ok(keygen(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            &policy.access_policy_to_current_partitions(access_policy, true)?,
        ))
    }

    /// Refreshes the user key according to the given master key and user
    /// policy.
    ///
    /// The user key will be granted access to the current partitions, as
    /// determined by its access policy. If `preserve_old_partitions_access`
    /// is set, the old user access will be preserved.
    ///
    /// - `usk`                 : the user key to refresh
    /// - `user_policy`         : the access policy of the user key
    /// - `msk`                 : master secret key
    /// - `policy`              : global policy of the master secret key
    /// - `keep_old_accesses`   : whether access to old partitions (i.e. before
    ///   rotation) should be kept
    pub fn refresh_user_secret_key(
        &self,
        usk: &mut UserSecretKey,
        access_policy: &AccessPolicy,
        msk: &MasterSecretKey,
        policy: &Policy,
        keep_old_accesses: bool,
    ) -> Result<(), Error> {
        refresh(
            msk,
            usk,
            &policy.access_policy_to_current_partitions(access_policy, true)?,
            keep_old_accesses,
        )
    }

    /// Generates a random symmetric key to be used with a DEM scheme and
    /// generates its `Covercrypt` encapsulation for the given policy
    /// `attributes`.
    ///
    /// - `policy`              : global policy
    /// - `pk`                  : public key
    /// - `encryption_policy`   : encryption policy used for the encapsulation
    pub fn encaps(
        &self,
        policy: &Policy,
        pk: &MasterPublicKey,
        access_policy: &AccessPolicy,
    ) -> Result<(SymmetricKey<SYM_KEY_LENGTH>, Encapsulation), Error> {
        encaps(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            pk,
            &policy.access_policy_to_current_partitions(access_policy, false)?,
        )
    }

    /// Decapsulates a symmetric key from the given `Covercrypt` encapsulation.
    /// This returns multiple key candidates. The use of an authenticated DEM
    /// scheme allows to select valid ones.
    ///
    /// - `sk_u`            : user secret key
    /// - `encapsulation`   : encrypted symmetric key
    pub fn decaps(
        &self,
        usk: &UserSecretKey,
        encapsulation: &Encapsulation,
    ) -> Result<SymmetricKey<SYM_KEY_LENGTH>, Error> {
        decaps(usk, encapsulation)
    }

    /// Encrypts the given plaintext using the given symmetric key.
    ///
    /// The encryption scheme used is AES-256 GCM.
    ///
    /// - `symmetric_key`   : AES key
    /// - `plaintext`       : data to be encrypted
    /// - `ad`              : optional associated data
    pub fn encrypt(
        &self,
        symmetric_key: &SymmetricKey<SYM_KEY_LENGTH>,
        plaintext: &[u8],
        ad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let aes256gcm = Aes256Gcm::new(symmetric_key);
        let nonce = Nonce::new(&mut *self.rng.lock().expect("could not lock mutex"));
        let mut ciphertext = aes256gcm.encrypt(&nonce, plaintext, ad)?;
        let mut res =
            Vec::with_capacity(plaintext.len() + Aes256Gcm::MAC_LENGTH + Aes256Gcm::NONCE_LENGTH);
        res.extend(nonce.0);
        res.append(&mut ciphertext);
        Ok(res)
    }

    /// Decrypts the given ciphertext using the given symmetric key.
    ///
    /// The encryption scheme used is AES-256 GCM.
    ///
    /// - `symmetric_key`   : AES key
    /// - `ciphertext`      : encrypted data
    /// - `ad`              : associated data
    pub fn decrypt(
        &self,
        symmetric_key: &SymmetricKey<SYM_KEY_LENGTH>,
        ciphertext: &[u8],
        ad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let aes256gcm = Aes256Gcm::new(symmetric_key);
        aes256gcm
            .decrypt(
                &Nonce::try_from_slice(&ciphertext[..Aes256Gcm::NONCE_LENGTH])?,
                &ciphertext[Aes256Gcm::NONCE_LENGTH..],
                ad,
            )
            .map_err(Error::CryptoCoreError)
    }
}

/// Encrypted header holding a `Covercrypt` encapsulation of a symmetric key and
/// additional data encrypted using the `Covercrypt` DEM with the encapsulated
/// key.
///
/// *Note*: the DEM ciphertext is also used to select the correct symmetric key
/// from the decapsulation.
///
/// - `encapsulation`       :   `Covercrypt` encapsulation of a symmetric key
/// - `encrypted_metadata`  :   AES-256 GCM encryption of the metadata
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedHeader {
    pub encapsulation: Encapsulation,
    pub encrypted_metadata: Option<Vec<u8>>,
}

impl EncryptedHeader {
    /// Generates an encrypted header for a random key and the given metadata.
    /// Returns the encrypted header along with the symmetric key
    /// encapsulated in this header.
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
    ) -> Result<(SymmetricKey<SYM_KEY_LENGTH>, Self), Error> {
        let (symmetric_key, encapsulation) =
            cover_crypt.encaps(policy, public_key, encryption_policy)?;

        let encrypted_metadata = metadata
            .map(|bytes| cover_crypt.encrypt(&symmetric_key, bytes, authentication_data))
            .transpose()?;

        Ok((
            symmetric_key,
            Self {
                encapsulation,
                encrypted_metadata,
            },
        ))
    }

    /// Decrypts the header with the given user secret key.
    ///
    /// The nonce used is extracted from the encapsulation tag.
    ///
    /// - `cover_crypt`         : `Covercrypt` object
    /// - `usk`                 : `Covercrypt` user secret key
    /// - `authentication_data` : authentication data used in the DEM encryption
    pub fn decrypt(
        &self,
        cover_crypt: &Covercrypt,
        usk: &UserSecretKey,
        authentication_data: Option<&[u8]>,
    ) -> Result<CleartextHeader, Error> {
        let symmetric_key = cover_crypt.decaps(usk, &self.encapsulation)?;
        let metadata = self
            .encrypted_metadata
            .as_ref()
            .map(|ciphertext| cover_crypt.decrypt(&symmetric_key, ciphertext, authentication_data))
            .transpose()?;
        Ok(CleartextHeader {
            symmetric_key,
            metadata,
        })
    }
}

/// Structure containing all data encrypted in an `EncryptedHeader`.
///
/// - `symmetric_key`   : DEM key
/// - `metadata`        : additional data symmetrically encrypted in a header
#[derive(Debug, PartialEq, Eq)]
pub struct CleartextHeader {
    pub symmetric_key: SymmetricKey<SYM_KEY_LENGTH>,
    pub metadata: Option<Vec<u8>>,
}
