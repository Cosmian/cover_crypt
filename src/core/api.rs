//! Defines the `Covercrypt` API.

use std::{collections::HashMap, fmt::Debug, sync::Mutex};

use cosmian_crypto_core::{
    reexport::rand_core::SeedableRng, Aes256Gcm, CsRng, Dem, FixedSizeCBytes, Instantiable, Nonce,
    RandomFixedSizeCBytes, SymmetricKey,
};

use super::{
    primitives::{mpk_keygen, prune, update_coordinate_keys, usk_keygen},
    MIN_TRACING_LEVEL,
};
use crate::{
    abe_policy::{AccessPolicy, AttributeStatus, Coordinate, EncryptionHint, Policy},
    core::{
        primitives::{decaps, encaps, refresh, rekey, setup},
        Encapsulation, MasterPublicKey, MasterSecretKey, UserSecretKey, SEED_LENGTH,
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
    /// Sets up the Covercrypt scheme.
    ///
    /// Generates a MSK and a MPK with a tracing level of [`MIN_TRACING_LEVEL`](core::MIN_TRACING_LEVEL).
    /// They only hold keys for the origin coordinate: only broadcast
    /// encapsulations can be created.
    pub fn setup(&self) -> Result<(MasterSecretKey, MasterPublicKey), Error> {
        let mut msk = setup(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            MIN_TRACING_LEVEL,
        )?;

        // Add broadcast coordinate with classic encryption level.
        //
        // TODO replace this function by `add_coordinates`,
        // `remove_coordinates`, `hybridize_coordinates` and
        // `deprecate_coordinates`.
        update_coordinate_keys(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            &mut msk,
            HashMap::from_iter([(
                Coordinate::from_attribute_ids(vec![])?,
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            )]),
        )?;
        let mpk = mpk_keygen(&msk)?;

        Ok((msk, mpk))
    }

    /// Updates the MSK according to this policy. Returns the new version of the
    /// MPK.
    ///
    /// Sets the MPK coordinates to the one defined by the policy:
    /// - removes coordinates from the MSK that don't belong to the new policy
    /// along with their associated keys;
    /// - adds the policy coordinates that don't belong yet to the MSK,
    /// generating new keys.
    ///
    /// The new MPK holds the latest public keys of each coordinates of the new policy.
    pub fn update_master_keys(
        &self,
        policy: &Policy,
        msk: &mut MasterSecretKey,
    ) -> Result<MasterPublicKey, Error> {
        update_coordinate_keys(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            policy.generate_universal_coordinates()?,
        )?;
        let mpk = mpk_keygen(msk)?;
        Ok(mpk)
    }

    /// Generates new keys for each coordinate in the semantic space of the
    /// given access policy and update the given master keys.
    ///
    /// All user keys need to be refreshed.
    // TODO document error cases.
    pub fn rekey(
        &self,
        ap: &AccessPolicy,
        policy: &Policy,
        msk: &mut MasterSecretKey,
    ) -> Result<MasterPublicKey, Error> {
        rekey(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            policy.generate_semantic_space_coordinates(ap.clone())?,
        )?;
        let mpk = mpk_keygen(msk)?;
        Ok(mpk)
    }

    /// Removes all but the latest secret of each coordinate in the semantic
    /// space of the given access policy from the given master keys.
    ///
    /// This action is *irreversible*, and all user keys need to be refreshed.
    // TODO document error cases.
    pub fn prune_master_secret_key(
        &self,
        access_policy: &AccessPolicy,
        policy: &Policy,
        msk: &mut MasterSecretKey,
    ) -> Result<MasterPublicKey, Error> {
        prune(
            msk,
            &policy.generate_semantic_space_coordinates(access_policy.clone())?,
        );
        let mpk = mpk_keygen(msk)?;
        Ok(mpk)
    }

    /// Generates a USK associated to the given access policy.
    ///
    /// It will be given the latest secret of each coordinate in the semantic
    /// space of its access policy.
    // TODO document error cases.
    pub fn generate_user_secret_key(
        &self,
        msk: &mut MasterSecretKey,
        access_policy: &AccessPolicy,
        policy: &Policy,
    ) -> Result<UserSecretKey, Error> {
        usk_keygen(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            policy.generate_semantic_space_coordinates(access_policy.clone())?,
        )
    }

    /// Refreshes the USK relatively to the given MSK and policy.
    ///
    /// The USK will be given the latest secrets of each coordinate in the
    /// semantic space of its access policy and secrets that have been removed
    /// from the MSK will be removed. If `keep_old_rights` is set to false, only
    /// the latest secret of each coordinate is kept instead.
    ///
    /// Updates the tracing level to match the one of the MSK if needed.
    // TODO document error cases.
    pub fn refresh_usk(
        &self,
        usk: &mut UserSecretKey,
        msk: &mut MasterSecretKey,
        keep_old_rights: bool,
    ) -> Result<(), Error> {
        refresh(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            usk,
            keep_old_rights,
        )
    }

    /// Generates a random symmetric key to be used with a DEM scheme and
    /// generates its encapsulation for the given access policy.
    // TODO document error cases.
    pub fn encaps(
        &self,
        policy: &Policy,
        pk: &MasterPublicKey,
        access_policy: AccessPolicy,
    ) -> Result<(SymmetricKey<SEED_LENGTH>, Encapsulation), Error> {
        encaps(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            pk,
            &policy.generate_point_coordinates(access_policy)?,
        )
    }

    /// Attempts opening the given `Covercrypt` encapsulation. Returns the
    /// encapsulated key upon success and `None` otherwise.
    // TODO document error cases.
    pub fn decaps(
        &self,
        usk: &UserSecretKey,
        encapsulation: &Encapsulation,
    ) -> Result<Option<SymmetricKey<SEED_LENGTH>>, Error> {
        decaps(usk, encapsulation)
    }

    /// Encrypts the given plaintext using the given symmetric key.
    ///
    /// The encryption scheme used is AES-256 GCM.
    ///
    /// - `symmetric_key`   : AES key
    /// - `plaintext`       : data to be encrypted
    /// - `ad`              : optional associated data
    pub fn dem_encrypt(
        &self,
        symmetric_key: &SymmetricKey<SEED_LENGTH>,
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
    pub fn dem_decrypt(
        &self,
        symmetric_key: &SymmetricKey<SEED_LENGTH>,
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
    ) -> Result<(SymmetricKey<SEED_LENGTH>, Self), Error> {
        let (symmetric_key, encapsulation) =
            cover_crypt.encaps(policy, public_key, encryption_policy.clone())?;

        let encrypted_metadata = metadata
            .map(|bytes| cover_crypt.dem_encrypt(&symmetric_key, bytes, authentication_data))
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
    ) -> Result<Option<CleartextHeader>, Error> {
        if let Some(symmetric_key) = cover_crypt.decaps(usk, &self.encapsulation)? {
            let metadata = self
                .encrypted_metadata
                .as_ref()
                .map(|ciphertext| {
                    cover_crypt.dem_decrypt(&symmetric_key, ciphertext, authentication_data)
                })
                .transpose()?;
            Ok(Some(CleartextHeader {
                symmetric_key,
                metadata,
            }))
        } else {
            Ok(None)
        }
    }
}

/// Structure containing all data encrypted in an `EncryptedHeader`.
///
/// - `symmetric_key`   : DEM key
/// - `metadata`        : additional data symmetrically encrypted in a header
#[derive(Debug, PartialEq, Eq)]
pub struct CleartextHeader {
    pub symmetric_key: SymmetricKey<SEED_LENGTH>,
    pub metadata: Option<Vec<u8>>,
}


pub trait CovercryptKEM {
    /// Sets up the Covercrypt scheme.
    ///
    /// Generates a MSK and a MPK with a tracing level of
    /// [`MIN_TRACING_LEVEL`](core::MIN_TRACING_LEVEL).
    /// They only hold keys for the origin coordinate: only broadcast
    /// encapsulations can be created.
    fn setup () ->
        (MasterSecretKey,MasterPublicKey);
    /// Generate a user secret key with the given rights.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is not valid.
    fn keygen (msk : &MasterSecretKey,
               ap : &str) ->
        Result<UserSecretKey,Error>;
    /// Generates an encapsulation for the given access
    /// policy.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is not valid.
    fn encaps<const LENGTH : usize> (mpk : &MasterPublicKey,
                                     ap : &str) ->
        Result<(SymmetricKey<LENGTH>,Encapsulation), Error>;
    /// Attempts opening the given encapsulation using the given
    /// user secret key.
    ///
    /// Returns the encapsulated symmetric key if the user key holds
    /// the correct rights.
    fn decaps<const LENGTH : usize> (usk : &UserSecretKey,
                                     enc : Encapsulation) ->
        Option<SymmetricKey<LENGTH>>;


}

pub trait CovercryptPKE<const LENGTH : usize, Dem> {
    fn encrypt (mpk : &MasterPublicKey,
                ap : &AccessPolicy,
                ad : &[u8],
                ptx : &[u8]) ->
        Result<Vec<u8>,Error>;
    
    fn decrypt (usk : &UserSecretKey,
                ad : &[u8],
                ctx : &[u8]) ->
        Result<Vec<u8>,Error>;

}

// TODO : 1) Implement CCKEM and test it.
//        2) Implement CCPKE and test it.
//        remarks : 1) CCPKE contains CCKEM.
//                  2) Interface opaque to client. Only access to functions.
