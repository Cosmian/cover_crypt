//! Defines the `Covercrypt` API.

use std::{collections::HashMap, marker::PhantomData, str::FromStr, sync::Mutex};

use cosmian_crypto_core::{
    bytes_ser_de::Serializable,
    kdf256,
    reexport::{
        rand_core::{CryptoRngCore, SeedableRng},
    },
    Aes256Gcm, CsRng, Dem, FixedSizeCBytes, Instantiable, Nonce, RandomFixedSizeCBytes, Secret,
    SymmetricKey,
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
    /// Generates a MSK and a MPK with a tracing level of
    /// [`MIN_TRACING_LEVEL`](core::MIN_TRACING_LEVEL).
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

    /// Generate a user secret key with the given rights.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is not valid.
    pub fn keygen(
        &self,
        msk: &mut MasterSecretKey,
        policy: &Policy,
        ap: &str,
    ) -> Result<UserSecretKey, Error> {
        let ap = &AccessPolicy::parse(ap)?;
        usk_keygen(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            policy.generate_semantic_space_coordinates(ap.clone())?,
        )
    }
}

/// Authenticated Encryption trait
pub trait AE<const KEY_LENGTH: usize, const NONCE_LENGTH: usize, const MAC_LENGTH: usize> {
    fn encrypt(
        key: &SymmetricKey<KEY_LENGTH>,
        ptx: &[u8],
        ad: Option<&[u8]>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, Error>;

    fn decrypt(key: &Secret<KEY_LENGTH>, ctx: &[u8], ad: Option<&[u8]>) -> Result<Vec<u8>, Error>;
}

impl AE<{ Self::KEY_LENGTH }, { Self::NONCE_LENGTH }, { Self::MAC_LENGTH }> for Aes256Gcm {
    fn encrypt(
        key: &SymmetricKey<{ Self::KEY_LENGTH }>,
        ptx: &[u8],
        ad: Option<&[u8]>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let nonce = &self::Nonce::<{ Self::NONCE_LENGTH }>::new(&mut *rng);
        let aes = Self::new(key);
        let mut ciphertext = aes
            .encrypt(nonce, ptx, ad)
            .map_err(Error::CryptoCoreError)?;
        let mut res = Vec::with_capacity(ptx.len() + Self::MAC_LENGTH + Self::NONCE_LENGTH);
        res.extend(&Nonce::to_bytes(nonce));
        res.append(&mut ciphertext);
        Ok(res)
    }

    fn decrypt(
        key: &Secret<{ Self::KEY_LENGTH }>,
        ctx: &[u8],
        ad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        if ctx.len() < Self::NONCE_LENGTH {
            return Err(Error::CryptoCoreError(
                cosmian_crypto_core::CryptoCoreError::DecryptionError,
            ));
        }
        let sym_key = SymmetricKey::try_from_slice(key)?;
        let nonce =
            &Nonce::<{ Self::NONCE_LENGTH }>::try_from_slice(&ctx[..{ Self::NONCE_LENGTH }])?;
        let aes = Self::new(&sym_key);
        aes.decrypt(nonce, &ctx[{ Self::NONCE_LENGTH }..], ad)
            .map_err(Error::CryptoCoreError)
    }
}

/// Encrypted header holding a `Covercrypt` encapsulation of a 256-bit seed and
/// metadata encrypted under the scheme `E` using a key derived from the
/// encapsulated seed.
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedHeader<E> {
    pub encapsulation: Encapsulation,
    pub encrypted_metadata: Option<Vec<u8>>,
    pub phantom: PhantomData<E>,
}

pub trait EncryptedHeaderEnc<
    Aead,
    const KEY_LENGTH: usize,
    const NONCE_LENGTH: usize,
    const MAC_LENGTH: usize,
>
{
    fn generate(
        cover_crypt: &Covercrypt,
        policy: &Policy,
        public_key: &MasterPublicKey,
        encryption_policy: &str,
        metadata: Option<&[u8]>,
        authentication_data: Option<&[u8]>,
    ) -> Result<(Secret<SEED_LENGTH>, EncryptedHeader<Aead>), Error>;

    fn decrypt(
        &self,
        cover_crypt: &Covercrypt,
        usk: &UserSecretKey,
        authentication_data: Option<&[u8]>,
    ) -> Result<Option<CleartextHeader>, Error>;
}

impl<
        const KEY_LENGTH: usize,
        const NONCE_LENGTH: usize,
        const MAC_LENGTH: usize,
        E: AE<KEY_LENGTH, NONCE_LENGTH, MAC_LENGTH>,
    > EncryptedHeaderEnc<E, KEY_LENGTH, NONCE_LENGTH, MAC_LENGTH> for EncryptedHeader<E>
{
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
    fn generate(
        cover_crypt: &Covercrypt,
        policy: &Policy,
        public_key: &MasterPublicKey,
        encryption_policy: &str,
        metadata: Option<&[u8]>,
        authentication_data: Option<&[u8]>,
    ) -> Result<(Secret<SEED_LENGTH>, Self), Error> {
        let (seed, encapsulation) =
            CovercryptKEM::encaps(cover_crypt, public_key, policy, encryption_policy)?;
        let encrypted_metadata = metadata
            .map(|bytes| {
                let mut sym_key = SymmetricKey::<KEY_LENGTH>::default();
                kdf256!(&mut sym_key, &seed, &[0u8]);
                let mut rng = cover_crypt.rng.lock().expect("poisoned lock");
                E::encrypt(&sym_key, bytes, authentication_data, &mut *rng)
            })
            .transpose()?;
        let mut new_seed = Secret::<SEED_LENGTH>::default();
        // Generating a new seed adding a variant component 1, to prevent reusing
        // seed used for the metadata encryption.
        kdf256!(&mut new_seed, &seed, &[1u8]);
        Ok((
            new_seed,
            Self {
                encapsulation,
                encrypted_metadata,
                phantom: PhantomData,
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
    fn decrypt(
        &self,
        cover_crypt: &Covercrypt,
        usk: &UserSecretKey,
        authentication_data: Option<&[u8]>,
    ) -> Result<Option<CleartextHeader>, Error> {
        CovercryptKEM::decaps(cover_crypt, usk, self.encapsulation.clone()).map(|seed| {
            if let Some(mut seed) = seed {
                let metadata = self
                    .encrypted_metadata
                    .as_ref()
                    .map(|ctx| {
                        let mut key = Secret::<KEY_LENGTH>::default();
                        kdf256!(&mut key, &seed, &[0u8]);
                        E::decrypt(&key, ctx, authentication_data)
                    })
                    .transpose()?;
                kdf256!(&mut seed, &seed, &[1u8]);
                Ok(Some(CleartextHeader { seed, metadata }))
            } else {
                Ok(None)
            }
        })?
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

pub trait CovercryptKEM {
    /// Generates an encapsulation for the given access
    /// policy.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is not valid.
    fn encaps(
        &self,
        mpk: &MasterPublicKey,
        policy: &Policy,
        ap: &str,
    ) -> Result<(Secret<SEED_LENGTH>, Encapsulation), Error>; // todo : symmetric_key or seed?

    /// Attempts opening the given encapsulation using the given
    /// user secret key.
    ///
    /// Returns the encapsulated symmetric key if the user key holds
    /// the correct rights.
    fn decaps(
        &self,
        usk: &UserSecretKey,
        enc: Encapsulation,
    ) -> Result<Option<Secret<SEED_LENGTH>>, Error>;
}

impl CovercryptKEM for Covercrypt {
    /// Generates an encapsulation for the given access
    /// policy.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is not valid.
    fn encaps(
        &self,
        mpk: &MasterPublicKey,
        policy: &Policy,
        ap: &str,
    ) -> Result<(Secret<SEED_LENGTH>, Encapsulation), Error> {
        let ap = &AccessPolicy::parse(ap)?;
        encaps(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            mpk,
            &policy.generate_point_coordinates(ap.clone())?,
        )
    }
    /// Attempts opening the given encapsulation using the given
    /// user secret key.
    ///
    /// Returns the encapsulated symmetric key if the user key holds
    /// the correct rights.
    fn decaps(
        &self,
        usk: &UserSecretKey,
        encapsulation: Encapsulation,
    ) -> Result<Option<Secret<SEED_LENGTH>>, Error> {
        decaps(usk, &encapsulation)
    }
}

pub trait CovercryptPKE<
    Aead,
    const KEY_LENGTH: usize,
    const NONCE_LENGTH: usize,
    const MAC_LENGTH: usize,
>
{
    /// Encrypts the given plaintext using Covercrypt and the given DEM.
    ///
    /// Creates a Covercrypt encapsulation of a LENGTH-byte key, and use this
    /// key with the given authentication data to produce a DEM ciphertext of
    /// the plaintext.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is not valid.
    fn encrypt(
        &self,
        mpk: &MasterPublicKey,
        policy: &Policy,
        ap: &str,
        ad: Option<&[u8]>,
        plaintext: &[u8],
    ) -> Result<(Encapsulation, Vec<u8>), Error>;

    /// Attempts decrypting the given ciphertext using the Covercrypt KEM and the DEM.
    ///
    /// Attempts opening the Covercrypt encapsulation. If it succeeds, decrypts
    /// the ciphertext using the DEM with the encapsulated key and the given
    /// authentication data. Returns ‘None‘ otherwise.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is not valid.
    fn decrypt(
        &self,
        usk: &UserSecretKey,
        ad: Option<&[u8]>,
        cyphertext: &[u8],
        enc: &Encapsulation,
    ) -> Result<Option<Vec<u8>>, Error>;
}

impl<
        const KEY_LENGTH: usize,
        const NONCE_LENGTH: usize,
        const MAC_LENGTH: usize,
        E: AE<KEY_LENGTH, NONCE_LENGTH, MAC_LENGTH>,
    > CovercryptPKE<E, KEY_LENGTH, NONCE_LENGTH, MAC_LENGTH> for Covercrypt
{
    /// Encrypts the given plaintext using Covercrypt and the given DEM.
    ///
    /// Creates a Covercrypt encapsulation of a LENGTH-byte key, and use this
    /// key with the given authentication data to produce a DEM ciphertext of
    /// the plaintext.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is not valid.
    fn encrypt(
        &self,
        mpk: &MasterPublicKey,
        policy: &Policy,
        ap: &str,
        ad: Option<&[u8]>,
        plaintext: &[u8],
    ) -> Result<(Encapsulation, Vec<u8>), Error> {
        let (seed, enc) = CovercryptKEM::encaps(self, mpk, policy, ap)?;
        if seed.length() < KEY_LENGTH {
            return Err(Error::KeyError(
                String::from_str("SEED_LENGTH >= KEY_LENGTH").unwrap(),
            ));
        }
        let sym_key = SymmetricKey::<KEY_LENGTH>::try_from_slice(&seed[..KEY_LENGTH])?;
        let mut rng = self.rng.lock().expect("poisoned lock");
        let res = E::encrypt(&sym_key, plaintext, ad, &mut *rng)?;
        Ok((enc, res))
    }

    /// Attempts decrypting the given ciphertext using the Covercrypt KEM and the DEM.
    ///
    /// Attempts opening the Covercrypt encapsulation. If it succeeds, decrypts
    /// the ciphertext using the DEM with the encapsulated key and the given
    /// authentication data. Returns ‘None‘ otherwise.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is not valid.
    fn decrypt(
        &self,
        usk: &UserSecretKey,
        ad: Option<&[u8]>,
        ciphertext: &[u8],
        enc: &Encapsulation,
    ) -> Result<Option<Vec<u8>>, Error> {
        let seed = CovercryptKEM::decaps(self, usk, enc.clone())?;
        seed.map(|seed| {
            let mut sym_key = Secret::<KEY_LENGTH>::default();
            kdf256!(&mut sym_key, &seed);
            E::decrypt(&sym_key, ciphertext, ad)
        })
        .transpose()
    }
}
