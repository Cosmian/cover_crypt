use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};

use cosmian_crypto_core::{kdf256, reexport::rand_core::SeedableRng, CsRng, Secret, SymmetricKey};
use zeroize::Zeroizing;

use super::{
    ae::AE,
    primitives::{prune, update_coordinate_keys, usk_keygen},
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
    pub fn rng(&self) -> MutexGuard<CsRng> {
        self.rng.lock().expect("poisoned mutex")
    }
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
        let mpk = msk.mpk()?;

        Ok((msk, mpk))
    }

    /// Updates the MSK according to this policy. Returns the new version of the
    /// MPK.
    ///
    /// When a coordinate exists in the new policy but not in the master keys,
    /// a new key pair is added to the master keys for that coordinate.
    /// When a coordinate exists on the master keys, but not in the new policy,
    /// it is removed from the master keys.
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
        msk.mpk()
    }

    /// Generates new keys for each coordinate in the semantic space of the
    /// given access policy and update the given master keys.
    ///
    /// All user keys need to be refreshed.
    ///
    ///  - `ap`  : describe the keys to renew
    ///  - `policy`         : global policy
    ///  - `msk`            : master secret key
    ///  - `mpk`            : master public key
    pub fn rekey_master_keys(
        &self,
        ap: &AccessPolicy,
        policy: &Policy,
        msk: &mut MasterSecretKey,
    ) -> Result<MasterPublicKey, Error> {
        rekey(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            policy.generate_semantic_space_coordinates(ap)?,
        )?;
        msk.mpk()
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
            &policy.generate_semantic_space_coordinates(access_policy)?,
        );
        msk.mpk()
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
            policy.generate_semantic_space_coordinates(access_policy)?,
        )
    }

    /// Refreshes the USK relatively to the given MSK and policy.
    ///
    /// The user key will be granted access to the current coordinates, as
    /// determined by its access policy. If `preserve_old_coordinates_access`
    /// is set, the old user access will be preserved.
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
        ap: &AccessPolicy,
    ) -> Result<(Secret<SEED_LENGTH>, Encapsulation), Error>;

    /// Attempts opening the given encapsulation using the given
    /// user secret key.
    ///
    /// Returns the encapsulated symmetric key if the user key holds
    /// the correct rights.
    fn decaps(
        &self,
        usk: &UserSecretKey,
        enc: &Encapsulation,
    ) -> Result<Option<Secret<SEED_LENGTH>>, Error>;
}

impl CovercryptKEM for Covercrypt {
    fn encaps(
        &self,
        mpk: &MasterPublicKey,
        policy: &Policy,
        ap: &AccessPolicy,
    ) -> Result<(Secret<SEED_LENGTH>, Encapsulation), Error> {
        encaps(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            mpk,
            &policy.generate_point_coordinates(ap)?,
        )
    }

    fn decaps(
        &self,
        usk: &UserSecretKey,
        encapsulation: &Encapsulation,
    ) -> Result<Option<Secret<SEED_LENGTH>>, Error> {
        decaps(usk, encapsulation)
    }
}

pub trait CovercryptPKE<Aead, const KEY_LENGTH: usize> {
    /// Encrypts the given plaintext using Covercrypt and the given DEM.
    ///
    /// Creates a Covercrypt encapsulation of a 256-bit seed, and use it with
    /// the given authentication data to encrypt the plaintext.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is not valid.
    fn encrypt(
        &self,
        mpk: &MasterPublicKey,
        policy: &Policy,
        ap: &AccessPolicy,
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
        ciphertext: &[u8],
        enc: &Encapsulation,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error>;
}

impl<const KEY_LENGTH: usize, E: AE<KEY_LENGTH>> CovercryptPKE<E, KEY_LENGTH> for Covercrypt {
    fn encrypt(
        &self,
        mpk: &MasterPublicKey,
        policy: &Policy,
        ap: &AccessPolicy,
        plaintext: &[u8],
    ) -> Result<(Encapsulation, Vec<u8>), Error> {
        if SEED_LENGTH < KEY_LENGTH {
            return Err(Error::ConversionFailed(format!(
                "insufficient entropy to generate a {}-byte key from a {}-byte seed",
                KEY_LENGTH, SEED_LENGTH
            )));
        }
        let (seed, enc) = self.encaps(mpk, policy, ap)?;
        let mut sym_key = SymmetricKey::default();
        kdf256!(&mut sym_key, &seed);
        let mut rng = self.rng.lock().expect("poisoned lock");
        let res = E::encrypt(&mut *rng, &sym_key, plaintext)?;
        Ok((enc, res))
    }

    fn decrypt(
        &self,
        usk: &UserSecretKey,
        ciphertext: &[u8],
        enc: &Encapsulation,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        if SEED_LENGTH < KEY_LENGTH {
            return Err(Error::ConversionFailed(format!(
                "insufficient entropy to generate a {}-byte key from a {}-byte seed",
                KEY_LENGTH, SEED_LENGTH
            )));
        }
        let seed = self.decaps(usk, enc)?;
        seed.map(|seed| {
            let mut sym_key = SymmetricKey::<KEY_LENGTH>::default();
            kdf256!(&mut sym_key, &seed);
            E::decrypt(&sym_key, ciphertext)
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
    pub symmetric_key: SymmetricKey<SYM_KEY_LENGTH>,
    pub metadata: Option<Vec<u8>>,
}
