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
    /// Sets the MPK coordinates to the one defined by the policy:
    /// - removes coordinates from the MSK that don't belong to the new policy
    /// along with their associated keys;
    /// - adds the policy coordinates that don't belong yet to the MSK,
    /// generating new keys.
    ///
    ///  - `msk`    : master secret key
    ///  - `mpk`    : master public key
    pub fn update_master_keys(
        &self,
        msk: &mut MasterSecretKey,
    ) -> Result<MasterPublicKey, Error> {
        update_coordinate_keys(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            mpk,
            msk.policy.generate_all_partitions()?,
        )
    }

    /// Generate new keys associated to the given access policy in the master
    /// keys. User keys will need to be refreshed after this step.
    ///  - `access_policy`  : describe the keys to renew
    ///  - `msk`            : master secret key
    ///  - `mpk`            : master public key
    pub fn rekey_master_keys(
        &self,
        access_policy: &AccessPolicy,
        msk: &mut MasterSecretKey,
    ) -> Result<MasterPublicKey, Error> {
        rekey(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            mpk,
            mpk.policy.access_policy_to_partitions(access_policy, false)?,
        )
    }

    /// Removes old keys associated to the given master keys from the master
    /// keys. This will permanently remove access to old ciphers.
    ///  - `access_policy`  : describe the keys to prune
    ///  - `msk`            : master secret key
    pub fn prune_master_secret_key(
        &self,
        access_policy: &AccessPolicy,
        msk: &mut MasterSecretKey,
    ) -> Result<MasterPublicKey, Error> {
        prune(
            msk,
            &msk.policy.access_policy_to_partitions(access_policy, false)?,
        )
    }

    /// Generates a USK associated to the given access policy.
    ///
    /// A new user secret key only has the latest keys corresponding to its
    /// access policy.
    ///
    /// - `msk`           : master secret key
    /// - `access_policy` : user access policy
    pub fn generate_user_secret_key(
        &self,
        msk: &mut MasterSecretKey,
        access_policy: &AccessPolicy,
    ) -> Result<UserSecretKey, Error> {
        usk_keygen(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            &msk.policy.access_policy_to_partitions(access_policy, true)?,
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
}

pub trait CovercryptKEM {
    /// Generates an encapsulation for the given access
    /// policy.
    ///
    /// - `pk`                  : public key
    /// - `encryption_policy`   : encryption policy used for the encapsulation
    pub fn encaps(
        &self,
        pk: &MasterPublicKey,
        access_policy: &AccessPolicy,
    ) -> Result<(SymmetricKey<SYM_KEY_LENGTH>, Encapsulation), Error> {
        encaps(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            pk,
            &pk.policy.access_policy_to_partitions(access_policy, false)?,
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
    /// - `cover_crypt`         : `Covercrypt` object
    /// - `public_key`          : `Covercrypt` public key
    /// - `encryption_policy`   : access policy used for the encapsulation
    /// - `header_metadata`     : additional data symmetrically encrypted in the
    ///   header
    /// - `authentication_data` : authentication data used in the DEM encryption
    pub fn generate(
        cover_crypt: &Covercrypt,
        public_key: &MasterPublicKey,
        encryption_policy: &AccessPolicy,
        metadata: Option<&[u8]>,
        authentication_data: Option<&[u8]>,
    ) -> Result<(SymmetricKey<SYM_KEY_LENGTH>, Self), Error> {
        let (symmetric_key, encapsulation) =
            cover_crypt.encaps(public_key, encryption_policy)?;

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