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
    abe_policy::{AccessPolicy, AttributeStatus, Coordinate, EncryptionHint},
    core::{
        primitives::{decaps, encaps, refresh, rekey, setup},
        Encapsulation, MasterPublicKey, MasterSecretKey, UserSecretKey, SHARED_SECRET_LENGTH,
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
            MIN_TRACING_LEVEL,
            &mut *self.rng.lock().expect("Mutex lock failed!"),
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
    ///   along with their associated keys;
    /// - adds the policy coordinates that don't belong yet to the MSK,
    ///   generating new keys.
    ///
    /// The new MPK holds the latest public keys of each coordinates of the new policy.
    pub fn update_master_keys(&self, msk: &mut MasterSecretKey) -> Result<MasterPublicKey, Error> {
        update_coordinate_keys(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            msk.policy.generate_universal_coordinates()?,
        )?;
        msk.mpk()
    }

    /// Generates new keys for each coordinate in the semantic space of the
    /// given access policy and update the given master keys.
    ///
    /// All user keys need to be refreshed.
    // TODO document error cases.
    pub fn rekey(
        &self,
        msk: &mut MasterSecretKey,
        ap: &AccessPolicy,
    ) -> Result<MasterPublicKey, Error> {
        rekey(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            msk.policy.ap_to_usk_rights(ap)?,
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
        msk: &mut MasterSecretKey,
        ap: &AccessPolicy,
    ) -> Result<MasterPublicKey, Error> {
        prune(msk, &msk.policy.ap_to_usk_rights(ap)?);
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
        ap: &AccessPolicy,
    ) -> Result<UserSecretKey, Error> {
        usk_keygen(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            msk.policy.ap_to_usk_rights(ap)?,
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
        msk: &mut MasterSecretKey,
        usk: &mut UserSecretKey,
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
        ap: &AccessPolicy,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, Encapsulation), Error>;

    /// Attempts opening the given encapsulation using the given
    /// user secret key.
    ///
    /// Returns the encapsulated symmetric key if the user key holds
    /// the correct rights.
    fn decaps(
        &self,
        usk: &UserSecretKey,
        enc: &Encapsulation,
    ) -> Result<Option<Secret<SHARED_SECRET_LENGTH>>, Error>;
}

impl CovercryptKEM for Covercrypt {
    fn encaps(
        &self,
        mpk: &MasterPublicKey,
        ap: &AccessPolicy,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, Encapsulation), Error> {
        encaps(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            mpk,
            &mpk.policy.ap_to_enc_rights(ap)?,
        )
    }

    fn decaps(
        &self,
        usk: &UserSecretKey,
        enc: &Encapsulation,
    ) -> Result<Option<Secret<SHARED_SECRET_LENGTH>>, Error> {
        decaps(usk, enc)
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
        ap: &AccessPolicy,
        ptx: &[u8],
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
        enc: &Encapsulation,
        ctx: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error>;
}

impl<const KEY_LENGTH: usize, E: AE<KEY_LENGTH>> CovercryptPKE<E, KEY_LENGTH> for Covercrypt {
    fn encrypt(
        &self,
        mpk: &MasterPublicKey,
        ap: &AccessPolicy,
        ptx: &[u8],
    ) -> Result<(Encapsulation, Vec<u8>), Error> {
        if SHARED_SECRET_LENGTH < KEY_LENGTH {
            return Err(Error::ConversionFailed(format!(
                "insufficient entropy to generate a {}-byte key from a {}-byte seed",
                KEY_LENGTH, SHARED_SECRET_LENGTH
            )));
        }
        let (seed, enc) = self.encaps(mpk, ap)?;
        let mut sym_key = SymmetricKey::default();
        kdf256!(&mut *sym_key, &*seed);
        let mut rng = self.rng.lock().expect("poisoned lock");
        let res = E::encrypt(&mut *rng, &sym_key, ptx)?;
        Ok((enc, res))
    }

    fn decrypt(
        &self,
        usk: &UserSecretKey,
        enc: &Encapsulation,
        ctx: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        if SHARED_SECRET_LENGTH < KEY_LENGTH {
            return Err(Error::ConversionFailed(format!(
                "insufficient entropy to generate a {}-byte key from a {}-byte seed",
                KEY_LENGTH, SHARED_SECRET_LENGTH
            )));
        }
        let seed = self.decaps(usk, enc)?;
        seed.map(|seed| {
            let mut sym_key = SymmetricKey::<KEY_LENGTH>::default();
            kdf256!(&mut *sym_key, &*seed);
            E::decrypt(&sym_key, ctx)
        })
        .transpose()
    }
}
