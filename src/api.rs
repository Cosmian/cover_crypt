use std::sync::{Mutex, MutexGuard};

use cosmian_crypto_core::{kdf256, reexport::rand_core::SeedableRng, CsRng, Secret, SymmetricKey};
use zeroize::Zeroizing;

use super::{
    ae::AE,
    core::primitives::{prune, update_coordinate_keys, usk_keygen},
    core::MIN_TRACING_LEVEL,
};
use crate::{
    abe_policy::AccessPolicy,
    core::{
        primitives::{decaps, encaps, refresh, rekey, setup},
        MasterPublicKey, MasterSecretKey, UserSecretKey, XEnc, SHARED_SECRET_LENGTH,
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
        let mut rng = self.rng.lock().expect("Mutex lock failed!");
        let mut msk = setup(MIN_TRACING_LEVEL, &mut *rng)?;
        let coordinates = msk.policy.generate_universal_coordinates()?;
        update_coordinate_keys(&mut *rng, &mut msk, coordinates)?;
        let mpk = msk.mpk()?;
        Ok((msk, mpk))
    }

    /// Updates the MSK according to this policy. Returns the new version of the
    /// MPK.
    ///
    /// Sets the MSK coordinates to the one defined by the policy:
    /// - removes coordinates from the MSK that don't belong to the new policy
    ///   along with their associated keys;
    /// - adds the policy coordinates that don't belong yet to the MSK,
    ///   generating new keys.
    ///
    /// The new MPK holds the latest public keys of each coordinates of the new policy.
    // TODO: this function should be internalized and replaced by specialized functions.
    pub fn update_msk(&self, msk: &mut MasterSecretKey) -> Result<MasterPublicKey, Error> {
        update_coordinate_keys(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            msk.policy.generate_universal_coordinates()?,
        )?;
        msk.mpk()
    }

    /// Generates new secrets for each right a USK associated to the given access policy would
    /// hold, updates the MSK and returns the new MPK.
    ///
    /// User keys need to be refreshed.
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

    /// Removes from the master secret key all but the latest secret of each right a USK associated
    /// to the given access policy would hold. Returns the new MPK.
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
    /// The new key is given the latest secret of each right in the complementary space of its
    /// access policy.
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

    /// Refreshes the USK with respect to the given MSK.
    ///
    /// The USK is given all missing secrets since the first secret hold by the USK, for each right
    /// in the complementary space of its access policy. Secrets hold by the USK but have been
    /// removed from the MSK are removed.
    ///
    /// If `keep_old_rights` is set to false, only the latest secret of each right is kept instead.
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

pub trait KemAc<const LENGTH: usize> {
    type EncapsulationKey;
    type DecapsulationKey;
    type Encapsulation;
    type Error: std::error::Error;

    /// Generates a new encapsulation for the given access policy.
    ///
    /// # Error
    /// Returns an error if the access policy is not valid.
    fn encaps(
        &self,
        ek: &Self::EncapsulationKey,
        ap: &AccessPolicy,
    ) -> Result<(Secret<LENGTH>, Self::Encapsulation), Self::Error>;

    /// Attempts opening the given encapsulation with the given key. Returns the encapsulated
    /// secret upon success or `None` if this key was not authorized to open this encapsulation.
    // TODO: document error cases.
    fn decaps(
        &self,
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<Option<Secret<LENGTH>>, Self::Error>;
}

impl KemAc<SHARED_SECRET_LENGTH> for Covercrypt {
    type EncapsulationKey = MasterPublicKey;
    type DecapsulationKey = UserSecretKey;
    type Encapsulation = XEnc;
    type Error = Error;

    fn encaps(
        &self,
        mpk: &MasterPublicKey,
        ap: &AccessPolicy,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, Self::Encapsulation), Self::Error> {
        encaps(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            mpk,
            &mpk.policy.ap_to_enc_rights(ap)?,
        )
    }

    fn decaps(
        &self,
        usk: &UserSecretKey,
        enc: &XEnc,
    ) -> Result<Option<Secret<SHARED_SECRET_LENGTH>>, Error> {
        decaps(usk, enc)
    }
}

pub trait PkeAc<Aead, const KEY_LENGTH: usize> {
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

    /// Attempts decrypting the given ciphertext with the given key. Returns the plaintext upon
    /// success, or `None` if this key was not authorized to decrypt this ciphertext.
    //
    // TODO: document error cases.
    fn decrypt(
        &self,
        usk: &Self::DecryptionKey,
        ctx: &Self::Ciphertext,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error>;
}

impl<const KEY_LENGTH: usize, E: AE<KEY_LENGTH>> PkeAc<E, KEY_LENGTH> for Covercrypt {
    type EncryptionKey = MasterPublicKey;
    type DecryptionKey = UserSecretKey;
    type Ciphertext = (XEnc, Vec<u8>);
    type Error = Error;

    fn encrypt(
        &self,
        mpk: &MasterPublicKey,
        ap: &AccessPolicy,
        ptx: &[u8],
    ) -> Result<(XEnc, Vec<u8>), Error> {
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
        ctx: &(XEnc, Vec<u8>),
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        if SHARED_SECRET_LENGTH < KEY_LENGTH {
            return Err(Error::ConversionFailed(format!(
                "insufficient entropy to generate a {}-byte key from a {}-byte seed",
                KEY_LENGTH, SHARED_SECRET_LENGTH
            )));
        }
        let seed = self.decaps(usk, &ctx.0)?;
        seed.map(|seed| {
            let mut sym_key = SymmetricKey::<KEY_LENGTH>::default();
            kdf256!(&mut *sym_key, &*seed);
            E::decrypt(&sym_key, &ctx.1)
        })
        .transpose()
    }
}
