use std::sync::{Mutex, MutexGuard};

use cosmian_crypto_core::{CsRng, Secret, SymmetricKey, kdf256, reexport::rand_core::SeedableRng};
use zeroize::Zeroizing;

use super::{
    core::MIN_TRACING_LEVEL,
    core::primitives::{prune, update_msk, usk_keygen},
    traits::AE,
};
use crate::{
    AccessPolicy, Error,
    core::{
        MasterPublicKey, MasterSecretKey, SHARED_SECRET_LENGTH, UserSecretKey, XEnc,
        primitives::{decaps, encaps, full_decaps, refresh, rekey, setup},
    },
    traits::{KemAc, PkeAc},
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

impl Covercrypt {
    pub fn rng(&self) -> MutexGuard<CsRng> {
        self.rng.lock().expect("poisoned mutex")
    }

    /// Sets up the Covercrypt scheme.
    ///
    /// Generates a MSK and a MPK only holing broadcasting keys, and with a
    /// tracing level of [`MIN_TRACING_LEVEL`](core::MIN_TRACING_LEVEL).
    pub fn setup(&self) -> Result<(MasterSecretKey, MasterPublicKey), Error> {
        let mut rng = self.rng.lock().expect("Mutex lock failed!");
        let mut msk = setup(MIN_TRACING_LEVEL, &mut *rng)?;
        let rights = msk.access_structure.omega()?;
        update_msk(&mut *rng, &mut msk, rights)?;
        let mpk = msk.mpk()?;
        Ok((msk, mpk))
    }

    /// Updates the MSK according to its access structure. Returns the new
    /// version of the MPK.
    ///
    /// Sets the MSK rights to the one defined by the access structure:
    ///
    /// - removes rights from the MSK that don't belong to the access structure
    ///   along with their associated secrets;
    ///
    /// - adds the rights that don't belong yet to the MSK, generating new
    ///   secrets.
    ///
    /// The new MPK holds the latest encryption key of each right of the access
    /// structure.
    // TODO: this function should be internalized and replaced by specialized
    // functions.
    pub fn update_msk(&self, msk: &mut MasterSecretKey) -> Result<MasterPublicKey, Error> {
        update_msk(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            msk.access_structure.omega()?,
        )?;
        msk.mpk()
    }

    /// Generates new secrets for each right a USK associated to the given
    /// access policy would hold, updates the MSK and returns the new MPK.
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
            msk.access_structure.ap_to_usk_rights(ap)?,
        )?;
        msk.mpk()
    }

    /// Removes from the master secret key all but the latest secret of each
    /// right a USK associated to the given access policy would hold. Returns
    /// the new MPK.
    ///
    /// This action is *irreversible*, and all user keys need to be refreshed.
    // TODO document error cases.
    pub fn prune_master_secret_key(
        &self,
        msk: &mut MasterSecretKey,
        ap: &AccessPolicy,
    ) -> Result<MasterPublicKey, Error> {
        prune(msk, &msk.access_structure.ap_to_usk_rights(ap)?);
        msk.mpk()
    }

    /// Generates a USK associated to the given access policy.
    ///
    /// The new key is given the latest secret of each right in the
    /// complementary space of its access policy.
    // TODO document error cases.
    pub fn generate_user_secret_key(
        &self,
        msk: &mut MasterSecretKey,
        ap: &AccessPolicy,
    ) -> Result<UserSecretKey, Error> {
        usk_keygen(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            msk.access_structure.ap_to_usk_rights(ap)?,
        )
    }

    /// Refreshes the USK with respect to the given MSK.
    ///
    /// The USK is given all missing secrets since the first secret hold by the
    /// USK, for each right in the complementary space of its access
    /// policy. Secrets hold by the USK but have been removed from the MSK are
    /// removed.
    ///
    /// If `keep_old_secrets` is set to false, only the latest secret of each
    /// right is kept instead.
    ///
    /// Updates the tracing level to match the one of the MSK if needed.
    // TODO document error cases.
    pub fn refresh_usk(
        &self,
        msk: &mut MasterSecretKey,
        usk: &mut UserSecretKey,
        keep_old_secrets: bool,
    ) -> Result<(), Error> {
        refresh(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            usk,
            keep_old_secrets,
        )
    }

    /// Returns a new encapsulation with the same rights as the one given, along
    /// with a freshly generated shared secret.
    pub fn recaps(
        &self,
        msk: &MasterSecretKey,
        mpk: &MasterPublicKey,
        encapsulation: &XEnc,
    ) -> Result<(Secret<32>, XEnc), Error> {
        let (_ss, rights) = full_decaps(msk, encapsulation)?;
        encaps(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            mpk,
            &rights,
        )
    }
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
            &mpk.access_structure.ap_to_enc_rights(ap)?,
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

impl<const KEY_LENGTH: usize, E: AE<KEY_LENGTH, Error = Error>> PkeAc<KEY_LENGTH, E>
    for Covercrypt
{
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
