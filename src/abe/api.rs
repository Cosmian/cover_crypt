use crate::{
    Error,
    abe::{
        core::{
            MIN_TRACING_LEVEL, MasterPublicKey, MasterSecretKey,
            SHARED_SECRET_LENGTH, UserSecretKey, XEnc,
            primitives::{
                self, master_decaps, prune, refresh, rekey, setup, update_msk,
                usk_keygen,
            },
        },
        policy::AccessPolicy,
        traits::{KemAc, PkeAc},
    },
};
use cosmian_crypto_core::{
    Secret,
    reexport::rand_core::CryptoRngCore,
    traits::{AE, KDF},
};

#[derive(Default, Debug, Clone)]
pub struct Covercrypt;

impl Covercrypt {
    /// Sets up the Covercrypt scheme.
    ///
    /// Generates a MSK and a MPK only holing broadcasting keys, and with a
    /// tracing level of [`MIN_TRACING_LEVEL`](core::MIN_TRACING_LEVEL).
    pub fn setup(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(MasterSecretKey, MasterPublicKey), Error> {
        let mut msk = setup(MIN_TRACING_LEVEL, rng)?;
        let rights = msk.access_structure.omega()?;
        update_msk(&mut msk, rights)?;
        let mpk = msk.mpk(None)?;
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
    pub fn update_msk(
        msk: &mut MasterSecretKey,
    ) -> Result<MasterPublicKey, Error> {
        update_msk(msk, msk.access_structure.omega()?)?;
        msk.mpk(None)
    }

    /// Generates new secrets for each right a USK associated to the given
    /// access policy would hold, updates the MSK and returns the new MPK.
    ///
    /// User keys need to be refreshed.
    // TODO document error cases.
    pub fn rekey(
        msk: &mut MasterSecretKey,
        ap: &AccessPolicy,
    ) -> Result<MasterPublicKey, Error> {
        rekey(msk, msk.access_structure.ap_to_usk_rights(ap)?)?;
        msk.mpk(None)
    }

    /// Removes from the master secret key all but the latest secret of each
    /// right a USK associated to the given access policy would hold. Returns
    /// the new MPK.
    ///
    /// This action is *irreversible*, and all user keys need to be refreshed.
    // TODO document error cases.
    pub fn prune_master_secret_key(
        msk: &mut MasterSecretKey,
        ap: &AccessPolicy,
    ) -> Result<MasterPublicKey, Error> {
        prune(msk, &msk.access_structure.ap_to_usk_rights(ap)?);
        msk.mpk(None)
    }

    /// Generates the MPK associated to this MSK.
    ///
    /// If an access policy was given, restrains the MPK to the keys required to
    /// generate encapsulations under this (or any stricter) access policy.
    pub fn gen_mpk(
        msk: &MasterSecretKey,
        ap: Option<&AccessPolicy>,
    ) -> Result<MasterPublicKey, Error> {
        msk.mpk(
            ap.map(|ap| msk.access_structure.ap_to_enc_rights(ap))
                .transpose()?
                .as_ref(),
        )
    }

    /// Generates a USK associated to the given access policy.
    ///
    /// The new key is given the latest secret of each right in the
    /// complementary space of its access policy.
    // TODO document error cases.
    pub fn generate_user_secret_key(
        rng: &mut impl CryptoRngCore,
        msk: &mut MasterSecretKey,
        ap: &AccessPolicy,
    ) -> Result<UserSecretKey, Error> {
        usk_keygen(rng, msk, msk.access_structure.ap_to_usk_rights(ap)?)
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
        rng: &mut impl CryptoRngCore,
        msk: &mut MasterSecretKey,
        usk: &mut UserSecretKey,
        keep_old_secrets: bool,
    ) -> Result<(), Error> {
        refresh(rng, msk, usk, keep_old_secrets)
    }

    /// Returns a new encapsulation with the same rights as the one given, along
    /// with a freshly generated shared secret.
    pub fn recaps(
        rng: &mut impl CryptoRngCore,
        msk: &MasterSecretKey,
        mpk: &MasterPublicKey,
        encapsulation: &XEnc,
    ) -> Result<(Secret<32>, XEnc), Error> {
        let (_ss, rights) = master_decaps(msk, encapsulation, true)?;
        primitives::encaps(rng, mpk, &rights)
    }
}

impl KemAc<SHARED_SECRET_LENGTH> for Covercrypt {
    type EncapsulationKey = MasterPublicKey;
    type DecapsulationKey = UserSecretKey;
    type Encapsulation = XEnc;
    type Error = Error;

    fn encaps(
        rng: &mut impl CryptoRngCore,
        ek: &Self::EncapsulationKey,
        ap: &AccessPolicy,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, Self::Encapsulation), Self::Error>
    {
        primitives::encaps(rng, ek, &ek.access_structure.ap_to_enc_rights(ap)?)
    }

    fn decaps(
        rng: &mut impl CryptoRngCore,
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<Option<Secret<SHARED_SECRET_LENGTH>>, Error> {
        primitives::decaps(rng, dk, enc)
    }
}

impl<
    const KEY_LENGTH: usize,
    const NONCE_LENGTH: usize,
    const TAG_LENGTH: usize,
    Kdf: KDF<KEY_LENGTH>,
    E: AE<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH>,
> PkeAc<KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH, Kdf, E> for Covercrypt
{
    type EncryptionKey = MasterPublicKey;
    type DecryptionKey = UserSecretKey;
    type Ciphertext = (XEnc, E::Ciphertext);
    type Error = Error;

    fn encrypt(
        rng: &mut impl CryptoRngCore,
        mpk: &Self::EncryptionKey,
        ap: &AccessPolicy,
        ptx: &[u8],
    ) -> Result<Self::Ciphertext, Self::Error> {
        let (seed, enc) = Self::encaps(rng, mpk, ap)?;
        let key = Kdf::derive(&*seed, vec![b"Covercrypt AE key"])
            .map_err(|e| Self::Error::Kdf(e.to_string()))?;
        let mut nonce = [0; NONCE_LENGTH];
        rng.fill_bytes(&mut nonce);
        let ctx = E::encrypt(&key, ptx, &nonce)
            .map_err(|e| Self::Error::Ae(e.to_string()))?;
        Ok((enc, ctx))
    }

    fn decrypt(
        rng: &mut impl CryptoRngCore,
        usk: &Self::DecryptionKey,
        ctx: &Self::Ciphertext,
    ) -> Result<Option<E::Plaintext>, Self::Error> {
        Self::decaps(rng, usk, &ctx.0)?
            .map(|seed| {
                let key = Kdf::derive(&*seed, vec![b"Covercrypt AE key"])
                    .map_err(|e| Self::Error::Kdf(e.to_string()))?;
                E::decrypt(&key, ctx.1.as_ref())
                    .map_err(|e| Self::Error::Ae(e.to_string()))
            })
            .transpose()
    }
}

/// Select a single feature combination.
#[cfg(all(
    feature = "curve25519",
    feature = "mlkem-512",
    not(feature = "p-256"),
    not(feature = "mlkem-768")
))]
#[cfg(test)]
mod tests {
    use crate::{
        AccessPolicy, Covercrypt, test_utils::cc_keygen, traits::KemAc,
    };
    use cosmian_crypto_core::{
        CsRng, bytes_ser_de::Serializable, reexport::rand_core::SeedableRng,
    };
    use regression_test::RegTest;

    #[test]
    fn test_regressions() {
        {
            // Ensure the (MSK, MPK) couple can be deterministically populated.
            let mut rng = CsRng::from_seed([0; 32]);
            let (msk_1, mpk_1) = cc_keygen(&mut rng, true).unwrap();
            let mut rng = CsRng::from_seed([0; 32]);
            let (msk_2, mpk_2) = cc_keygen(&mut rng, true).unwrap();

            assert_eq!(msk_1, msk_2);
            assert_eq!(mpk_1, mpk_2);
        }

        let mut rng = CsRng::from_seed([0; 32]);
        let (mut msk, mpk) = cc_keygen(&mut rng, true).unwrap();

        let usk_1 = Covercrypt::generate_user_secret_key(
            &mut rng,
            &mut msk,
            &AccessPolicy::parse(
                "SEC::LOW || (SEC::TOP && ((CTR::FR || CTR::EN) || DPT::FIN))",
            )
            .unwrap(),
        )
        .unwrap();

        let usk_2 = Covercrypt::generate_user_secret_key(
            &mut rng,
            &mut msk,
            &AccessPolicy::parse(
                "(SEC::LOW && DPT::FIN) || (SEC::MED && CTR::FR && DPT::DEV)",
            )
            .unwrap(),
        )
        .unwrap();

        let enc_1 = Covercrypt::encaps(
            &mut rng,
            &mpk,
            &AccessPolicy::parse(
                "SEC::TOP && (((CTR::FR || CTR::EN) && DPT::DEV) || DPT::FIN)",
            )
            .unwrap(),
        )
        .unwrap();

        let enc_2 = Covercrypt::encaps(
            &mut rng,
            &mpk,
            &AccessPolicy::parse("*").unwrap(),
        )
        .unwrap();

        RegTest::new("./test-data/msk")
            .unwrap()
            .regtest_dbg(msk.serialize().unwrap().to_vec());

        RegTest::new("./test-data/mpk")
            .unwrap()
            .regtest_dbg(mpk.serialize().unwrap().to_vec());

        RegTest::new("./test-data/usk_1")
            .unwrap()
            .regtest_dbg(usk_1.serialize().unwrap().to_vec());

        RegTest::new("./test-data/usk_2")
            .unwrap()
            .regtest_dbg(usk_2.serialize().unwrap().to_vec());

        RegTest::new("./test-data/enc_1")
            .unwrap()
            .regtest_dbg(enc_1.serialize().unwrap().to_vec());

        RegTest::new("./test-data/enc_2")
            .unwrap()
            .regtest_dbg(enc_2.serialize().unwrap().to_vec());
    }
}
