use crate::{
    AccessStructure, Error,
    abe::{
        core::{
            MIN_TRACING_LEVEL, MasterSecretKey, PublicKey,
            SHARED_SECRET_LENGTH, UserSecretKey, XEnc,
            primitives::{
                self, master_decaps, prune, refresh_usk, rekey, setup,
                update_msk, usk_keygen,
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
    /// Generates a fresh MSK only holding the broadcast right.
    pub fn setup(
        rng: &mut impl CryptoRngCore,
    ) -> Result<MasterSecretKey, Error> {
        let mut msk = setup(MIN_TRACING_LEVEL, rng)?;
        let rights = msk.access_structure.omega()?;
        update_msk(&mut msk, rights)?;
        Ok(msk)
    }

    /// Edits the access structure hold by the given MSK.
    pub fn edit_msk(
        msk: &mut MasterSecretKey,
        edit: impl FnOnce(&mut AccessStructure) -> Result<(), Error>,
    ) -> Result<(), Error> {
        edit(&mut msk.access_structure)?;
        update_msk(msk, msk.access_structure.omega()?)
    }

    /// Generates new secrets for each right a USK associated to the given
    /// access policy would hold and updates the MSK accordingly.
    ///
    /// All user secret and public keys need to be refreshed.
    pub fn rekey(
        msk: &mut MasterSecretKey,
        ap: AccessPolicy,
    ) -> Result<(), Error> {
        rekey(msk, msk.access_structure.ap_to_usk_rights(ap)?)
    }

    /// Removes from this MSK all but the latest secret of each right a USK
    /// associated to the given access policy would hold.
    ///
    /// This action is *irreversible*, and all user secret keys need to be
    /// refreshed in order to be pruned accordingly.
    pub fn prune(
        msk: &mut MasterSecretKey,
        ap: AccessPolicy,
    ) -> Result<(), Error> {
        prune(msk, &msk.access_structure.ap_to_usk_rights(ap)?);
        Ok(())
    }

    /// Generates the PK associated the given access policy.
    ///
    /// If none was given, generate the PK associated to the whole access
    /// structure.
    pub fn gen_pk(
        msk: &MasterSecretKey,
        ap: Option<AccessPolicy>,
    ) -> Result<PublicKey, Error> {
        msk.gen_pk(
            ap.map(|ap| msk.access_structure.ap_to_enc_rights(ap))
                .transpose()?
                .as_ref(),
        )
    }

    /// Generates a fresh USK associated to the given access policy.
    ///
    /// The new key is given the latest secret of each right in the
    /// complementary space of its access policy.
    pub fn gen_usk(
        rng: &mut impl CryptoRngCore,
        msk: &mut MasterSecretKey,
        ap: AccessPolicy,
    ) -> Result<UserSecretKey, Error> {
        usk_keygen(rng, msk, msk.access_structure.ap_to_usk_rights(ap)?)
    }

    /// Refreshes the given USK.
    ///
    /// The USK is given all missing secrets since the first secret hold by the
    /// USK, for each right in the complementary space of its access policy.
    /// Secrets hold by the USK but have been removed from the MSK are removed.
    ///
    /// If `keep_old_secrets` is set to false, only the latest secret of each
    /// right is kept instead.
    ///
    /// Updates the tracing level to match the one of the MSK if needed.
    pub fn refresh_usk(
        rng: &mut impl CryptoRngCore,
        msk: &mut MasterSecretKey,
        usk: &mut UserSecretKey,
        keep_old_secrets: bool,
    ) -> Result<(), Error> {
        refresh_usk(rng, msk, usk, keep_old_secrets)
    }

    /// Returns a new encapsulation with the same rights as the one given, along
    /// with a freshly generated shared secret.
    pub fn recaps(
        rng: &mut impl CryptoRngCore,
        msk: &MasterSecretKey,
        pk: &PublicKey,
        encapsulation: &XEnc,
    ) -> Result<(Secret<32>, XEnc), Error> {
        let (_ss, rights) = master_decaps(msk, encapsulation, true)?;
        primitives::encaps(rng, pk, &rights)
    }
}

impl KemAc<SHARED_SECRET_LENGTH> for Covercrypt {
    type EncapsulationKey = PublicKey;
    type DecapsulationKey = UserSecretKey;
    type Encapsulation = XEnc;
    type Error = Error;

    fn encaps(
        rng: &mut impl CryptoRngCore,
        ek: &Self::EncapsulationKey,
        ap: &AccessPolicy,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, Self::Encapsulation), Self::Error>
    {
        primitives::encaps(
            rng,
            ek,
            &ek.access_structure().ap_to_enc_rights(ap.clone())?,
        )
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
    type EncryptionKey = PublicKey;
    type DecryptionKey = UserSecretKey;
    type Ciphertext = (XEnc, E::Ciphertext);
    type Error = Error;

    fn encrypt(
        rng: &mut impl CryptoRngCore,
        pk: &Self::EncryptionKey,
        ap: &AccessPolicy,
        ptx: &[u8],
    ) -> Result<Self::Ciphertext, Self::Error> {
        let (seed, enc) = Self::encaps(rng, pk, ap)?;
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
            // Ensure the (MSK, PK) couple can be deterministically populated.
            let mut rng = CsRng::from_seed([0; 32]);
            let (msk_1, pk_1) = cc_keygen(&mut rng, true).unwrap();
            let mut rng = CsRng::from_seed([0; 32]);
            let (msk_2, pk_2) = cc_keygen(&mut rng, true).unwrap();

            assert_eq!(msk_1, msk_2);
            assert_eq!(pk_1, pk_2);
        }

        let mut rng = CsRng::from_seed([0; 32]);
        let (mut msk, pk) = cc_keygen(&mut rng, true).unwrap();

        let usk_1 = Covercrypt::gen_usk(
            &mut rng,
            &mut msk,
            AccessPolicy::parse(
                "SEC::LOW || (SEC::TOP && ((CTR::FR || CTR::EN) || DPT::FIN))",
            )
            .unwrap(),
        )
        .unwrap();

        let usk_2 = Covercrypt::gen_usk(
            &mut rng,
            &mut msk,
            AccessPolicy::parse(
                "(SEC::LOW && DPT::FIN) || (SEC::MED && CTR::FR && DPT::DEV)",
            )
            .unwrap(),
        )
        .unwrap();

        let enc_1 = Covercrypt::encaps(
            &mut rng,
            &pk,
            &AccessPolicy::parse(
                "SEC::TOP && (((CTR::FR || CTR::EN) && DPT::DEV) || DPT::FIN)",
            )
            .unwrap(),
        )
        .unwrap();

        let enc_2 = Covercrypt::encaps(
            &mut rng,
            &pk,
            &AccessPolicy::parse("*").unwrap(),
        )
        .unwrap();

        RegTest::new("./test-data/msk")
            .unwrap()
            .regtest_dbg(msk.serialize().unwrap().to_vec());

        RegTest::new("./test-data/pk")
            .unwrap()
            .regtest_dbg(pk.serialize().unwrap().to_vec());

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
