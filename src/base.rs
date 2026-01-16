use crate::{
    abe::{AccessPolicy, KemAc},
    providers::{MlKem, PreQuantumKem},
    AccessStructure, Covercrypt, Error, MasterPublicKey, MasterSecretKey, UserSecretKey, XEnc,
};
use cosmian_crypto_core::{
    reexport::{rand_core::CryptoRngCore, zeroize::ZeroizeOnDrop},
    traits::{kem_to_pke::GenericPKE, KEM},
    SymmetricKey,
};

#[derive(Debug)]
pub enum AbeDKey {
    Master(Covercrypt, MasterSecretKey),
    User(Covercrypt, UserSecretKey),
}

// All secret keys are zeroized on drop.
impl ZeroizeOnDrop for AbeDKey {}

#[derive(Debug, ZeroizeOnDrop)]
pub enum DKey {
    AbeScheme(AbeDKey),
    PreQuantum(<PreQuantumKem as KEM<{ ConfigurableKEM::KEY_LENGTH }>>::DecapsulationKey),
    PostQuantum(<MlKem as KEM<{ ConfigurableKEM::KEY_LENGTH }>>::DecapsulationKey),
}

impl DKey {
    pub fn access_structure(&mut self) -> Result<&mut AccessStructure, Error> {
        match self {
            DKey::AbeScheme(AbeDKey::Master(_, msk)) => Ok(&mut msk.access_structure),
            _ => Err(Error::KeyError(
                "no access structure associated to non-ABE key type".to_string(),
            )),
        }
    }

    pub fn update_msk(&mut self) -> Result<EKey, Error> {
        match self {
            DKey::AbeScheme(AbeDKey::Master(cc, msk)) => {
                let mpk = cc.update_msk(msk)?;
                Ok(EKey::AbeScheme(cc.clone(), mpk, None))
            }
            _ => Err(Error::KeyError(
                "cannot update non ABE master key".to_string(),
            )),
        }
    }

    pub fn rekey(&mut self, ap: &AccessPolicy) -> Result<EKey, Error> {
        match self {
            DKey::AbeScheme(AbeDKey::Master(cc, msk)) => {
                let mpk = cc.rekey(msk, ap)?;
                Ok(EKey::AbeScheme(cc.clone(), mpk, None))
            }
            _ => Err(Error::KeyError(
                "cannot re-key non ABE master key".to_string(),
            )),
        }
    }

    pub fn prune_master_key(&mut self, ap: &AccessPolicy) -> Result<EKey, Error> {
        match self {
            DKey::AbeScheme(AbeDKey::Master(cc, msk)) => {
                let mpk = cc.prune_master_secret_key(msk, ap)?;
                Ok(EKey::AbeScheme(cc.clone(), mpk, None))
            }
            _ => Err(Error::KeyError(
                "cannot prune non ABE master key".to_string(),
            )),
        }
    }

    pub fn generate_user_secret_key(&mut self, ap: &AccessPolicy) -> Result<DKey, Error> {
        match self {
            DKey::AbeScheme(AbeDKey::Master(cc, msk)) => {
                let usk = cc.generate_user_secret_key(msk, ap)?;
                Ok(DKey::AbeScheme(AbeDKey::User(cc.clone(), usk)))
            }
            _ => Err(Error::KeyError(
                "cannot generate user secret key using a non ABE master key".to_string(),
            )),
        }
    }

    pub fn refresh_user_secret_key(
        &mut self,
        usk: &mut DKey,
        keep_old_secrets: bool,
    ) -> Result<(), Error> {
        match (self, usk) {
            (DKey::AbeScheme(AbeDKey::Master(cc, msk)), DKey::AbeScheme(AbeDKey::User(_, usk))) => {
                cc.refresh_usk(msk, usk, keep_old_secrets)
            }
            _ => Err(Error::KeyError(
                "cannot refresh user secret key: invalid key types".to_string(),
            )),
        }
    }

    pub fn recaps(
        &mut self,
        mpk: &EKey,
        enc: &Enc,
    ) -> Result<(SymmetricKey<{ ConfigurableKEM::KEY_LENGTH }>, Enc), Error> {
        match (self, mpk, enc) {
            (
                DKey::AbeScheme(AbeDKey::Master(cc, msk)),
                EKey::AbeScheme(_, mpk, _),
                Enc::AbeScheme(enc),
            ) => {
                let (ss, enc) = cc.recaps(msk, mpk, enc)?;
                Ok((SymmetricKey::from(ss), Enc::AbeScheme(enc)))
            }
            _ => Err(Error::KeyError(
                "cannot re-encapsulate: invalid object types".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub enum EKey {
    AbeScheme(Covercrypt, MasterPublicKey, Option<AccessPolicy>),
    PreQuantum(<PreQuantumKem as KEM<{ ConfigurableKEM::KEY_LENGTH }>>::EncapsulationKey),
    PostQuantum(<MlKem as KEM<{ ConfigurableKEM::KEY_LENGTH }>>::EncapsulationKey),
}

impl EKey {
    /// Sets the encapsulation key to use the provided access polity.
    pub fn set_access_policy(&mut self, access_policy: AccessPolicy) -> Result<(), Error> {
        match self {
            Self::AbeScheme(_, _, ap) => {
                *ap = Some(access_policy);
                Ok(())
            }
            _ => Err(Error::KeyError(
                "cannot set access policy for non-ABE encapsulation keys".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Enc {
    AbeScheme(XEnc),
    PreQuantum(<PreQuantumKem as KEM<{ ConfigurableKEM::KEY_LENGTH }>>::Encapsulation),
    PostQuantum(<MlKem as KEM<{ ConfigurableKEM::KEY_LENGTH }>>::Encapsulation),
}

#[derive(Debug, Clone)]
pub enum Configuration {
    AbeScheme,
    PreQuantum,
    PostQuantum,
}

impl Configuration {
    pub fn keygen(&self, rng: &mut impl CryptoRngCore) -> Result<(DKey, EKey), Error> {
        match self {
            Self::AbeScheme => {
                let cc = Covercrypt::default();
                let (msk, mpk) = cc.setup()?;
                Ok((
                    DKey::AbeScheme(AbeDKey::Master(cc.clone(), msk)),
                    EKey::AbeScheme(cc, mpk, None),
                ))
            }
            Self::PreQuantum => {
                let (dk, ek) = PreQuantumKem::keygen(rng)?;
                Ok((DKey::PreQuantum(dk), EKey::PreQuantum(ek)))
            }
            Self::PostQuantum => {
                let (dk, ek) = MlKem::keygen(rng)?;
                Ok((DKey::PostQuantum(dk), EKey::PostQuantum(ek)))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfigurableKEM;

impl KEM<32> for ConfigurableKEM {
    type Encapsulation = Enc;

    type EncapsulationKey = EKey;

    type DecapsulationKey = DKey;

    type Error = Error;

    fn keygen(
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error> {
        Err(Error::Kem(
            "key generation is not implemented for ConfigurableKEM, use the KEMConfiguration instead"
                .to_string(),
        ))
    }

    fn enc(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(SymmetricKey<32>, Self::Encapsulation), Self::Error> {
        match ek {
            EKey::AbeScheme(_, _, None) => Err(Error::Kem(
                "access policy must be provided for encapsulation".to_string(),
            )),
            EKey::AbeScheme(cc, mpk, Some(ap)) => cc
                .encaps(mpk, ap)
                .map(|(key, enc)| (SymmetricKey::from(key), Enc::AbeScheme(enc))),
            EKey::PreQuantum(ek) => {
                let (key, enc) =
                    PreQuantumKem::enc(ek, rng).map_err(|e| Error::Kem(e.to_string()))?;
                Ok((key, Enc::PreQuantum(enc)))
            }
            EKey::PostQuantum(ek) => {
                let (key, enc) = MlKem::enc(ek, rng).map_err(|e| Error::Kem(e.to_string()))?;
                Ok((key, Enc::PostQuantum(enc)))
            }
        }
    }

    fn dec(
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<SymmetricKey<32>, Self::Error> {
        match (dk, enc) {
            (DKey::AbeScheme(dk), Enc::AbeScheme(xenc)) => match dk {
                AbeDKey::Master(_cc, msk) => {
                    let (ss, _) = crate::abe::core::primitives::master_decaps(msk, xenc, false)?;
                    Ok(SymmetricKey::from(ss))
                }
                AbeDKey::User(cc, usk) => cc.decaps(usk, xenc).and_then(|res| {
                    let ss = res.ok_or_else(|| {
                        Error::OperationNotPermitted(
                            "user key does not have the required access right".to_string(),
                        )
                    })?;
                    Ok(SymmetricKey::from(ss))
                }),
            },
            (DKey::PreQuantum(dk), Enc::PreQuantum(enc)) => {
                PreQuantumKem::dec(dk, enc).map_err(|e| Error::Kem(e.to_string()))
            }
            (DKey::PostQuantum(dk), Enc::PostQuantum(enc)) => {
                MlKem::dec(dk, enc).map_err(|e| Error::Kem(e.to_string()))
            }
            _ => Err(Error::KeyError(
                "cannot proceed with decapsulation: incompatible types".to_string(),
            )),
        }
    }
}

pub type ConfigurablePKE<AE> = GenericPKE<{ ConfigurableKEM::KEY_LENGTH }, ConfigurableKEM, AE>;

#[cfg(test)]
mod tests {
    use crate::test_utils::cc_keygen;

    use super::*;
    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};

    #[test]
    fn test_abe_kem() {
        let mut rng = CsRng::from_entropy();
        let config = Configuration::AbeScheme;
        let (mut msk, _) = config.keygen(&mut rng).unwrap();

        // Load the test access structure used in other tests.
        let access_structure = msk.access_structure().unwrap();
        let (_msk, _) = cc_keygen(&Covercrypt::default(), true).unwrap();
        *access_structure = _msk.access_structure.clone();
        let mut mpk = msk.update_msk().unwrap();

        let user_ap = AccessPolicy::parse("(DPT::MKG || DPT::FIN) && SEC::TOP").unwrap();
        let ok_ap = AccessPolicy::parse("DPT::MKG && SEC::TOP").unwrap();
        let ko_ap = AccessPolicy::parse("DPT::DEV").unwrap();

        let usk = msk.generate_user_secret_key(&user_ap).unwrap();

        // Check user *can* decrypt the OK access policy.
        mpk.set_access_policy(ok_ap).unwrap();
        let (key, enc) = ConfigurableKEM::enc(&mpk, &mut rng).unwrap();
        let key_ = ConfigurableKEM::dec(&usk, &enc).unwrap();
        assert_eq!(key, key_);

        // Check user *cannot* decrypt the KO access policy.
        mpk.set_access_policy(ko_ap).unwrap();
        let (_key, enc) = ConfigurableKEM::enc(&mpk, &mut rng).unwrap();
        let res = ConfigurableKEM::dec(&usk, &enc);
        assert!(res.is_err());
        match res {
            Err(Error::OperationNotPermitted(msg)) => {
                assert_eq!(&msg, "user key does not have the required access right")
            }
            _ => panic!("incorrect error returned"),
        }
    }
}
