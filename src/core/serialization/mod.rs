//! Implements the serialization methods for the `Covercrypt` objects.

use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable, Serializer};

use crate::{
    core::{
        MasterPublicKey, MasterSecretKey, RightPublicKey, RightSecretKey, TracingPublicKey,
        TracingSecretKey, UserId, UserSecretKey, XEnc,
    },
    Error,
};

impl Serializable for TracingPublicKey {
    type Error = Error;

    fn length(&self) -> usize {
        self.0.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        #[allow(clippy::needless_question_mark)]
        Ok(self.0.write(ser)?)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        #[allow(clippy::needless_question_mark)]
        Ok(Self(de.read()?))
    }
}

impl Serializable for RightPublicKey {
    type Error = Error;

    fn length(&self) -> usize {
        1 + match self {
            Self::Classic { H } => H.length(),
            Self::PostQuantum { ek } => ek.length(),
            Self::Hybridized { H, ek } => H.length() + ek.length(),
        }
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        match self {
            Self::Classic { H } => Ok(0usize.write(ser)? + H.write(ser)?),
            Self::PostQuantum { ek } => Ok(2usize.write(ser)? + ek.write(ser)?),
            Self::Hybridized { H, ek } => Ok(1usize.write(ser)? + H.write(ser)? + ek.write(ser)?),
        }
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let is_hybridized = de.read::<usize>()?;
        match is_hybridized {
            0 => Ok(Self::Classic { H: de.read()? }),
            2 => Ok(Self::PostQuantum { ek: de.read()? }),
            1 => Ok(Self::Hybridized {
                H: de.read()?,
                ek: de.read()?,
            }),
            n => Err(Error::ConversionFailed(format!(
                "invalid hybridization flag {n}"
            ))),
        }
    }
}

impl Serializable for MasterPublicKey {
    type Error = Error;

    fn length(&self) -> usize {
        self.tpk.length() + self.encryption_keys.length() + self.access_structure.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        Ok(self.tpk.write(ser)?
            + self.encryption_keys.write(ser)?
            + self.access_structure.write(ser)?)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        Ok(Self {
            tpk: de.read()?,
            encryption_keys: de.read()?,
            access_structure: de.read()?,
        })
    }
}

impl Serializable for TracingSecretKey {
    type Error = Error;

    fn length(&self) -> usize {
        self.s.length() + self.users.length() + self.tracers.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        Ok(self.s.write(ser)? + self.tracers.write(ser)? + self.users.write(ser)?)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        Ok(Self {
            s: de.read()?,
            tracers: de.read()?,
            users: de.read()?,
        })
    }
}

impl Serializable for MasterSecretKey {
    type Error = Error;

    fn length(&self) -> usize {
        self.tsk.length()
            + self.secrets.length()
            + self.signing_key.length()
            + self.access_structure.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        Ok(self.tsk.write(ser)?
            + self.secrets.write(ser)?
            + self.signing_key.write(ser)?
            + self.access_structure.write(ser)?)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        Ok(Self {
            tsk: de.read()?,
            secrets: de.read()?,
            signing_key: de.read()?,
            access_structure: de.read()?,
        })
    }
}

impl Serializable for UserId {
    type Error = Error;

    fn length(&self) -> usize {
        self.0.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        #[allow(clippy::needless_question_mark)]
        Ok(self.0.write(ser)?)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        #[allow(clippy::needless_question_mark)]
        Ok(Self(de.read()?))
    }
}

impl Serializable for RightSecretKey {
    type Error = Error;

    fn length(&self) -> usize {
        1 + match self {
            Self::Hybridized { sk, dk } => sk.length() + dk.length(),
            Self::Classic { sk } => sk.length(),
            Self::Quantum { dk } => dk.length(),
        }
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        match self {
            Self::Classic { sk } => Ok(0usize.write(ser)? + sk.write(ser)?),
            Self::Quantum { dk } => Ok(2usize.write(ser)? + dk.write(ser)?),
            Self::Hybridized { sk, dk } => {
                Ok(1usize.write(ser)? + sk.write(ser)? + dk.write(ser)?)
            }
        }
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let mode = de.read_leb128_u64()?;
        match mode {
            0 => Ok(Self::Classic { sk: de.read()? }),
            1 => Ok(Self::Hybridized {
                sk: de.read()?,
                dk: de.read()?,
            }),
            2 => Ok(Self::Quantum { dk: de.read()? }),
            _ => Err(Error::ConversionFailed(format!(
                "invalid hybridization flag {mode}"
            ))),
        }
    }
}

impl Serializable for UserSecretKey {
    type Error = Error;

    fn length(&self) -> usize {
        self.id.length() + self.ps.length() + self.secrets.length() + self.signature.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        Ok(self.id.write(ser)?
            + self.ps.write(ser)?
            + self.secrets.write(ser)?
            + self.signature.write(ser)?)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        Ok(Self {
            id: de.read()?,
            ps: de.read()?,
            secrets: de.read()?,
            signature: de.read()?,
        })
    }
}

impl Serializable for XEnc {
    type Error = Error;

    fn length(&self) -> usize {
        1 + match self {
            Self::Classic {
                tag,
                c,
                encapsulations,
            } => tag.length() + c.length() + encapsulations.length(),
            Self::Quantum {
                tag,
                encapsulations,
            } => tag.length() + encapsulations.length(),
            Self::Hybridized {
                tag,
                c,
                encapsulations,
            } => tag.length() + c.length() + encapsulations.length(),
        }
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        match self {
            XEnc::Classic {
                tag,
                c,
                encapsulations,
            } => Ok(0usize.write(ser)?
                + tag.write(ser)?
                + c.write(ser)?
                + encapsulations.write(ser)?),
            XEnc::Quantum {
                tag,
                encapsulations,
            } => Ok(1usize.write(ser)? + tag.write(ser)? + encapsulations.write(ser)?),
            XEnc::Hybridized {
                tag,
                c,
                encapsulations,
            } => Ok(2usize.write(ser)?
                + tag.write(ser)?
                + c.write(ser)?
                + encapsulations.write(ser)?),
        }
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let mode = usize::read(de)?;
        match mode {
            0 => Ok(Self::Classic {
                tag: de.read()?,
                c: de.read()?,
                encapsulations: de.read()?,
            }),
            1 => Ok(Self::Quantum {
                tag: de.read()?,
                encapsulations: de.read()?,
            }),
            2 => Ok(Self::Hybridized {
                tag: de.read()?,
                c: de.read()?,
                encapsulations: de.read()?,
            }),
            n => Err(Error::ConversionFailed(format!(
                "invalid encapsulation type: {n}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use cosmian_crypto_core::{
        bytes_ser_de::test_serialization, reexport::rand_core::SeedableRng, CsRng,
    };

    use crate::{
        abe_policy::{EncryptionStatus, Right},
        api::Covercrypt,
        core::{
            primitives::{encaps, rekey, setup, update_msk, usk_keygen},
            MIN_TRACING_LEVEL,
        },
        test_utils::cc_keygen,
        traits::KemAc,
        AccessPolicy, SecurityMode,
    };

    #[test]
    fn test_serializations() {
        {
            let mut rng = CsRng::from_entropy();
            let coordinate_1 = Right::random(&mut rng);
            let coordinate_2 = Right::random(&mut rng);
            let coordinate_3 = Right::random(&mut rng);

            let universe = HashMap::from([
                (
                    coordinate_1.clone(),
                    (SecurityMode::Hybridized, EncryptionStatus::EncryptDecrypt),
                ),
                (
                    coordinate_2.clone(),
                    (SecurityMode::Hybridized, EncryptionStatus::EncryptDecrypt),
                ),
                (
                    coordinate_3.clone(),
                    (SecurityMode::Hybridized, EncryptionStatus::EncryptDecrypt),
                ),
            ]);

            let user_set = HashSet::from([coordinate_1.clone(), coordinate_3.clone()]);
            let target_set = HashSet::from([coordinate_1, coordinate_3]);
            let mut rng = CsRng::from_entropy();

            let mut msk = setup(MIN_TRACING_LEVEL + 2, &mut rng).unwrap();
            update_msk(&mut rng, &mut msk, universe.clone()).unwrap();
            let mpk = msk.mpk().unwrap();
            let usk = usk_keygen(&mut rng, &mut msk, user_set).unwrap();
            let (_, enc) = encaps(&mut rng, &mpk, &target_set).unwrap();

            test_serialization(&msk).unwrap();
            test_serialization(&mpk).unwrap();
            test_serialization(&usk).unwrap();
            test_serialization(&enc).unwrap();

            rekey(&mut rng, &mut msk, universe.keys().cloned().collect()).unwrap();
            test_serialization(&msk).unwrap();
        }

        {
            let cc = Covercrypt::default();
            let (mut msk, mpk) = cc_keygen(&cc, false).unwrap();
            let usk = cc
                .generate_user_secret_key(&mut msk, &AccessPolicy::parse("SEC::TOP").unwrap())
                .unwrap();
            let (_, enc) = cc
                .encaps(&mpk, &AccessPolicy::parse("DPT::MKG").unwrap())
                .unwrap();

            test_serialization(&msk).unwrap();
            test_serialization(&mpk).unwrap();
            test_serialization(&usk).unwrap();
            test_serialization(&enc).unwrap();
        }
    }
}
