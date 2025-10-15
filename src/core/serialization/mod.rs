//! Implements the serialization methods for the `Covercrypt` objects.

use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable, Serializer};

use crate::{
    core::{
        Encapsulations, MasterPublicKey, MasterSecretKey, RightPublicKey, RightSecretKey,
        TracingPublicKey, TracingSecretKey, UserId, UserSecretKey, XEnc,
    },
    Error,
};

impl Serializable for TracingPublicKey {
    type Error = Error;

    fn length(&self) -> usize {
        self.0.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        self.0.write(ser)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        de.read().map(Self)
    }
}

impl Serializable for RightPublicKey {
    type Error = Error;

    fn length(&self) -> usize {
        1 + match self {
            Self::Hybridized { H, ek } => H.length() + ek.length(),
            Self::Classic { H } => H.length(),
        }
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        match self {
            Self::Classic { H } => Ok(0usize.write(ser)? + H.write(ser)?),
            Self::Hybridized { H, ek } => Ok(1usize.write(ser)? + ser.write(H)? + ser.write(ek)?),
        }
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let is_hybridized = de.read::<usize>()?;
        match is_hybridized {
            0 => Ok(Self::Classic { H: de.read()? }),
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
        self.0.write(ser)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        de.read().map(Self)
    }
}

impl Serializable for RightSecretKey {
    type Error = Error;

    fn length(&self) -> usize {
        1 + match self {
            Self::Hybridized { sk, dk } => sk.length() + dk.length(),
            Self::Classic { sk } => sk.length(),
        }
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        match self {
            Self::Hybridized { sk, dk } => {
                let mut n = ser.write_leb128_u64(1)?;
                n += ser.write(sk)?;
                n += ser.write(dk)?;
                Ok(n)
            }
            Self::Classic { sk } => {
                let mut n = ser.write_leb128_u64(0)?;
                n += ser.write(sk)?;
                Ok(n)
            }
        }
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let is_hybridized = de.read_leb128_u64()?;
        let sk = de.read()?;
        if 1 == is_hybridized {
            let dk = de.read()?;
            Ok(Self::Hybridized { sk, dk })
        } else if 0 == is_hybridized {
            Ok(Self::Classic { sk })
        } else {
            Err(Error::ConversionFailed(format!(
                "invalid hybridization flag {is_hybridized}"
            )))
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

impl Serializable for Encapsulations {
    type Error = Error;

    fn length(&self) -> usize {
        1 + match self {
            Encapsulations::HEncs(vec) => vec.length(),
            Encapsulations::CEncs(vec) => vec.length(),
        }
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        match self {
            Encapsulations::CEncs(vec) => Ok(0usize.write(ser)? + vec.write(ser)?),
            Encapsulations::HEncs(vec) => Ok(1usize.write(ser)? + vec.write(ser)?),
        }
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let is_hybridized = de.read_leb128_u64()?;
        match is_hybridized {
            0 => Ok(Self::CEncs(de.read()?)),
            1 => Ok(Self::HEncs(de.read()?)),
            n => Err(Error::ConversionFailed(format!(
                "invalid encapsulation type: {n}"
            ))),
        }
    }
}

impl Serializable for XEnc {
    type Error = Error;

    fn length(&self) -> usize {
        self.tag.length() + self.c.length() + self.encapsulations.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        Ok(self.tag.write(ser)? + self.c.write(ser)? + self.encapsulations.write(ser)?)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        Ok(Self {
            tag: de.read()?,
            c: de.read()?,
            encapsulations: de.read()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use cosmian_crypto_core::{
        bytes_ser_de::test_serialization, reexport::rand_core::SeedableRng, CsRng,
    };

    use crate::{
        abe_policy::{AttributeStatus, EncryptionHint, Right},
        api::Covercrypt,
        core::{
            primitives::{encaps, rekey, setup, update_msk, usk_keygen},
            MIN_TRACING_LEVEL,
        },
        test_utils::cc_keygen,
        traits::KemAc,
        AccessPolicy,
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
                    (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
                ),
                (
                    coordinate_2.clone(),
                    (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
                ),
                (
                    coordinate_3.clone(),
                    (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
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
