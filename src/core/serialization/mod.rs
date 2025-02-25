//! Implements the serialization methods for the `Covercrypt` objects.

use std::collections::{HashMap, HashSet, LinkedList};

use cosmian_crypto_core::{
    bytes_ser_de::{to_leb128_len, Deserializer, Serializable, Serializer},
    FixedSizeCBytes, SymmetricKey,
};

use super::{
    Encapsulations, RightPublicKey, RightSecretKey, TracingPublicKey, TracingSecretKey, UserId,
    SIGNATURE_LENGTH, SIGNING_KEY_LENGTH, TAG_LENGTH,
};
use crate::{
    abe_policy::{AccessStructure, Right},
    core::{MasterPublicKey, MasterSecretKey, UserSecretKey, XEnc, SHARED_SECRET_LENGTH},
    data_struct::{RevisionMap, RevisionVec},
    Error,
};

impl Serializable for TracingPublicKey {
    type Error = Error;

    fn length(&self) -> usize {
        to_leb128_len(self.0.len()) + self.0.iter().map(Serializable::length).sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_leb128_u64(self.0.len() as u64)?;
        for pk in self.0.iter() {
            n += pk.write(ser)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let n_pk = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut tracers = LinkedList::new();
        for _ in 0..n_pk {
            let tracer = de.read()?;
            tracers.push_back(tracer);
        }
        Ok(Self(tracers))
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
            Self::Hybridized { H, ek } => {
                let mut n = ser.write_leb128_u64(1)?;
                n += ser.write(H)?;
                n += ser.write(ek)?;
                Ok(n)
            }
            Self::Classic { H } => {
                let mut n = ser.write_leb128_u64(0)?;
                n += ser.write(H)?;
                Ok(n)
            }
        }
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let is_hybridized = de.read_leb128_u64()?;
        let H = de.read()?;
        if 1 == is_hybridized {
            let ek = de.read()?;
            Ok(Self::Hybridized { H, ek })
        } else if 0 == is_hybridized {
            Ok(Self::Classic { H })
        } else {
            Err(Error::ConversionFailed(format!(
                "invalid hybridization flag {is_hybridized}"
            )))
        }
    }
}

impl Serializable for MasterPublicKey {
    type Error = Error;

    fn length(&self) -> usize {
        self.tpk.length()
            + to_leb128_len(self.encryption_keys.len())
            + self
                .encryption_keys
                .iter()
                .map(|(coordinate, pk)| coordinate.length() + pk.length())
                .sum::<usize>()
            + self.access_structure.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write(&self.tpk)?;
        n += ser.write_leb128_u64(self.encryption_keys.len() as u64)?;
        for (coordinate, pk) in &self.encryption_keys {
            n += ser.write(coordinate)?;
            n += ser.write(pk)?;
        }
        n += ser.write(&self.access_structure)?;

        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let tpk = de.read::<TracingPublicKey>()?;
        let n_coordinates = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut coordinate_keys = HashMap::with_capacity(n_coordinates);
        for _ in 0..n_coordinates {
            let coordinate = de.read::<Right>()?;
            let pk = de.read::<RightPublicKey>()?;
            coordinate_keys.insert(coordinate, pk);
        }
        let access_structure = de.read::<AccessStructure>()?;
        Ok(Self {
            tpk,
            encryption_keys: coordinate_keys,
            access_structure,
        })
    }
}

impl Serializable for TracingSecretKey {
    type Error = Error;

    fn length(&self) -> usize {
        self.s.length()
            + to_leb128_len(self.users.len())
            + self.users.iter().map(Serializable::length).sum::<usize>()
            + to_leb128_len(self.tracers.len())
            + self
                .tracers
                .iter()
                .map(|(sk, pk)| sk.length() + pk.length())
                .sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = self.s.write(ser)?;

        n += ser.write_leb128_u64(self.tracers.len() as u64)?;
        for (sk, pk) in &self.tracers {
            n += ser.write(sk)?;
            n += ser.write(pk)?;
        }

        n = ser.write_leb128_u64(self.users.len() as u64)?;
        for id in &self.users {
            n += ser.write(id)?;
        }

        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let s = de.read()?;

        let n_tracers = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut tracers = LinkedList::new();
        for _ in 0..n_tracers {
            let sk = de.read()?;
            let pk = de.read()?;
            tracers.push_back((sk, pk));
        }

        let n_users = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut users = HashSet::with_capacity(n_users);
        for _ in 0..n_users {
            let id = de.read()?;
            users.insert(id);
        }
        Ok(Self { s, tracers, users })
    }
}

impl Serializable for MasterSecretKey {
    type Error = Error;

    fn length(&self) -> usize {
        self.tsk.length()
            + to_leb128_len(self.secrets.len())
            + self
                .secrets
                .iter()
                .map(|(coordinate, chain)| {
                    coordinate.length()
                        + to_leb128_len(chain.len())
                        + chain.iter().map(|(_, k)| 1 + k.length()).sum::<usize>()
                })
                .sum::<usize>()
            + self.signing_key.as_ref().map_or_else(|| 0, |key| key.len())
            + self.access_structure.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write(&self.tsk)?;
        n += ser.write_leb128_u64(self.secrets.len() as u64)?;
        for (coordinate, chain) in &self.secrets.map {
            n += ser.write(coordinate)?;
            n += ser.write_leb128_u64(to_leb128_len(chain.len()) as u64)?;
            for (is_activated, sk) in chain {
                n += ser.write_leb128_u64((*is_activated).into())?;
                n += ser.write(sk)?;
            }
        }
        if let Some(kmac_key) = &self.signing_key {
            n += ser.write_array(&**kmac_key)?;
        }
        n += ser.write(&self.access_structure)?;
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let tsk = de.read::<TracingSecretKey>()?;
        let n_coordinates = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut coordinate_keypairs = RevisionMap::with_capacity(n_coordinates);
        for _ in 0..n_coordinates {
            let coordinate = de.read()?;
            let n_keys = <usize>::try_from(de.read_leb128_u64()?)?;
            let chain = (0..n_keys)
                .map(|_| -> Result<_, Error> {
                    let is_activated = de.read_leb128_u64()? == 1;
                    let sk = de.read::<RightSecretKey>()?;
                    Ok((is_activated, sk))
                })
                .collect::<Result<LinkedList<_>, _>>()?;
            coordinate_keypairs.map.insert(coordinate, chain);
        }

        let signing_key = if de.value().len() < SIGNING_KEY_LENGTH {
            None
        } else {
            Some(SymmetricKey::try_from_bytes(
                de.read_array::<SIGNING_KEY_LENGTH>()?,
            )?)
        };

        let access_structure = de.read()?;

        Ok(Self {
            tsk,
            secrets: coordinate_keypairs,
            signing_key,
            access_structure,
        })
    }
}

impl Serializable for UserId {
    type Error = Error;

    fn length(&self) -> usize {
        to_leb128_len(self.0.len()) + self.iter().map(|marker| marker.length()).sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_leb128_u64(self.0.len() as u64)?;
        for marker in &self.0 {
            n += ser.write(marker)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let length = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut id = LinkedList::new();
        for _ in 0..length {
            let marker = de.read()?;
            id.push_back(marker);
        }
        Ok(Self(id))
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
        self.id.length()
            + to_leb128_len(self.ps.len())
            + self.ps.iter().map(|p| p.length()).sum::<usize>()
            + to_leb128_len(self.secrets.len())
            + self
                .secrets
                .iter()
                .map(|(coordinate, chain)| {
                    coordinate.length()
                        + to_leb128_len(chain.len())
                        + chain.iter().map(|sk| sk.length()).sum::<usize>()
                })
                .sum::<usize>()
            + self.signature.as_ref().map_or_else(|| 0, |kmac| kmac.len())
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write(&self.id)?;

        n += ser.write_leb128_u64(self.ps.len() as u64)?;
        for p in &self.ps {
            n += ser.write(p)?;
        }

        n += ser.write_leb128_u64(self.secrets.len() as u64)?;
        for (coordinate, chain) in self.secrets.iter() {
            n += ser.write(coordinate)?;
            n += ser.write_leb128_u64(chain.len() as u64)?;
            for sk in chain {
                n += ser.write(sk)?;
            }
        }
        if let Some(kmac) = &self.signature {
            n += ser.write_array(kmac)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let id = de.read::<UserId>()?;

        let n_ps = usize::try_from(de.read_leb128_u64()?)?;

        let mut ps = Vec::with_capacity(n_ps);
        for _ in 0..n_ps {
            let p = de.read()?;
            ps.push(p);
        }

        let n_coordinates = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut coordinate_keys = RevisionVec::with_capacity(n_coordinates);
        for _ in 0..n_coordinates {
            let coordinate = de.read()?;
            let n_keys = <usize>::try_from(de.read_leb128_u64()?)?;
            let new_chain = (0..n_keys)
                .map(|_| de.read::<RightSecretKey>())
                .collect::<Result<_, _>>()?;
            coordinate_keys.insert_new_chain(coordinate, new_chain);
        }

        let msk_signature = if de.value().len() < SIGNATURE_LENGTH {
            None
        } else {
            Some(de.read_array::<SIGNATURE_LENGTH>()?)
        };

        Ok(Self {
            id,
            ps,
            secrets: coordinate_keys,
            signature: msk_signature,
        })
    }
}

impl Serializable for Encapsulations {
    type Error = Error;

    fn length(&self) -> usize {
        1 + match self {
            Encapsulations::HEncs(vec) => {
                to_leb128_len(vec.len())
                    + vec.iter().map(|(E, F)| E.length() + F.len()).sum::<usize>()
            }
            Encapsulations::CEncs(vec) => {
                to_leb128_len(vec.len()) + vec.iter().map(|F| F.len()).sum::<usize>()
            }
        }
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        match self {
            Encapsulations::HEncs(vec) => {
                let mut n = ser.write_leb128_u64(1)?;
                n += ser.write_leb128_u64(vec.len() as u64)?;
                for (E, F) in vec.iter() {
                    n += ser.write(E)?;
                    n += ser.write_array(F)?;
                }
                Ok(n)
            }
            Encapsulations::CEncs(vec) => {
                let mut n = ser.write_leb128_u64(0)?;
                n += ser.write_leb128_u64(vec.len() as u64)?;
                for F in vec.iter() {
                    n += ser.write_array(F)?;
                }
                Ok(n)
            }
        }
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let is_hybridized = de.read_leb128_u64()?;
        if is_hybridized == 1 {
            let len = usize::try_from(de.read_leb128_u64()?)?;
            let vec = (0..len)
                .map(|_| {
                    let E = de.read()?;
                    let F = de.read_array::<SHARED_SECRET_LENGTH>()?;
                    Ok::<_, Error>((E, F))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Self::HEncs(vec))
        } else if 0 == is_hybridized {
            let len = usize::try_from(de.read_leb128_u64()?)?;
            let vec = (0..len)
                .map(|_| {
                    let F = de.read_array::<SHARED_SECRET_LENGTH>()?;
                    Ok::<_, Error>(F)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Self::CEncs(vec))
        } else {
            Err(Error::ConversionFailed(format!(
                "invalid hybridization flag {is_hybridized}"
            )))
        }
    }
}

impl Serializable for XEnc {
    type Error = Error;

    fn length(&self) -> usize {
        TAG_LENGTH
            + to_leb128_len(self.c.len())
            + self.c.iter().map(Serializable::length).sum::<usize>()
            + self.encapsulations.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(&self.tag)?;
        n += ser.write_leb128_u64(self.c.len() as u64)?;
        for trap in &self.c {
            n += ser.write(trap)?;
        }
        n += ser.write(&self.encapsulations)?;
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let tag = de.read_array::<TAG_LENGTH>()?;
        let n_traps = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut traps = Vec::with_capacity(n_traps);
        for _ in 0..n_traps {
            let trap = de.read()?;
            traps.push(trap);
        }
        let encapsulations = Encapsulations::read(de)?;
        Ok(Self {
            tag,
            c: traps,
            encapsulations,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use cosmian_crypto_core::{
        bytes_ser_de::test_serialization, reexport::rand_core::SeedableRng, CsRng,
    };

    use super::*;
    use crate::{
        abe_policy::{AttributeStatus, EncryptionHint},
        api::Covercrypt,
        core::{
            primitives::{encaps, setup, update_msk, usk_keygen},
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
            update_msk(&mut rng, &mut msk, universe).unwrap();
            let mpk = msk.mpk().unwrap();
            let usk = usk_keygen(&mut rng, &mut msk, user_set).unwrap();
            let (_, enc) = encaps(&mut rng, &mpk, &target_set).unwrap();

            test_serialization(&msk).unwrap();
            test_serialization(&mpk).unwrap();
            test_serialization(&usk).unwrap();
            test_serialization(&enc).unwrap();
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
