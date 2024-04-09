//! Implements the serialization methods for the `Covercrypt` objects.

use std::collections::{HashMap, HashSet, LinkedList};

use cosmian_crypto_core::{
    bytes_ser_de::{to_leb128_len, Deserializer, Serializable, Serializer},
    FixedSizeCBytes, RandomFixedSizeCBytes, SymmetricKey,
};

use super::{
    elgamal::{EcPoint, Scalar},
    postquantum::{self, PublicKey},
    CoordinateKeypair, CoordinatePublicKey, CoordinateSecretKey, TracingPublicKey,
    TracingSecretKey, UserId, KMAC_KEY_LENGTH, KMAC_SIG_LENGTH, TAG_LENGTH,
};
use crate::{
    abe_policy::Coordinate,
    core::{
        Encapsulation, MasterPublicKey, MasterSecretKey, SeedEncapsulation, UserSecretKey,
        SEED_LENGTH,
    },
    data_struct::{RevisionMap, RevisionVec},
    Error,
};

use crate::api::CleartextHeader;
use crate::api::EncryptedHeader;
use core::marker::PhantomData;

impl Serializable for TracingPublicKey {
    type Error = Error;

    fn length(&self) -> usize {
        to_leb128_len(self.0.len()) + self.0.iter().map(Serializable::length).sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_leb128_u64(self.0.len() as u64)?;
        for pk in self.0.iter() {
            n += ser.write_array(&pk.to_bytes())?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let n_pk = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut tracers = LinkedList::new();
        for _ in 0..n_pk {
            let tracer = EcPoint::try_from_bytes(de.read_array::<{ EcPoint::LENGTH }>()?)?;
            tracers.push_back(tracer);
        }
        Ok(Self(tracers))
    }
}

impl Serializable for CoordinatePublicKey {
    type Error = Error;

    fn length(&self) -> usize {
        match self {
            CoordinatePublicKey::Hybridized { .. } => {
                1 + SEED_LENGTH + postquantum::PublicKey::LENGTH
            }
            CoordinatePublicKey::Classic { .. } => 1 + SEED_LENGTH,
        }
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        match self {
            CoordinatePublicKey::Hybridized {
                postquantum_pk,
                elgamal_pk,
            } => {
                let mut n = ser.write_leb128_u64(1)?;
                n += ser.write_array(postquantum_pk)?;
                n += ser.write_array(&elgamal_pk.to_bytes())?;
                Ok(n)
            }
            CoordinatePublicKey::Classic { elgamal_pk } => {
                let mut n = ser.write_leb128_u64(0)?;
                n += ser.write_array(&elgamal_pk.to_bytes())?;
                Ok(n)
            }
        }
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let is_hybridized = de.read_leb128_u64()?;
        if 1 == is_hybridized {
            Ok(Self::Hybridized {
                postquantum_pk: de.read::<PublicKey>()?,
                elgamal_pk: de.read::<EcPoint>()?,
            })
        } else if 0 == is_hybridized {
            Ok(Self::Classic {
                elgamal_pk: de.read::<EcPoint>()?,
            })
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
        self.h.length()
            + self.tpk.length()
            + to_leb128_len(self.coordinate_keys.len())
            + self
                .coordinate_keys
                .iter()
                .map(|(coordinate, pk)| coordinate.length() + pk.length())
                .sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(&self.h.to_bytes())?;
        n += ser.write(&self.tpk)?;
        n += ser.write_leb128_u64(self.coordinate_keys.len() as u64)?;
        for (coordinate, pk) in &self.coordinate_keys {
            n += ser.write(coordinate)?;
            n += ser.write(pk)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let h = de.read::<EcPoint>()?;
        let tpk = de.read::<TracingPublicKey>()?;
        let n_coordinates = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut coordinate_keys = HashMap::with_capacity(n_coordinates);
        for _ in 0..n_coordinates {
            let coordinate = de.read::<Coordinate>()?;
            let pk = de.read::<CoordinatePublicKey>()?;
            coordinate_keys.insert(coordinate, pk);
        }
        Ok(Self {
            h,
            tpk,
            coordinate_keys,
        })
    }
}

impl Serializable for TracingSecretKey {
    type Error = Error;

    fn length(&self) -> usize {
        to_leb128_len(self.users.len())
            + self.users.iter().map(Serializable::length).sum::<usize>()
            + to_leb128_len(self.tracers.len())
            + self.tracers.iter().map(Serializable::length).sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_leb128_u64(self.users.len() as u64)?;
        for id in &self.users {
            n += ser.write(id)?;
        }
        n += ser.write_leb128_u64(self.tracers.len() as u64)?;
        for tracer in &self.tracers {
            n += ser.write(tracer)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let n_users = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut users = HashSet::with_capacity(n_users);
        for _ in 0..n_users {
            let id = de.read()?;
            users.insert(id);
        }
        let n_tracers = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut tracers = LinkedList::new();
        for _ in 0..n_tracers {
            let t = de.read()?;
            tracers.push_back(t);
        }
        Ok(Self { tracers, users })
    }
}

impl Serializable for CoordinateKeypair {
    type Error = Error;

    fn length(&self) -> usize {
        self.elgamal_keypair.length()
            + 1
            + self
                .postquantum_keypair
                .as_ref()
                .map(Serializable::length)
                .unwrap_or_default()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write(&self.elgamal_keypair)?;
        if let Some(keypair) = &self.postquantum_keypair {
            n += ser.write_leb128_u64(1)?;
            n += ser.write(keypair)?;
        } else {
            n += ser.write_leb128_u64(0)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let elgamal_keypair = de.read()?;
        let is_hybridized = de.read_leb128_u64()?;
        if 1 == is_hybridized {
            let postquantum_keypair = de.read()?;
            Ok(Self {
                elgamal_keypair,
                postquantum_keypair: Some(postquantum_keypair),
            })
        } else if 0 == is_hybridized {
            Ok(Self {
                elgamal_keypair,
                postquantum_keypair: None,
            })
        } else {
            Err(Error::ConversionFailed(format!(
                "invalid hybridization flag {is_hybridized}"
            )))
        }
    }
}

impl Serializable for MasterSecretKey {
    type Error = Error;

    fn length(&self) -> usize {
        self.s.length()
            + self.tsk.length()
            + to_leb128_len(self.coordinate_keypairs.len())
            + self
                .coordinate_keypairs
                .iter()
                .map(|(coordinate, chain)| {
                    coordinate.length()
                        + to_leb128_len(chain.len())
                        + chain.iter().map(Serializable::length).sum::<usize>()
                })
                .sum::<usize>()
            + self.signing_key.as_ref().map_or_else(|| 0, |key| key.len())
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write(&self.s)?;
        n += ser.write(&self.tsk)?;
        n += ser.write_leb128_u64(self.coordinate_keypairs.len() as u64)?;
        for (coordinate, chain) in &self.coordinate_keypairs.map {
            n += ser.write(coordinate)?;
            n += ser.write_leb128_u64(to_leb128_len(chain.len()) as u64)?;
            for sk in chain {
                n += ser.write(sk)?;
            }
        }
        if let Some(kmac_key) = &self.signing_key {
            n += ser.write_array(kmac_key)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let s = Scalar::try_from_bytes(de.read_array::<{ Scalar::LENGTH }>()?)?;
        let tsk = de.read::<TracingSecretKey>()?;
        let n_coordinates = <usize>::try_from(de.read_leb128_u64()?)?;
        println!("n_coordinates: {n_coordinates}");
        let mut coordinate_keypairs = RevisionMap::with_capacity(n_coordinates);
        for i in 0..n_coordinates {
            println!("reading coordinate {i}");
            let coordinate = de.read()?;
            let n_keys = <usize>::try_from(de.read_leb128_u64()?)?;
            println!("n_keys {n_keys}");
            let chain = (0..n_keys)
                .map(|_| de.read::<CoordinateKeypair>())
                .collect::<Result<LinkedList<_>, _>>()?;
            coordinate_keypairs.map.insert(coordinate, chain);
        }

        println!("HEY");

        let signing_key = if de.value().len() < KMAC_KEY_LENGTH {
            None
        } else {
            Some(SymmetricKey::try_from_bytes(
                de.read_array::<KMAC_KEY_LENGTH>()?,
            )?)
        };

        println!("OH");

        Ok(Self {
            s,
            tsk,
            coordinate_keypairs,
            signing_key,
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

impl Serializable for CoordinateSecretKey {
    type Error = Error;

    fn length(&self) -> usize {
        1 + match self {
            CoordinateSecretKey::Hybridized {
                postquantum_sk,
                elgamal_sk,
            } => elgamal_sk.length() + postquantum_sk.length(),
            CoordinateSecretKey::Classic { elgamal_sk } => elgamal_sk.length(),
        }
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        match self {
            CoordinateSecretKey::Hybridized {
                postquantum_sk,
                elgamal_sk,
            } => {
                let mut n = ser.write_leb128_u64(1)?;
                n += ser.write(elgamal_sk)?;
                n += ser.write(postquantum_sk)?;
                Ok(n)
            }
            CoordinateSecretKey::Classic { elgamal_sk } => {
                let mut n = ser.write_leb128_u64(0)?;
                n += ser.write(elgamal_sk)?;
                Ok(n)
            }
        }
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let is_hybridized = de.read_leb128_u64()?;
        if 1 == is_hybridized {
            let elgamal_sk = de.read()?;
            let postquantum_sk = de.read()?;
            Ok(Self::Hybridized {
                postquantum_sk,
                elgamal_sk,
            })
        } else if 0 == is_hybridized {
            Ok(Self::Classic {
                elgamal_sk: de.read()?,
            })
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
            + to_leb128_len(self.coordinate_keys.len())
            + self
                .coordinate_keys
                .iter()
                .map(|(coordinate, chain)| {
                    coordinate.length()
                        + to_leb128_len(chain.len())
                        + chain.iter().map(|sk| sk.length()).sum::<usize>()
                })
                .sum::<usize>()
            + self
                .msk_signature
                .as_ref()
                .map_or_else(|| 0, |kmac| kmac.len())
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write(&self.id)?;
        n += ser.write_leb128_u64(self.coordinate_keys.len() as u64)?;
        for (coordinate, chain) in self.coordinate_keys.iter() {
            n += ser.write(coordinate)?;
            n += ser.write_leb128_u64(chain.len() as u64)?;
            for sk in chain {
                n += ser.write(sk)?;
            }
        }
        if let Some(kmac) = &self.msk_signature {
            n += ser.write_array(kmac)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let id = de.read::<UserId>()?;
        let n_coordinates = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut coordinate_keys = RevisionVec::with_capacity(n_coordinates);
        for _ in 0..n_coordinates {
            let coordinate = de.read()?;
            let n_keys = <usize>::try_from(de.read_leb128_u64()?)?;
            let new_chain = (0..n_keys)
                .map(|_| de.read::<CoordinateSecretKey>())
                .collect::<Result<_, _>>()?;
            coordinate_keys.insert_new_chain(coordinate, new_chain);
        }
        let msk_signature = if de.value().len() < KMAC_SIG_LENGTH {
            None
        } else {
            Some(de.read_array::<KMAC_SIG_LENGTH>()?)
        };
        Ok(Self {
            id,
            coordinate_keys,
            msk_signature,
        })
    }
}

impl Serializable for SeedEncapsulation {
    type Error = Error;

    fn length(&self) -> usize {
        1 + match self {
            Self::Classic(enc) => enc.len(),
            Self::Hybridized(enc) => enc.length(),
        }
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = 0;
        match self {
            Self::Classic(enc) => {
                n += ser.write_leb128_u64(0)?;
                n += ser.write_array(enc)?;
            }
            Self::Hybridized(enc) => {
                n += ser.write_leb128_u64(1)?;
                n += ser.write(enc)?;
            }
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let is_hybridized = de.read_leb128_u64()?;
        if is_hybridized == 1 {
            de.read::<postquantum::Ciphertext>().map(Self::Hybridized)
        } else {
            de.read_array::<SEED_LENGTH>()
                .map(Self::Classic)
                .map_err(Self::Error::from)
        }
    }
}

impl Serializable for Encapsulation {
    type Error = Error;

    fn length(&self) -> usize {
        TAG_LENGTH
            + to_leb128_len(self.traps.len())
            + self.traps.iter().map(Serializable::length).sum::<usize>()
            + to_leb128_len(self.coordinate_encapsulations.len())
            + self
                .coordinate_encapsulations
                .iter()
                .map(Serializable::length)
                .sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(&self.tag)?;
        n += ser.write_leb128_u64(self.traps.len() as u64)?;
        for trap in &self.traps {
            n += ser.write(trap)?;
        }
        n += ser.write_leb128_u64(self.coordinate_encapsulations.len() as u64)?;
        for enc in &self.coordinate_encapsulations {
            n += ser.write(enc)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let tag = de.read_array::<TAG_LENGTH>()?;
        let n_traps = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut traps = Vec::with_capacity(n_traps);
        for _ in 0..n_traps {
            let trap = de.read::<EcPoint>()?;
            traps.push(trap);
        }
        let n_encapsulations = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut coordinate_encapsulations = HashSet::with_capacity(n_encapsulations);
        for _ in 0..n_encapsulations {
            let enc = de.read::<SeedEncapsulation>()?;
            coordinate_encapsulations.insert(enc);
        }
        Ok(Self {
            tag,
            traps,
            coordinate_encapsulations,
        })
    }
}

impl<E> Serializable for EncryptedHeader<E> {
    type Error = Error;

    fn length(&self) -> usize {
        self.encapsulation.length()
            + if let Some(metadata) = &self.encrypted_metadata {
                to_leb128_len(to_leb128_len(metadata.len()) + metadata.len())
            } else {
                0
            }
    }

    /// Tries to serialize the encrypted header.
    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = self.encapsulation.write(ser)?;
        match &self.encrypted_metadata {
            Some(bytes) => n += ser.write_vec(bytes)?,
            None => n += ser.write_vec(&[])?,
        }
        Ok(n)
    }

    /// Tries to deserialize the encrypted header.
    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let encapsulation = de.read::<Encapsulation>()?;
        let ciphertext = de.read_vec()?;
        let encrypted_metadata = if ciphertext.is_empty() {
            None
        } else {
            Some(ciphertext)
        };
        Ok(Self {
            encapsulation,
            encrypted_metadata,
            phantom: PhantomData,
        })
    }
}

impl Serializable for CleartextHeader {
    type Error = Error;

    fn length(&self) -> usize {
        SEED_LENGTH
            + to_leb128_len(
                self.metadata
                    .as_ref()
                    .map(std::vec::Vec::len)
                    .unwrap_or_default(),
            )
            + self
                .metadata
                .as_ref()
                .map(std::vec::Vec::len)
                .unwrap_or_default()
    }

    /// Tries to serialize the cleartext header.
    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(self.symmetric_key.as_bytes())?;
        match &self.metadata {
            Some(bytes) => n += ser.write_vec(bytes)?,
            None => n += ser.write_vec(&[])?,
        }
        Ok(n)
    }

    /// Tries to deserialize the cleartext header.
    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let symmetric_key = SymmetricKey::try_from_bytes(de.read_array::<SEED_LENGTH>()?)?;
        let metadata = de.read_vec()?;
        let metadata = if metadata.is_empty() {
            None
        } else {
            Some(metadata)
        };
        Ok(Self {
            symmetric_key,
            metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};

    use super::*;
    use crate::{
        abe_policy::{AttributeStatus, EncryptionHint},
        core::{
            primitives::{encaps, mpk_keygen, setup, update_coordinate_keys, usk_keygen},
            MIN_TRACING_LEVEL,
        },
    };

    #[test]
    fn test_coordinate_keypair() {
        let mut rng = CsRng::from_entropy();
        let s = Scalar::new(&mut rng);
        let h = EcPoint::from(&s);

        {
            let ckp = CoordinateKeypair::random(&mut rng, &h, true);
            let bytes = ckp.serialize().unwrap();
            assert_eq!(bytes.len(), ckp.length());
            let ckp_ = CoordinateKeypair::deserialize(&bytes).unwrap();
            assert_eq!(ckp, ckp_);
        }

        {
            let ckp = CoordinateKeypair::random(&mut rng, &h, false);
            let bytes = ckp.serialize().unwrap();
            assert_eq!(bytes.len(), ckp.length());
            let ckp_ = CoordinateKeypair::deserialize(&bytes).unwrap();
            assert_eq!(ckp, ckp_);
        }
    }

    #[test]
    fn test_coordinate_pk() {
        let mut rng = CsRng::from_entropy();

        {
            let elgamal_pk = EcPoint::from(&Scalar::new(&mut rng));
            let cpk = CoordinatePublicKey::Classic { elgamal_pk };
            let bytes = cpk.serialize().unwrap();
            assert_eq!(bytes.len(), cpk.length());
            let cpk_ = CoordinatePublicKey::deserialize(&bytes).unwrap();
            assert_eq!(cpk, cpk_);
        }

        {
            let elgamal_pk = EcPoint::from(&Scalar::new(&mut rng));
            let postquantum_pk = postquantum::keygen(&mut rng).1;
            let cpk = CoordinatePublicKey::Hybridized {
                postquantum_pk,
                elgamal_pk,
            };

            let bytes = cpk.serialize().unwrap();
            assert_eq!(bytes.len(), cpk.length());
            let cpk_ = CoordinatePublicKey::deserialize(&bytes).unwrap();
            assert_eq!(cpk, cpk_);
        }
    }

    #[test]
    fn test_tracing_keys() {
        let mut rng = CsRng::from_entropy();
        let mut tsk = TracingSecretKey::default();
        for _ in 0..MIN_TRACING_LEVEL + 2 {
            tsk.increase_tracing(&mut rng);
        }

        {
            let bytes = tsk.serialize().unwrap();
            assert_eq!(bytes.len(), tsk.length());
            let tsk_ = TracingSecretKey::deserialize(&bytes).unwrap();
            assert_eq!(tsk, tsk_);
        }
    }

    #[test]
    fn test_serialization() {
        let mut rng = CsRng::from_entropy();
        let coordinate_1 = Coordinate::random(&mut rng);
        let coordinate_2 = Coordinate::random(&mut rng);
        let coordinate_3 = Coordinate::random(&mut rng);

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
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
        ]);

        let user_set = HashSet::from([coordinate_1.clone(), coordinate_3.clone()]);
        let target_set = HashSet::from([coordinate_1, coordinate_3]);
        let mut rng = CsRng::from_entropy();

        let mut msk = setup(&mut rng, MIN_TRACING_LEVEL + 2).unwrap();
        update_coordinate_keys(&mut rng, &mut msk, universe).unwrap();
        let mpk = mpk_keygen(&msk).unwrap();

        // Check Covercrypt `MasterSecretKey` serialization.
        {
            let bytes = msk.serialize().unwrap();
            assert_eq!(bytes.len(), msk.length(), "Wrong master secret key length");
            let msk_ = MasterSecretKey::deserialize(&bytes).unwrap();
            assert_eq!(msk, msk_, "Wrong `MasterSecretKey` deserialization.");
        }

        // Check Covercrypt `PublicKey` serialization.
        {
            let bytes = mpk.serialize().unwrap();
            assert_eq!(bytes.len(), mpk.length(), "Wrong master public key length");
            let mpk_ = MasterPublicKey::deserialize(&bytes).unwrap();
            assert_eq!(mpk, mpk_, "Wrong `PublicKey` derserialization.");
        }

        // Check Covercrypt `UserSecretKey` serialization.
        {
            let usk = usk_keygen(&mut rng, &mut msk, user_set).unwrap();
            let bytes = usk.serialize().unwrap();
            assert_eq!(bytes.len(), usk.length(), "Wrong user secret key size");
            let usk_ = UserSecretKey::deserialize(&bytes).unwrap();
            assert_eq!(usk, usk_, "Wrong `UserSecretKey` deserialization.");
        }

        // Check Covercrypt `Encapsulation` serialization.
        {
            let (_, encapsulation) = encaps(&mut rng, &mpk, &target_set).unwrap();
            let bytes = encapsulation.serialize().unwrap();
            assert_eq!(
                bytes.len(),
                encapsulation.length(),
                "Wrong encapsulation size"
            );
            let encapsulation_ = Encapsulation::deserialize(&bytes).unwrap();
            assert_eq!(
                encapsulation, encapsulation_,
                "Wrong `Encapsulation` serialization."
            );
        }

        // // Setup Covercrypt.
        // {
        //     use crate::{abe_policy::AccessPolicy, test_utils::policy, Covercrypt};

        //     let cc = Covercrypt::default();
        //     let policy = policy()?;
        //     let user_policy = AccessPolicy::from_boolean_expression(
        //         "Department::MKG && Security Level::Top Secret",
        //     )?;
        //     let encryption_policy = AccessPolicy::from_boolean_expression(
        //         "Department::MKG && Security Level::High Secret",
        //     )?;
        //     let (msk, mpk) = cc.generate_master_keys(&policy)?;
        //     let usk = cc.generate_user_secret_key(&msk, &user_policy, &policy)?;

        //     // Check `EncryptedHeader` serialization.
        //     let (_secret_key, encrypted_header) =
        //         EncryptedHeader::generate(&cc, &policy, &mpk, &encryption_policy, None, None)?;
        //     let bytes = encrypted_header.serialize()?;
        //     assert_eq!(
        //         bytes.len(),
        //         encrypted_header.length(),
        //         "Wrong encapsulation size."
        //     );
        //     let encrypted_header_ = EncryptedHeader::deserialize(&bytes)?;
        //     assert_eq!(
        //         encrypted_header, encrypted_header_,
        //         "Wrong `EncryptedHeader` derserialization."
        //     );

        //     // Check `CleartextHeader` serialization.
        //     let cleartext_header = encrypted_header.decrypt(&cc, &usk, None)?;
        //     let bytes = cleartext_header.serialize()?;
        //     assert_eq!(
        //         bytes.len(),
        //         cleartext_header.length(),
        //         "Wrong cleartext header size."
        //     );
        //     let cleartext_header_ = CleartextHeader::deserialize(&bytes)?;
        //     assert_eq!(
        //         cleartext_header, cleartext_header_,
        //         "Wrong `CleartextHeader` derserialization."
        //     );
        // }
    }
}
