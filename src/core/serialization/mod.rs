//! Implements the serialization methods for the `Covercrypt` objects.

use std::collections::{HashMap, HashSet, LinkedList};

use cosmian_crypto_core::{
    bytes_ser_de::{to_leb128_len, Deserializer, Serializable, Serializer},
    FixedSizeCBytes, Secret, SymmetricKey,
};

use super::{
    elgamal::{EcPoint, Scalar},
    CoordinatePublicKey, CoordinateSecretKey, TracingPublicKey, TracingSecretKey, UserId,
    SIGNATURE_LENGTH, SIGNING_KEY_LENGTH, TAG_LENGTH,
};
use crate::{
    abe_policy::{Coordinate, Policy},
    core::{
        CleartextHeader, Encapsulation, EncryptedHeader, MasterPublicKey, MasterSecretKey,
        SeedEncapsulation, UserSecretKey, SEED_LENGTH,
    },
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
        1 + self.el.length()
            + self
                .pq
                .as_ref()
                .map(Serializable::length)
                .unwrap_or_default()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_leb128_u64(self.is_hybridized().into())?;
        n += ser.write_array(&self.el.to_bytes())?;
        if let Some(k) = &self.pq {
            n += ser.write(k)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let is_hybridized = de.read_leb128_u64()?;
        let el = de.read()?;
        let pq = if 1 == is_hybridized {
            Some(de.read()?)
        } else if 0 == is_hybridized {
            None
        } else {
            return Err(Error::ConversionFailed(format!(
                "invalid hybridization flag {is_hybridized}"
            )));
        };
        Ok(Self { el, pq })
    }
}

impl Serializable for MasterPublicKey {
    type Error = Error;

    fn length(&self) -> usize {
        self.tpk.length()
            + to_leb128_len(self.coordinate_keys.len())
            + self
                .coordinate_keys
                .iter()
                .map(|(coordinate, pk)| coordinate.length() + pk.length())
                .sum::<usize>()
            + self.policy.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write(&self.tpk)?;
        n += ser.write_leb128_u64(self.coordinate_keys.len() as u64)?;
        for (coordinate, pk) in &self.coordinate_keys {
            n += ser.write(coordinate)?;
            n += ser.write(pk)?;
        }
        n += ser.write(&self.policy)?;
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let tpk = de.read::<TracingPublicKey>()?;
        let n_coordinates = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut coordinate_keys = HashMap::with_capacity(n_coordinates);
        for _ in 0..n_coordinates {
            let coordinate = de.read::<Coordinate>()?;
            let pk = de.read::<CoordinatePublicKey>()?;
            coordinate_keys.insert(coordinate, pk);
        }
        let policy = de.read::<Policy>()?;
        Ok(Self {
            tpk,
            coordinate_keys,
            policy,
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

impl Serializable for MasterSecretKey {
    type Error = Error;

    fn length(&self) -> usize {
        self.s.length()
            + self.tsk.length()
            + to_leb128_len(self.coordinate_secrets.len())
            + self
                .coordinate_secrets
                .iter()
                .map(|(coordinate, chain)| {
                    coordinate.length()
                        + to_leb128_len(chain.len())
                        + chain.iter().map(|(_, k)| 1 + k.length()).sum::<usize>()
                })
                .sum::<usize>()
            + self.signing_key.as_ref().map_or_else(|| 0, |key| key.len())
            + self.policy.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write(&self.s)?;
        n += ser.write(&self.tsk)?;
        n += ser.write_leb128_u64(self.coordinate_secrets.len() as u64)?;
        for (coordinate, chain) in &self.coordinate_secrets.map {
            n += ser.write(coordinate)?;
            n += ser.write_leb128_u64(to_leb128_len(chain.len()) as u64)?;
            for (is_activated, sk) in chain {
                n += ser.write_leb128_u64((*is_activated).into())?;
                n += ser.write(sk)?;
            }
        }
        if let Some(kmac_key) = &self.signing_key {
            n += ser.write_array(kmac_key)?;
        }
        n += ser.write(&self.policy)?;
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let s = Scalar::try_from_bytes(de.read_array::<{ Scalar::LENGTH }>()?)?;
        let tsk = de.read::<TracingSecretKey>()?;
        let n_coordinates = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut coordinate_keypairs = RevisionMap::with_capacity(n_coordinates);
        for _ in 0..n_coordinates {
            let coordinate = de.read()?;
            let n_keys = <usize>::try_from(de.read_leb128_u64()?)?;
            let chain = (0..n_keys)
                .map(|_| -> Result<_, Error> {
                    let is_activated = de.read_leb128_u64()? == 1;
                    let sk = de.read::<CoordinateSecretKey>()?;
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

        let policy = de.read()?;

        Ok(Self {
            s,
            tsk,
            coordinate_secrets: coordinate_keypairs,
            signing_key,
            policy,
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
        1 + self.el.length()
            + self
                .pq
                .as_ref()
                .map(Serializable::length)
                .unwrap_or_default()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_leb128_u64(self.is_hybridized().into())?;
        n += ser.write(&self.el)?;
        if let Some(k) = &self.pq {
            n += ser.write(k)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let is_hybridized = de.read_leb128_u64()?;
        let el = de.read()?;
        let pq = if 1 == is_hybridized {
            Some(de.read()?)
        } else if 0 == is_hybridized {
            None
        } else {
            return Err(Error::ConversionFailed(format!(
                "invalid hybridization flag {is_hybridized}"
            )));
        };
        Ok(Self { el, pq })
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
        let msk_signature = if de.value().len() < SIGNATURE_LENGTH {
            None
        } else {
            Some(de.read_array::<SIGNATURE_LENGTH>()?)
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
            Self::Hybridized(enc) => to_leb128_len(enc.len()) + enc.len(),
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
                n += ser.write_vec(enc)?;
            }
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let is_hybridized = de.read_leb128_u64()?;
        if is_hybridized == 1 {
            de.read_vec().map(Self::Hybridized).map_err(Error::from)
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
        let mut coordinate_encapsulations = Vec::with_capacity(n_encapsulations);
        for _ in 0..n_encapsulations {
            let enc = de.read::<SeedEncapsulation>()?;
            coordinate_encapsulations.push(enc);
        }
        Ok(Self {
            tag,
            traps,
            coordinate_encapsulations,
        })
    }
}

impl Serializable for EncryptedHeader {
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
        let mut n = ser.write_array(&self.seed[..SEED_LENGTH])?;
        match &self.metadata {
            Some(bytes) => n += ser.write_vec(bytes)?,
            None => n += ser.write_vec(&[])?,
        }
        Ok(n)
    }

    /// Tries to deserialize the cleartext header.
    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let seed = Secret::from_unprotected_bytes(&mut de.read_array::<SEED_LENGTH>()?);
        let metadata = de.read_vec()?;
        let metadata = if metadata.is_empty() {
            None
        } else {
            Some(metadata)
        };
        Ok(Self { seed, metadata })
    }
}

impl Serializable for Policy {
    type Error = Error;

    fn length(&self) -> usize {
        to_leb128_len(self.version.clone() as usize)
            + to_leb128_len(self.last_attribute_value.try_into().unwrap())
            + self
                .dimensions
                .iter()
                .map(|(s, dim)| {
                    to_leb128_len(s.len())
                        + dim.attributes().into_iter().map(|d| {
                            d.len()
                        })
                        .sum::<usize>()
                })
                .sum::<usize>()
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        let n = Vec::<u8>::try_from(self);
        Ok(ser.write_vec(&n? as &[u8])?)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let n = de.read::<Policy>()?;
        Ok(n)
    }
}

#[cfg(test)]

mod tests {
    use super::*;
    use crate::{
        abe_policy::{AttributeStatus, EncryptionHint},
        core::{
            postquantum::{MlKemAesPke, PkeTrait},
            primitives::{encaps, setup, update_coordinate_keys, usk_keygen},
            MIN_TRACING_LEVEL,
        },
    };
    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};
    use std::collections::HashMap;

    #[test]
    fn test_coordinate_pk() {
        let mut rng = CsRng::from_entropy();

        {
            let elgamal_pk = EcPoint::from(&Scalar::new(&mut rng));
            let cpk = CoordinatePublicKey {
                el: elgamal_pk,
                pq: None,
            };
            let bytes = cpk.serialize().unwrap();
            assert_eq!(bytes.len(), cpk.length());
            let cpk_ = CoordinatePublicKey::deserialize(&bytes).unwrap();
            assert_eq!(cpk, cpk_);
        }

        {
            let elgamal_pk = EcPoint::from(&Scalar::new(&mut rng));
            let (_, postquantum_pk) = MlKemAesPke.keygen(&mut rng).unwrap();
            let cpk = CoordinatePublicKey {
                pq: Some(postquantum_pk),
                el: elgamal_pk,
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
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
        ]);

        let user_set = HashSet::from([coordinate_1.clone(), coordinate_3.clone()]);
        let target_set = HashSet::from([coordinate_1, coordinate_3]);
        let mut rng = CsRng::from_entropy();

        let mut msk = setup(&mut rng, MIN_TRACING_LEVEL + 2).unwrap();
        update_coordinate_keys(&mut rng, &mut msk, universe).unwrap();
        let mpk = msk.mpk().unwrap();

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
