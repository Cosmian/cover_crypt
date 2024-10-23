//! Implements the serialization methods for the `Covercrypt` objects.

use std::collections::{HashMap, HashSet, LinkedList};

use cosmian_crypto_core::{
    bytes_ser_de::{to_leb128_len, Deserializer, Serializable, Serializer},
    FixedSizeCBytes, R25519PrivateKey, R25519PublicKey, RandomFixedSizeCBytes, SymmetricKey,
};
use pqc_kyber::{KYBER_INDCPA_PUBLICKEYBYTES, KYBER_INDCPA_SECRETKEYBYTES};

use super::{KyberPublicKey, KyberSecretKey, KMAC_KEY_LENGTH, KMAC_LENGTH, TAG_LENGTH};
use crate::{
    abe_policy::Partition,
    core::{
        Encapsulation, KeyEncapsulation, MasterPublicKey, MasterSecretKey, UserSecretKey,
        SYM_KEY_LENGTH,
    },
    data_struct::{RevisionMap, RevisionVec},
    CleartextHeader, EncryptedHeader, Error,
};

/// Returns the byte length of a serialized option
macro_rules! serialize_len_option {
    ($option:expr, $value:ident, $method:expr) => {{
        let mut length = 1;
        if let Some($value) = &$option {
            length += $method;
        }
        length
    }};
}

/// Serialize an optional value as a LEB128-encoded unsigned integer followed by
/// the serialization of the contained value if any.
macro_rules! serialize_option {
    ($serializer:expr, $n:expr, $option:expr, $value:ident, $method:expr) => {{
        if let Some($value) = &$option {
            $n += $serializer.write_leb128_u64(1)?;
            $n += $method?;
        } else {
            $n += $serializer.write_leb128_u64(0)?;
        }
    }};
}

/// Deserialize an optional value from a LEB128-encoded unsigned integer
/// followed by the deserialization of the contained value if any.
macro_rules! deserialize_option {
    ($deserializer:expr, $method:expr) => {{
        let is_some = $deserializer.read_leb128_u64()?;
        if is_some == 1 {
            Some($method)
        } else {
            None
        }
    }};
}

impl Serializable for MasterPublicKey {
    type Error = Error;

    fn length(&self) -> usize {
        let mut length = 2 * R25519PublicKey::LENGTH
            // subkeys serialization
            + to_leb128_len(self.subkeys.len())
            + self.subkeys.len() * R25519PublicKey::LENGTH;
        for (partition, (pk_i, _)) in &self.subkeys {
            length += to_leb128_len(partition.len()) + partition.len();
            length += serialize_len_option!(pk_i, _value, KYBER_INDCPA_PUBLICKEYBYTES);
        }
        length
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(&self.g1.to_bytes())?;
        n += ser.write_array(&self.g2.to_bytes())?;
        n += ser.write_leb128_u64(self.subkeys.len() as u64)?;
        for (partition, (pk_i, h_i)) in &self.subkeys {
            n += ser.write_vec(partition)?;
            serialize_option!(ser, n, pk_i, value, ser.write_array(value));
            n += ser.write_array(&h_i.to_bytes())?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let g1 = R25519PublicKey::try_from_bytes(de.read_array::<{ R25519PublicKey::LENGTH }>()?)?;
        let g2 = R25519PublicKey::try_from_bytes(de.read_array::<{ R25519PublicKey::LENGTH }>()?)?;
        let n_partitions = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut subkeys = HashMap::with_capacity(n_partitions);
        let policy = MasterPublicKey::policy.read(de)?;
        for _ in 0..n_partitions {
            let partition = Partition::from(de.read_vec()?);
            let pk_i = deserialize_option!(de, KyberPublicKey(de.read_array()?));
            let h_i =
                R25519PublicKey::try_from_bytes(de.read_array::<{ R25519PublicKey::LENGTH }>()?)?;
            subkeys.insert(partition, (pk_i, h_i));
        }
        Ok(Self { g1, g2, subkeys, policy })
    }
}

impl Serializable for MasterSecretKey {
    type Error = Error;

    fn length(&self) -> usize {
        let mut length = 3 * R25519PrivateKey::LENGTH
            + self.kmac_key.as_ref().map_or_else(|| 0, |key| key.len())
            // subkeys serialization
            + to_leb128_len(self.subkeys.len())
            + self.subkeys.count_elements() * R25519PrivateKey::LENGTH;
        for (partition, chain) in &self.subkeys.map {
            length += to_leb128_len(partition.len()) + partition.len();
            length += to_leb128_len(chain.len());
            for (sk_i, _) in chain {
                let x = serialize_len_option!(sk_i, _value, KYBER_INDCPA_SECRETKEYBYTES);
                length += x;
            }
        }
        length
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(&self.s1.to_bytes())?;
        n += ser.write_array(&self.s2.to_bytes())?;
        n += ser.write_array(&self.s.to_bytes())?;
        n += ser.write_leb128_u64(self.subkeys.len() as u64)?;
        for (partition, chain) in &self.subkeys.map {
            n += ser.write_vec(partition)?;
            n += ser.write_leb128_u64(chain.len() as u64)?;
            for (sk_i, x_i) in chain {
                serialize_option!(ser, n, sk_i, value, ser.write_array(value));
                n += ser.write_array(&x_i.to_bytes())?;
            }
        }
        if let Some(kmac_key) = &self.kmac_key {
            n += ser.write_array(kmac_key)?;
        }

        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let s1 =
            R25519PrivateKey::try_from_bytes(de.read_array::<{ R25519PrivateKey::LENGTH }>()?)?;
        let s2 =
            R25519PrivateKey::try_from_bytes(de.read_array::<{ R25519PrivateKey::LENGTH }>()?)?;
        let s = R25519PrivateKey::try_from_bytes(de.read_array::<{ R25519PrivateKey::LENGTH }>()?)?;

        let n_partitions = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut subkeys = RevisionMap::with_capacity(n_partitions);
        let policy = MasterSecretKey::policy.read(de)?;
        for _ in 0..n_partitions {
            let partition = Partition::from(de.read_vec()?);
            let n_keys = <usize>::try_from(de.read_leb128_u64()?)?;
            let chain: Result<LinkedList<_>, Self::Error> = (0..n_keys)
                .map(|_| {
                    let sk_i = deserialize_option!(de, KyberSecretKey(de.read_array()?));
                    let x_i = de.read_array::<{ R25519PrivateKey::LENGTH }>()?;
                    Ok((sk_i, R25519PrivateKey::try_from_bytes(x_i)?))
                })
                .collect();
            subkeys.map.insert(partition, chain?);
        }

        let kmac_key = match de.read_array::<{ KMAC_KEY_LENGTH }>() {
            Ok(key_bytes) => Some(SymmetricKey::try_from_bytes(key_bytes)?),
            Err(_) => None,
        };

        Ok(Self {
            s,
            s1,
            s2,
            subkeys,
            kmac_key,
            policy,
        })
    }
}

impl Serializable for UserSecretKey {
    type Error = Error;

    fn length(&self) -> usize {
        let mut length = 2 * R25519PrivateKey::LENGTH
            + self.kmac.as_ref().map_or_else(|| 0, |kmac| kmac.len())
            // subkeys serialization
            + to_leb128_len(self.subkeys.len())
            + self.subkeys.count_elements() * R25519PrivateKey::LENGTH;
        for (partition, chain) in self.subkeys.iter() {
            length += to_leb128_len(partition.len()) + partition.len();
            length += to_leb128_len(chain.len());
            for (sk_i, _) in chain {
                length += serialize_len_option!(sk_i, _value, KYBER_INDCPA_SECRETKEYBYTES);
            }
        }
        length
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(&self.a.to_bytes())?;
        n += ser.write_array(&self.b.to_bytes())?;
        n += ser.write_leb128_u64(self.subkeys.len() as u64)?;
        for (partition, chain) in self.subkeys.iter() {
            // write chain partition
            n += ser.write_vec(partition)?;
            // iterate through all subkeys in the chain
            n += ser.write_leb128_u64(chain.len() as u64)?;
            for (sk_i, x_i) in chain {
                serialize_option!(ser, n, sk_i, value, ser.write_array(value));
                n += ser.write_array(&x_i.to_bytes())?;
            }
        }
        if let Some(kmac) = &self.kmac {
            n += ser.write_array(kmac)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let a = R25519PrivateKey::try_from_bytes(de.read_array::<{ R25519PrivateKey::LENGTH }>()?)?;
        let b = R25519PrivateKey::try_from_bytes(de.read_array::<{ R25519PrivateKey::LENGTH }>()?)?;
        let n_partitions = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut subkeys = RevisionVec::with_capacity(n_partitions);
        for _ in 0..n_partitions {
            let partition = Partition::from(de.read_vec()?);
            // read all keys forming a chain and inserting them all at once.
            let n_keys = <usize>::try_from(de.read_leb128_u64()?)?;
            let new_chain: Result<LinkedList<_>, _> = (0..n_keys)
                .map(|_| {
                    let sk_i = deserialize_option!(de, KyberSecretKey(de.read_array()?));
                    let x_i = de.read_array::<{ R25519PrivateKey::LENGTH }>()?;
                    Ok::<_, Self::Error>((sk_i, R25519PrivateKey::try_from_bytes(x_i)?))
                })
                .collect();
            subkeys.insert_new_chain(partition, new_chain?);
        }
        let kmac = de.read_array::<{ KMAC_LENGTH }>().ok();

        Ok(Self {
            a,
            b,
            subkeys,
            kmac,
        })
    }
}

impl Serializable for KeyEncapsulation {
    type Error = Error;

    fn length(&self) -> usize {
        match self {
            Self::ClassicEncapsulation(e_i) => 1 + e_i.len(),
            Self::HybridEncapsulation(epq_i) => 1 + epq_i.len(),
        }
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = 0;
        match self {
            Self::ClassicEncapsulation(e_i) => {
                n += ser.write_leb128_u64(0)?;
                n += ser.write_array(&**e_i)?;
            }
            Self::HybridEncapsulation(epq_i) => {
                n += ser.write_leb128_u64(1)?;
                n += ser.write_array(&**epq_i)?;
            }
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let is_hybridized = de.read_leb128_u64()?;
        if is_hybridized == 1 {
            Ok(Self::HybridEncapsulation(Box::new(de.read_array()?)))
        } else {
            Ok(Self::ClassicEncapsulation(Box::new(de.read_array()?)))
        }
    }
}

impl Serializable for Encapsulation {
    type Error = Error;

    fn length(&self) -> usize {
        let mut length = 2 * R25519PublicKey::LENGTH + TAG_LENGTH + to_leb128_len(self.encs.len());
        for key_encasulation in &self.encs {
            length += key_encasulation.length();
        }
        length
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(&self.c1.to_bytes())?;
        n += ser.write_array(&self.c2.to_bytes())?;
        n += ser.write_array(&self.tag)?;
        n += ser.write_leb128_u64(self.encs.len() as u64)?;
        for key_encapsulation in &self.encs {
            n += ser.write(key_encapsulation)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let c1 = R25519PublicKey::try_from_bytes(de.read_array::<{ R25519PublicKey::LENGTH }>()?)?;
        let c2 = R25519PublicKey::try_from_bytes(de.read_array::<{ R25519PublicKey::LENGTH }>()?)?;
        let tag = de.read_array()?;
        let n_partitions = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut encs = HashSet::with_capacity(n_partitions);
        for _ in 0..n_partitions {
            let key_encapsulation = de.read()?;
            encs.insert(key_encapsulation);
        }
        Ok(Self { c1, c2, tag, encs })
    }
}

impl Serializable for EncryptedHeader {
    type Error = Error;

    fn length(&self) -> usize {
        self.encapsulation.length()
            + to_leb128_len(
                self.encrypted_metadata
                    .as_ref()
                    .map(std::vec::Vec::len)
                    .unwrap_or_default(),
            )
            + self
                .encrypted_metadata
                .as_ref()
                .map(std::vec::Vec::len)
                .unwrap_or_default()
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
        SYM_KEY_LENGTH
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
        let symmetric_key = SymmetricKey::try_from_bytes(de.read_array::<SYM_KEY_LENGTH>()?)?;
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
        core::primitives::{encaps, keygen, setup},
    };

    #[test]
    fn test_serialization() -> Result<(), Error> {
        // Setup
        let admin_partition = Partition(b"admin".to_vec());
        let dev_partition = Partition(b"dev".to_vec());
        let partitions_set = HashMap::from([
            (
                admin_partition.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
            (
                dev_partition.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
        ]);
        let user_set = HashSet::from([admin_partition.clone(), dev_partition.clone()]);
        let target_set = HashSet::from([admin_partition, dev_partition]);
        let mut rng = CsRng::from_entropy();

        let (msk, mpk) = setup(&mut rng, partitions_set);

        // Check Covercrypt `MasterSecretKey` serialization.
        let bytes = msk.serialize()?;
        assert_eq!(bytes.len(), msk.length(), "Wrong master secret key length");
        let msk_ = MasterSecretKey::deserialize(&bytes)?;
        assert_eq!(msk, msk_, "Wrong `MasterSecretKey` deserialization.");
        assert!(
            msk_.kmac_key.is_some(),
            "Wrong `MasterSecretKey` deserialization."
        );
        assert_eq!(
            msk.kmac_key, msk_.kmac_key,
            "Wrong `MasterSecretKey` deserialization."
        );

        // Check Covercrypt `PublicKey` serialization.
        let bytes = mpk.serialize()?;
        assert_eq!(bytes.len(), mpk.length(), "Wrong master public key length");
        let mpk_ = MasterPublicKey::deserialize(&bytes)?;
        assert_eq!(mpk, mpk_, "Wrong `PublicKey` derserialization.");

        // Check Covercrypt `UserSecretKey` serialization.
        let usk = keygen(&mut rng, &msk, &user_set)?;
        let bytes = usk.serialize()?;
        assert_eq!(bytes.len(), usk.length(), "Wrong user secret key size");
        let usk_ = UserSecretKey::deserialize(&bytes)?;
        assert_eq!(usk.a, usk_.a, "Wrong `UserSecretKey` deserialization.");
        assert_eq!(usk.b, usk_.b, "Wrong `UserSecretKey` deserialization.");
        assert_eq!(
            usk.kmac, usk_.kmac,
            "Wrong `UserSecretKey` deserialization."
        );
        assert_eq!(usk, usk_, "Wrong `UserSecretKey` deserialization.");

        // Check Covercrypt `Encapsulation` serialization.
        let (_, encapsulation) = encaps(&mut rng, &mpk, &target_set)?;
        let bytes = encapsulation.serialize()?;
        assert_eq!(
            bytes.len(),
            encapsulation.length(),
            "Wrong encapsulation size"
        );
        let encapsulation_ = Encapsulation::deserialize(&bytes)?;
        assert_eq!(
            encapsulation, encapsulation_,
            "Wrong `Encapsulation` derserialization."
        );

        // Setup Covercrypt.
        #[cfg(feature = "test_utils")]
        {
            use crate::{abe_policy::AccessPolicy, test_utils::policy, Covercrypt};

            let cc = Covercrypt::default();
            let policy = policy()?;
            let user_policy = AccessPolicy::from_boolean_expression(
                "Department::MKG && Security Level::Top Secret",
            )?;
            let encryption_policy = AccessPolicy::from_boolean_expression(
                "Department::MKG && Security Level::High Secret",
            )?;
            let (msk, mpk) = cc.generate_master_keys(&policy)?;
            let usk = cc.generate_user_secret_key(&msk, &user_policy)?;

            // Check `EncryptedHeader` serialization.
            let (_secret_key, encrypted_header) =
                EncryptedHeader::generate(&cc, &mpk, &encryption_policy, None, None)?;
            let bytes = encrypted_header.serialize()?;
            assert_eq!(
                bytes.len(),
                encrypted_header.length(),
                "Wrong encapsulation size."
            );
            let encrypted_header_ = EncryptedHeader::deserialize(&bytes)?;
            assert_eq!(
                encrypted_header, encrypted_header_,
                "Wrong `EncryptedHeader` derserialization."
            );

            // Check `CleartextHeader` serialization.
            let cleartext_header = encrypted_header.decrypt(&cc, &usk, None)?;
            let bytes = cleartext_header.serialize()?;
            assert_eq!(
                bytes.len(),
                cleartext_header.length(),
                "Wrong cleartext header size."
            );
            let cleartext_header_ = CleartextHeader::deserialize(&bytes)?;
            assert_eq!(
                cleartext_header, cleartext_header_,
                "Wrong `CleartextHeader` derserialization."
            );
        }

        Ok(())
    }
}
