//! Implements the serialization methods for the CoverCrypt objects.

use crate::{
    core::{
        partitions::Partition, Encapsulation, KeyEncapsulation, MasterSecretKey, PublicKey,
        UserSecretKey,
    },
    CleartextHeader, CoverCrypt, EncryptedHeader, Error,
};
use cosmian_crypto_core::{
    asymmetric_crypto::DhKeyPair,
    bytes_ser_de::{to_leb128_len, Deserializer, Serializable, Serializer},
    symmetric_crypto::{Dem, SymKey},
    KeyTrait,
};
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    ops::{Add, Div, Mul, Sub},
};

impl<const PUBLIC_KEY_LENGTH: usize, DhPublicKey: KeyTrait<PUBLIC_KEY_LENGTH>> Serializable
    for PublicKey<PUBLIC_KEY_LENGTH, DhPublicKey>
{
    type Error = Error;

    #[inline]
    fn length(&self) -> usize {
        let mut length =
            2 * PUBLIC_KEY_LENGTH + to_leb128_len(self.H.len()) + self.H.len() * PUBLIC_KEY_LENGTH;
        for (partition, (pk_i, _)) in &self.H {
            length += (to_leb128_len(partition.len()) + partition.len())
                + (1 + pk_i.map(|v| v.len()).unwrap_or_default());
        }
        length
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(&self.U.to_bytes())?;
        n += ser.write_array(&self.V.to_bytes())?;
        n += ser.write_u64(self.H.len() as u64)?;
        for (partition, (pk_i, H_i)) in &self.H {
            n += ser.write_vec(partition)?;
            if let Some(pk_i) = pk_i {
                n += ser.write_u64(1)?;
                n += ser.write_array(pk_i)?;
            } else {
                n += ser.write_u64(0)?;
            }
            n += ser.write_array(&H_i.to_bytes())?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let U = DhPublicKey::try_from_bytes(&de.read_array::<PUBLIC_KEY_LENGTH>()?)?;
        let V = DhPublicKey::try_from_bytes(&de.read_array::<PUBLIC_KEY_LENGTH>()?)?;
        let H_len = <usize>::try_from(de.read_u64()?)?;
        let mut H = HashMap::with_capacity(H_len);
        for _ in 0..H_len {
            let partition = de.read_vec()?;
            let is_hybridized = de.read_u64()?;
            let pk_i = if is_hybridized == 1 {
                Some(de.read_array()?)
            } else {
                None
            };
            let H_i = de.read_array::<PUBLIC_KEY_LENGTH>()?;
            H.insert(
                Partition::from(partition),
                (pk_i, DhPublicKey::try_from_bytes(&H_i)?),
            );
        }
        Ok(Self { U, V, H })
    }
}

impl<const PRIVATE_KEY_LENGTH: usize, DhPrivateKey: KeyTrait<PRIVATE_KEY_LENGTH>> Serializable
    for MasterSecretKey<PRIVATE_KEY_LENGTH, DhPrivateKey>
{
    type Error = Error;

    #[inline]
    fn length(&self) -> usize {
        let mut length = 3 * PRIVATE_KEY_LENGTH
            + to_leb128_len(self.x.len())
            + self.x.len() * PRIVATE_KEY_LENGTH;
        for (partition, (sk_i, _)) in &self.x {
            length += (to_leb128_len(partition.len()) + partition.len())
                + (1 + sk_i.map(|v| v.len()).unwrap_or_default());
        }
        length
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(&self.u.to_bytes())?;
        n += ser.write_array(&self.v.to_bytes())?;
        n += ser.write_array(&self.s.to_bytes())?;
        n += ser.write_u64(self.x.len() as u64)?;
        for (partition, (sk_i, x_i)) in &self.x {
            n += ser.write_vec(partition)?;
            if let Some(sk_i) = sk_i {
                n += ser.write_u64(1)?;
                n += ser.write_array(sk_i)?;
            } else {
                n += ser.write_u64(0)?;
            }
            n += ser.write_array(&x_i.to_bytes())?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let u = DhPrivateKey::try_from_bytes(&de.read_array::<PRIVATE_KEY_LENGTH>()?)?;
        let v = DhPrivateKey::try_from_bytes(&de.read_array::<PRIVATE_KEY_LENGTH>()?)?;
        let s = DhPrivateKey::try_from_bytes(&de.read_array::<PRIVATE_KEY_LENGTH>()?)?;
        let x_len = <usize>::try_from(de.read_u64()?)?;
        let mut x = HashMap::with_capacity(x_len);
        for _ in 0..x_len {
            let partition = de.read_vec()?;
            let is_hybridized = de.read_u64()?;
            let sk_i = if is_hybridized == 1 {
                Some(de.read_array()?)
            } else {
                None
            };
            let x_i = de.read_array::<PRIVATE_KEY_LENGTH>()?;
            x.insert(
                Partition::from(partition),
                (sk_i, DhPrivateKey::try_from_bytes(&x_i)?),
            );
        }
        Ok(Self { u, v, s, x })
    }
}

impl<const PRIVATE_KEY_LENGTH: usize, DhPrivateKey: KeyTrait<PRIVATE_KEY_LENGTH> + Hash>
    Serializable for UserSecretKey<PRIVATE_KEY_LENGTH, DhPrivateKey>
{
    type Error = Error;

    #[inline]
    fn length(&self) -> usize {
        let mut length = 2 * PRIVATE_KEY_LENGTH
            + to_leb128_len(self.x.len())
            + self.x.len() * PRIVATE_KEY_LENGTH;
        for (sk_i, _) in &self.x {
            length += 1 + sk_i.map(|v| v.len()).unwrap_or_default();
        }
        length
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(&self.a.to_bytes())?;
        n += ser.write_array(&self.b.to_bytes())?;
        n += ser.write_u64(self.x.len() as u64)?;
        for (sk_i, x_i) in &self.x {
            if let Some(sk_i) = sk_i {
                n += ser.write_u64(1)?;
                n += ser.write_array(sk_i)?;
            } else {
                n += ser.write_u64(0)?;
            }
            n += ser.write_array(&x_i.to_bytes())?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let a = DhPrivateKey::try_from_bytes(&de.read_array::<PRIVATE_KEY_LENGTH>()?)?;
        let b = DhPrivateKey::try_from_bytes(&de.read_array::<PRIVATE_KEY_LENGTH>()?)?;
        let x_len = <usize>::try_from(de.read_u64()?)?;
        let mut x = HashSet::with_capacity(x_len);
        for _ in 0..x_len {
            let is_hybridized = de.read_u64()?;
            let sk_i = if is_hybridized == 1 {
                Some(de.read_array()?)
            } else {
                None
            };
            let x_i = de.read_array::<PRIVATE_KEY_LENGTH>()?;
            x.insert((sk_i, DhPrivateKey::try_from_bytes(&x_i)?));
        }
        Ok(Self { a, b, x })
    }
}

impl<const SYM_KEY_LENGTH: usize> Serializable for KeyEncapsulation<SYM_KEY_LENGTH> {
    type Error = Error;

    fn length(&self) -> usize {
        match self {
            Self::ClassicEncapsulation(E_i) => 1 + E_i.len(),
            Self::HybridEncapsulation(EPQ_i) => 1 + EPQ_i.len(),
        }
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = 0;
        match self {
            Self::ClassicEncapsulation(E_i) => {
                n += ser.write_u64(0)?;
                n += ser.write_array(&**E_i)?;
            }
            Self::HybridEncapsulation(EPQ_i) => {
                n += ser.write_u64(1)?;
                n += ser.write_array(&**EPQ_i)?;
            }
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let is_hybridized = de.read_u64()?;
        if is_hybridized == 1 {
            Ok(Self::HybridEncapsulation(Box::new(de.read_array()?)))
        } else {
            Ok(Self::ClassicEncapsulation(Box::new(de.read_array()?)))
        }
    }
}

impl<
        const TAG_LENGTH: usize,
        const ENCAPSULATION_LENGTH: usize,
        const PUBLIC_KEY_LENGTH: usize,
        DhPublicKey: KeyTrait<PUBLIC_KEY_LENGTH>,
    > Serializable
    for Encapsulation<TAG_LENGTH, ENCAPSULATION_LENGTH, PUBLIC_KEY_LENGTH, DhPublicKey>
{
    type Error = Error;

    #[inline]
    fn length(&self) -> usize {
        let mut length = 2 * PUBLIC_KEY_LENGTH + TAG_LENGTH + to_leb128_len(self.E.len());
        for key_encasulation in &self.E {
            length += key_encasulation.length();
        }
        length
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(&self.C.to_bytes())?;
        n += ser.write_array(&self.D.to_bytes())?;
        n += ser.write_array(&self.tag)?;
        n += ser.write_u64(self.E.len() as u64)?;
        for key_encapsulation in &self.E {
            n += ser.write(key_encapsulation)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let C = DhPublicKey::try_from_bytes(&de.read_array::<PUBLIC_KEY_LENGTH>()?)?;
        let D = DhPublicKey::try_from_bytes(&de.read_array::<PUBLIC_KEY_LENGTH>()?)?;
        let tag = de.read_array()?;
        let E_len = <usize>::try_from(de.read_u64()?)?;
        let mut E = HashSet::with_capacity(E_len);
        for _ in 0..E_len {
            let key_encapsulation = de.read()?;
            E.insert(key_encapsulation);
        }
        Ok(Self { C, D, tag, E })
    }
}

impl<
        const TAG_LENGTH: usize,
        const SYM_KEY_LENGTH: usize,
        const PK_LENGTH: usize,
        const SK_LENGTH: usize,
        KeyPair,
        DEM,
        CoverCryptScheme,
    > Serializable
    for EncryptedHeader<
        TAG_LENGTH,
        SYM_KEY_LENGTH,
        PK_LENGTH,
        SK_LENGTH,
        KeyPair,
        DEM,
        CoverCryptScheme,
    >
where
    KeyPair: DhKeyPair<PK_LENGTH, SK_LENGTH>,
    DEM: Dem<SYM_KEY_LENGTH>,
    KeyPair::PublicKey: From<KeyPair::PrivateKey>,
    for<'a, 'b> &'a KeyPair::PublicKey: Add<&'b KeyPair::PublicKey, Output = KeyPair::PublicKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PublicKey>,
    for<'a, 'b> &'a KeyPair::PrivateKey: Add<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Sub<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Div<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>,
    CoverCryptScheme: CoverCrypt<TAG_LENGTH, SYM_KEY_LENGTH, PK_LENGTH, SK_LENGTH, KeyPair, DEM>,
{
    type Error = Error;

    #[inline]
    fn length(&self) -> usize {
        self.encapsulation.length() + to_leb128_len(self.ciphertext.len()) + self.ciphertext.len()
    }

    /// Tries to serialize the encrypted header.
    #[inline]
    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = self.encapsulation.write(ser)?;
        n += ser.write_vec(self.ciphertext.as_slice())?;
        Ok(n)
    }

    /// Tries to deserialize the encrypted header.
    #[inline]
    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let encapsulation = de.read::<CoverCryptScheme::Encapsulation>()?;
        let ciphertext = de.read_vec()?;
        Ok(Self {
            encapsulation,
            ciphertext,
        })
    }
}

impl<const KEY_LENGTH: usize, DEM> Serializable for CleartextHeader<KEY_LENGTH, DEM>
where
    DEM: Dem<KEY_LENGTH>,
{
    type Error = Error;

    #[inline]
    fn length(&self) -> usize {
        KEY_LENGTH + to_leb128_len(self.header_metadata.len()) + self.header_metadata.len()
    }

    /// Tries to serialize the cleartext header.
    #[inline]
    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(self.symmetric_key.as_bytes())?;
        n += ser.write_vec(&self.header_metadata)?;
        Ok(n)
    }

    /// Tries to deserialize the cleartext header.
    #[inline]
    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let symmetric_key = DEM::Key::from_bytes(de.read_array::<KEY_LENGTH>()?);
        let header_metadata = de.read_vec()?;
        Ok(Self {
            symmetric_key,
            header_metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::statics::CoverCryptX25519Aes256;

    use super::*;
    use abe_policy::{AccessPolicy, Policy, PolicyAxis};
    use cosmian_crypto_core::{
        asymmetric_crypto::curve25519::X25519KeyPair, reexport::rand_core::SeedableRng,
        symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto, CsRng,
    };

    const TAG_LENGTH: usize = 32;
    const SYM_KEY_LENGTH: usize = 32;
    type KeyPair = X25519KeyPair;
    #[allow(clippy::upper_case_acronyms)]
    type DEM = Aes256GcmCrypto;

    fn policy() -> Result<Policy, Error> {
        let sec_level = PolicyAxis::new(
            "Security Level",
            &[
                "Protected",
                "Low Secret",
                "Medium Secret",
                "High Secret",
                "Top Secret",
            ],
            true,
        );
        let department = PolicyAxis::new("Department", &["R&D", "HR", "MKG", "FIN"], false);
        let mut policy = Policy::new(100);
        policy.add_axis(&sec_level)?;
        policy.add_axis(&department)?;
        Ok(policy)
    }

    #[test]
    fn test_serialization() -> Result<(), Error> {
        // Setup
        let admin_partition = Partition(b"admin".to_vec());
        let dev_partition = Partition(b"dev".to_vec());
        let partitions_set = HashMap::from([
            (admin_partition.clone(), true),
            (dev_partition.clone(), false),
        ]);
        let user_set = HashSet::from([admin_partition.clone(), dev_partition.clone()]);
        let target_set = HashSet::from([admin_partition, dev_partition]);
        let mut rng = CsRng::from_entropy();

        let (msk, mpk) = setup!(&mut rng, &partitions_set);

        // Check CoverCrypt `MasterSecretKey` serialization.
        let bytes = msk.try_to_bytes()?;
        assert_eq!(bytes.len(), msk.length(), "Wrong master secret key length");
        let msk_ = MasterSecretKey::try_from_bytes(&bytes)?;
        assert_eq!(msk, msk_, "Wrong `MasterSecretKey` derserialization.");

        // Check CoverCrypt `PublicKey` serialization.
        let bytes = mpk.try_to_bytes()?;
        assert_eq!(bytes.len(), mpk.length(), "Wrong master public key length");
        let mpk_ = PublicKey::try_from_bytes(&bytes)?;
        assert_eq!(mpk, mpk_, "Wrong `PublicKey` derserialization.");

        // Check CoverCrypt `UserSecretKey` serialization.
        let usk = join!(&mut rng, &msk, &user_set)?;
        let bytes = usk.try_to_bytes()?;
        assert_eq!(bytes.len(), usk.length(), "Wrong user secret key size");
        let usk_ = UserSecretKey::try_from_bytes(&bytes)?;
        assert_eq!(usk, usk_, "Wrong `UserSecretKey` derserialization.");

        // Check CoverCrypt `Encapsulation` serialization.
        let (_, encapsulation) = encaps!(&mut rng, &mpk, &target_set)?;
        let bytes = encapsulation.try_to_bytes()?;
        assert_eq!(
            bytes.len(),
            encapsulation.length(),
            "Wrong encapsulation size"
        );
        let encapsulation_ = Encapsulation::try_from_bytes(&bytes)?;
        assert_eq!(
            encapsulation, encapsulation_,
            "Wrong `Encapsulation` derserialization."
        );

        // Setup CoverCrypt.
        let cc = CoverCryptX25519Aes256::default();
        let policy = policy()?;
        let user_policy =
            AccessPolicy::from_boolean_expression("Department::MKG && Security Level::Top Secret")?;
        let encryption_policy = AccessPolicy::from_boolean_expression(
            "Department::MKG && Security Level::Medium Secret",
        )?;
        let (msk, mpk) = cc.generate_master_keys(&policy)?;
        let usk = cc.generate_user_secret_key(&msk, &user_policy, &policy)?;

        // Check `EncryptedHeader` serialization.
        let (_secret_key, encrypted_header) =
            EncryptedHeader::generate(&cc, &policy, &mpk, &encryption_policy, None, None)?;
        let bytes = encrypted_header.try_to_bytes()?;
        assert_eq!(
            bytes.len(),
            encrypted_header.length(),
            "Wrong encapsulation size."
        );
        let encrypted_header_ = EncryptedHeader::try_from_bytes(&bytes)?;
        assert_eq!(
            encrypted_header, encrypted_header_,
            "Wrong `EncryptedHeader` derserialization."
        );

        // Check `CleartextHeader` serialization.
        let cleartext_header = encrypted_header.decrypt(&cc, &usk, None)?;
        let bytes = cleartext_header.try_to_bytes()?;
        assert_eq!(
            bytes.len(),
            cleartext_header.length(),
            "Wrong cleartext header size."
        );
        let cleartext_header_ = CleartextHeader::try_from_bytes(&bytes)?;
        assert_eq!(
            cleartext_header, cleartext_header_,
            "Wrong `CleartextHeader` derserialization."
        );

        Ok(())
    }
}
