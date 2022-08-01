// Needed to use the paper naming conventions
#![allow(non_snake_case)]

use crate::{
    bytes_ser_de::{Deserializer, Serializer},
    error::Error,
};
use cosmian_crypto_core::{
    asymmetric_crypto::{X25519PrivateKey, X25519PublicKey},
    kdf::hkdf_256,
    KeyTrait,
};
use rand_core::{CryptoRng, RngCore};
use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
    ops::Deref,
};
use zeroize::Zeroize;

/// Additional information to generate symmetric key using the KDF.
const KEY_GEN_INFO: &str = "key generation info";

/// Partition associated to a subset. It corresponds to a combination
/// of attributes across all axes.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct Partition(Vec<u8>);

impl Partition {
    /// Create a Partition from the list of the attribute values
    /// which constitutes the "coordinates" of the partitions
    /// across all axes of the policy
    ///
    /// The attribute values MUST be unique across all axes
    pub fn from_attributes(mut attribute_values: Vec<u32>) -> Result<Self, Error> {
        // guard against overflow of the 1024 bytes buffer below
        if attribute_values.len() > 200 {
            return Err(Error::InvalidAttribute(
                "The current implementation does not currently support more than 200 attributes \
                 for a partition"
                    .to_string(),
            ));
        }
        // the sort operation allows to get the same hash for :
        // `Department::HR || Level::Secret`
        // and
        // `Level::Secret || Department::HR`
        attribute_values.sort_unstable();
        let mut buf = [0; 1024];
        let mut writable = &mut buf[..];

        let mut len = 0;
        for value in attribute_values {
            len += leb128::write::unsigned(&mut writable, value as u64)
                .map_err(|e| Error::Other(format!("Unexpected LEB128 write issue: {}", e)))?;
        }
        Ok(Self(buf[0..len].to_vec()))
    }
}

impl Deref for Partition {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for Partition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl From<Partition> for String {
    fn from(a: Partition) -> Self {
        format!("{a}")
    }
}

impl From<Vec<u8>> for Partition {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for Partition {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl From<Partition> for Vec<u8> {
    fn from(p: Partition) -> Self {
        p.0
    }
}

impl From<&Partition> for Vec<u8> {
    fn from(p: &Partition) -> Self {
        p.0.clone()
    }
}

/// CoverCrypt master private key.
///
/// It is composed of `u`, `v` and `s`, three randomly chosen scalars,
/// and the scalars `x_i` associated to all subsets `S_i`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterPrivateKey {
    u: X25519PrivateKey,
    v: X25519PrivateKey,
    s: X25519PrivateKey,
    pub(crate) x: HashMap<Partition, X25519PrivateKey>,
}

impl MasterPrivateKey {
    /// Serialize the master private key.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut serializer = Serializer::new();
        serializer.write_array(self.u.as_bytes())?;
        serializer.write_array(self.v.as_bytes())?;
        serializer.write_array(self.s.as_bytes())?;
        serializer.write_u64(self.x.len() as u64)?;
        for (partition, x_i) in &self.x {
            serializer.write_array(partition)?;
            serializer.write_array(x_i.as_bytes())?;
        }
        Ok(serializer.value().to_vec())
    }

    /// Deserialize the master private key from the given bytes.
    ///
    /// - `bytes`   : bytes from which to read the master private key
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyPrivateKey);
        }
        let mut de = Deserializer::new(bytes);
        let u = X25519PrivateKey::try_from_bytes(&de.read_array()?)?;
        let v = X25519PrivateKey::try_from_bytes(&de.read_array()?)?;
        let s = X25519PrivateKey::try_from_bytes(&de.read_array()?)?;
        let x_len = de.read_u64()?.try_into()?;
        let mut x = HashMap::with_capacity(x_len);
        for _ in 0..x_len {
            let partition = de.read_array()?;
            let x_i = de.read_array()?;
            x.insert(
                Partition::from(partition),
                X25519PrivateKey::try_from_bytes(&x_i)?,
            );
        }
        Ok(Self { u, v, s, x })
    }
}

impl Zeroize for MasterPrivateKey {
    fn zeroize(&mut self) {
        self.u.zeroize();
        self.v.zeroize();
        self.s.zeroize();
        self.x.iter_mut().for_each(|(_, x_i)| {
            x_i.zeroize();
        });
    }
}

impl Drop for MasterPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// CoverCrypt user private key.
///
/// It is composed of:
///
/// - `a` and `b` such that `a * u + b * v = s`, where `u`, `v` and `s` are
/// scalars from the master private key
/// - the scalars `x_i` associated to the subsets `S_i` for which the user has
/// been given the rights.
///
/// Therefore, a user can decrypt messages encrypted for any subset `S_i` his
/// private key holds the associted `x_i`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPrivateKey {
    a: X25519PrivateKey,
    b: X25519PrivateKey,
    pub(crate) x: HashMap<Partition, X25519PrivateKey>,
}

impl UserPrivateKey {
    /// Serialize the user private key.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut serializer = Serializer::new();
        serializer.write_array(self.a.as_bytes())?;
        serializer.write_array(self.b.as_bytes())?;
        serializer.write_u64(self.x.len() as u64)?;
        for (partition, x_i) in &self.x {
            serializer.write_array(partition)?;
            serializer.write_array(x_i.as_bytes())?;
        }
        Ok(serializer.value().to_vec())
    }

    /// Deserialize the user private key.
    ///
    /// - `bytes`   : bytes from which to read the user private key
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyPrivateKey);
        }
        let mut de = Deserializer::new(bytes);
        let a = X25519PrivateKey::try_from_bytes(&de.read_array()?)?;
        let b = X25519PrivateKey::try_from_bytes(&de.read_array()?)?;
        let x_len = de.read_u64()?.try_into()?;
        let mut x = HashMap::with_capacity(x_len);
        for _ in 0..x_len {
            let partition = de.read_array()?;
            let x_i = de.read_array()?;
            x.insert(
                Partition::from(partition),
                X25519PrivateKey::try_from_bytes(&x_i)?,
            );
        }
        Ok(Self { a, b, x })
    }
}

impl Zeroize for UserPrivateKey {
    fn zeroize(&mut self) {
        self.a.zeroize();
        self.b.zeroize();
        self.x.iter_mut().for_each(|(_, x_i)| {
            x_i.zeroize();
        });
    }
}

impl Drop for UserPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// CoverCrypt public key.
///
/// It is composed of:
///
/// - `U` and `V` such that `U = g * u` and `V = g * v`, where `u` and `v` are
/// scalars from the master private key and `g` is the group generator.
///
/// - the `H_i` such that `H_i = g * s * x_i` with `x_i` the scalars associated
/// to each subset `S_i`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    U: X25519PublicKey,
    V: X25519PublicKey,
    pub(crate) H: HashMap<Partition, X25519PublicKey>,
}

impl PublicKey {
    /// Serialize the public key.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut serializer = Serializer::new();
        serializer.write_array(&self.U.to_array())?;
        serializer.write_array(&self.V.to_array())?;
        serializer.write_u64(self.H.len() as u64)?;
        for (partition, H_i) in &self.H {
            serializer.write_array(partition)?;
            serializer.write_array(&H_i.to_array())?;
        }
        Ok(serializer.value().to_vec())
    }

    /// Deserialize the public key.
    ///
    /// - `bytes`   : bytes from which to read the public key
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyPrivateKey);
        }
        let mut de = Deserializer::new(bytes);
        let U = X25519PublicKey::try_from_bytes(&de.read_array()?)?;
        let V = X25519PublicKey::try_from_bytes(&de.read_array()?)?;
        let H_len = de.read_u64()?.try_into()?;
        let mut H = HashMap::with_capacity(H_len);
        for _ in 0..H_len {
            let partition = de.read_array()?;
            let H_i = de.read_array()?;
            H.insert(
                Partition::from(partition),
                X25519PublicKey::try_from_bytes(&H_i)?,
            );
        }
        Ok(Self { U, V, H })
    }
}

/// CoverCrypt secret key encapsulation.
///
/// It is composed of:
///
/// - `C` and `D` such that `C = U * r` and `D = V * r`, where `r` is a random
/// scalar and `U` and `V` are the points from the public key.
///
/// - the `E_i` such that `E_i = Hash(K_i) Xor K` with `K_i = H_i * r` where
/// the `H_i` are public key points from `H` that are associated to subsets
/// `S_i` in the encryption set used to generate the encapsulation, and `K` is
/// the randomly chosen symmetric key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encapsulation {
    C: X25519PublicKey,
    D: X25519PublicKey,
    E: HashSet<Vec<u8>>,
}

impl Encapsulation {
    /// Serialize the encapsulation.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut serializer = Serializer::new();
        serializer.write_array(&self.C.to_array())?;
        serializer.write_array(&self.D.to_array())?;
        serializer.write_u64(self.E.len() as u64)?;
        for K_i in &self.E {
            serializer.write_array(K_i)?;
        }
        Ok(serializer.value().to_vec())
    }

    /// Deserialize the encapsulation.
    ///
    /// - `bytes`   : bytes from which to read the encapsulation
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyPrivateKey);
        }
        let mut de = Deserializer::new(bytes);
        let C = X25519PublicKey::try_from_bytes(&de.read_array()?)?;
        let D = X25519PublicKey::try_from_bytes(&de.read_array()?)?;
        let K_len = de.read_u64()?.try_into()?;
        let mut K = HashSet::with_capacity(K_len as usize);
        for _ in 0..K_len {
            K.insert(de.read_array()?);
        }
        Ok(Self { C, D, E: K })
    }
}

/// CoverCrypt secret key.
///
/// Internally, it is a vector of bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SecretKey(Vec<u8>);

impl std::ops::Deref for SecretKey {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for SecretKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<u8>> for SecretKey {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<SecretKey> for Vec<u8> {
    fn from(sk: SecretKey) -> Self {
        sk.to_vec()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Generate the master private key and master public key of the CoverCrypt
/// scheme.
///
/// # Paper
///
/// Setup(`(𝑆_𝑖)_𝑖`): it generates the master public key mpk and the master
/// secret key msk as follows:
///
/// - it samples random `𝑢, 𝑣, 𝑠 ← ℤ_𝑞` and sets `𝑈 ← 𝑔 ^ 𝑢`, `𝑉 ← 𝑔 ^ 𝑣` and
/// `𝐻 ← 𝑔 ^ 𝑠`
///
/// - For each set `𝑆_𝑖 ∈ 𝒮`, where `𝒮 = (𝑆_𝑖)_𝑖` , it chooses a random
/// `𝑥_𝑖 ← ℤ_𝑞` and sets `𝐻_𝑖 ← 𝐻 ^ 𝑥_𝑖` .
///
/// Let `msk ← (𝑢, 𝑣, 𝑠, (𝑥_𝑖)_𝑖)` and `mpk ← (𝔾, 𝑔, 𝑈 , 𝑉 , 𝐻, (𝐻_𝑖)_𝑖)`.
///
/// # Arguments
///
/// - `rng`         : random number generator
/// - `partitions`  : set of partition to be used
pub fn setup<R>(rng: &mut R, partitions: &HashSet<Partition>) -> (MasterPrivateKey, PublicKey)
where
    R: CryptoRng + RngCore,
{
    let msk = MasterPrivateKey {
        u: X25519PrivateKey::new(rng),
        v: X25519PrivateKey::new(rng),
        s: X25519PrivateKey::new(rng),
        x: partitions
            .iter()
            .map(|partition| (partition.clone(), X25519PrivateKey::new(rng)))
            .collect(),
    };

    let S = X25519PublicKey::from(&msk.s);
    let mpk = PublicKey {
        U: X25519PublicKey::from(&msk.u),
        V: X25519PublicKey::from(&msk.v),
        H: msk
            .x
            .iter()
            .map(|(partition, x_i)| (partition.clone(), &S * x_i))
            .collect(),
    };
    (msk, mpk)
}

/// Generate a user private key for the given decryption sets.
///
/// # Paper
///
/// Join(`msk`, `𝑗`, `𝐴_𝑗`): it takes as input the master secret key `msk`, a
/// user identifier `𝑗`, and the set `𝐴_𝑗` of indices `𝑖` such that user `𝑗`
/// belongs to `𝑆_𝑖`, and provides its secret key `SK_𝑗`.
///
/// For the tracing, one first chooses random scalars `(𝑎_𝑗, 𝑏_𝑗)` such that
/// `𝑎_𝑗 ⋅ 𝑢 + 𝑏_𝑗 ⋅ 𝑣 = 𝑠`.
///
/// Then `SK_𝑗 ← (𝑎_𝑗 , 𝑏_𝑗 , (𝑥_𝑖)_{𝑖∈𝐴_𝑗})` is provided to user `𝑗`.
///
/// # Arguments
///
/// - `rng`             : random number generator
/// - `msk`             : master secret key
/// - `decryption_set`  : decryption set
pub fn join<R>(
    rng: &mut R,
    msk: &MasterPrivateKey,
    decryption_set: &HashSet<Partition>,
) -> Result<UserPrivateKey, Error>
where
    R: CryptoRng + RngCore,
{
    let a = X25519PrivateKey::new(rng);
    let b = (&msk.s - &a * &msk.u) * &msk.v.invert();
    let x = msk
        .x
        .iter()
        .filter_map(|(partition, x_i)| {
            if decryption_set.contains(partition) {
                Some((partition.clone(), x_i.clone()))
            } else {
                None
            }
        })
        .collect();
    Ok(UserPrivateKey { a, b, x })
}

/// Generate the secret key encapsulation.
///
/// # Paper
///
/// • Enc(`𝐾`, `𝐵`): it takes as input a bitstring `𝐾 ∈ {0, 1}^𝑛` to encrypt
/// to all the users belonging to `𝑆_𝑖` , for `𝑖 ∈ 𝐵`, and outputs the
/// encryption of `𝐾`.
///
/// – it samples a random `𝑟 ← ℤ_𝑞`;
///
/// – it sets `𝐶 ← 𝑈 ^ 𝑟` and `𝐷 ← 𝑉 ^ 𝑟`;
///
/// – for every `𝑖 ∈ 𝐵`, it generates `𝐾_𝑖 ← 𝐻_𝑖 ^ 𝑟` .
///
/// The ciphertext thus consists of `(𝐶, 𝐷, (𝐸_𝑖 = ℋ (𝐾_𝑖) ⊕ 𝐾)_{𝑖∈𝐵})`, where
/// `ℋ ` is a hash function onto `{0, 1}^𝑛` .
///
/// # Arguments
///
/// - `rng`             : secure random number generator
/// - `mpk`             : master public key
/// - `encyption_set`   : sets for which to generate a ciphertext
/// - `K`               : secret key
pub fn encaps<R>(
    rng: &mut R,
    mpk: &PublicKey,
    encryption_set: &HashSet<Partition>,
    K: &SecretKey,
) -> Result<Encapsulation, Error>
where
    R: CryptoRng + RngCore,
{
    let r = X25519PrivateKey::new(rng);
    let C = &mpk.U * &r;
    let D = &mpk.V * &r;
    let mut E = HashSet::with_capacity(encryption_set.len());
    for partition in encryption_set {
        if let Some(H_i) = mpk.H.get(partition) {
            let K_i = hkdf_256(&(H_i * &r).to_bytes(), K.len(), KEY_GEN_INFO.as_bytes())?;
            let E_i = K_i
                .iter()
                .zip(K.iter())
                .map(|(e_1, e_2)| e_1 ^ e_2)
                .collect();
            E.insert(E_i);
        } // else may log a warning about unknown target partition
    }
    Ok(Encapsulation { C, D, E })
}

/// Decapsulate the secret key if the given user ID is in the target set.
///
/// # Paper
///
/// Dec(`SK_𝑗`, `(𝐶, 𝐷, (𝐸_𝑖 = 𝐾_𝑖 ⊕ 𝐾)_{𝑖∈𝐵})`): it takes as input a user’s
/// secret key and a ciphertext, it outputs the decrypyted key `𝐾`.
///
/// - the user first chooses an index `𝑖 ∈ 𝐵 ∩ 𝐴_𝑗` , in both its set of rights
/// `𝐴_𝑗` and the rights `𝐵` of the ciphertext, and then uses `𝑥_𝑖 = sk_𝑖 ∈ SK_𝑗`;
///
/// - it can compute `𝐾_𝑖 = (𝐶 ^ 𝑎_𝑗 𝐷 ^ 𝑏_𝑗 ) ^ 𝑥_𝑖` , and extract
/// `𝐾 = 𝐸_𝑖 ⊕ ℋ (𝐾_𝑖)`.
///
/// # Arguments
///
/// - `sk_j`                : user private key
/// - `encapsulation`       : symmetric key encapsulation
pub fn decaps(
    sk_j: &UserPrivateKey,
    encapsulation: &Encapsulation,
) -> Result<Vec<SecretKey>, Error> {
    let mut res = Vec::with_capacity(sk_j.x.len() * encapsulation.E.len());
    for E_i in &encapsulation.E {
        for x_k in sk_j.x.values() {
            let K_k = (&encapsulation.C * &sk_j.a + &encapsulation.D * &sk_j.b) * x_k;
            let K: Vec<u8> = hkdf_256(&K_k.to_bytes(), E_i.len(), KEY_GEN_INFO.as_bytes())?
                .iter()
                .zip(E_i.iter())
                .map(|(e_1, e_2)| e_1 ^ e_2)
                .collect();
            res.push(SecretKey::from(K));
        }
    }
    Ok(res)
}

/// Update the master private key and master public key of the CoverCrypt
/// scheme with the given list of partitions.
///
/// If a partition exists in the keys but not in the list, it will be removed
/// from the keys.
///
/// If a partition exists in the list, but not in the keys, it will be "added"
/// to the keys, by adding a new partition key pair as performed in the setup
/// procedure above.
///
/// # Arguments
///
/// - `rng`             : random number generator
/// - `msk`             : master secret key
/// - `mpk`             : master public key
/// - `partition_set`   : new set of partitions to use after the update
pub fn update<R: CryptoRng + RngCore>(
    rng: &mut R,
    msk: &mut MasterPrivateKey,
    mpk: &mut PublicKey,
    partitions_set: &HashSet<Partition>,
) -> Result<(), Error> {
    // add keys for partitions that do not exist in the master keys
    for partition in partitions_set {
        if !msk.x.contains_key(partition) || !mpk.H.contains_key(partition) {
            let x_i = X25519PrivateKey::new(rng);
            let H_i = X25519PublicKey::from(&msk.s) * &x_i;
            msk.x.insert(partition.to_owned(), x_i);
            mpk.H.insert(partition.to_owned(), H_i);
        }
    }
    // remove keys for partitions not in the list
    for (partition, _) in msk.x.clone().iter() {
        if !partitions_set.contains(partition) {
            msk.x.remove_entry(partition);
        }
    }
    for (partition, _) in mpk.H.clone().iter() {
        if !partitions_set.contains(partition) {
            mpk.H.remove_entry(partition);
        }
    }
    Ok(())
}

/// Refresh a user key from the master private key and a list of partitions.
/// The partitions MUST exist in the master secret key.
///
/// If a partition exists in the user key but is not in the list, it will be removed from the user key.
///
/// If a partition exists in the list, but not in the user key, it will be "added" to the user key,
/// by copying the proper partition key from the master private key
pub fn refresh(
    msk: &MasterPrivateKey,
    usk: &mut UserPrivateKey,
    user_set: &HashSet<Partition>,
) -> Result<(), Error> {
    // add keys for partitions that do not exist
    for partition in user_set {
        if !usk.x.contains_key(partition) {
            // extract key from master private key (see join)
            let kem_private_key = msk.x.get(partition).ok_or_else(|| {
                Error::UnknownPartition(format!(
                    "the master private key does not contain the partition: {partition:?}"
                ))
            })?;
            usk.x
                .insert(partition.to_owned(), kem_private_key.to_owned());
        }
    }
    // remove keys for partitions not in the list
    for (partition, _) in usk.x.clone().iter() {
        if !user_set.contains(partition) {
            usk.x.remove_entry(partition);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmian_crypto_core::entropy::CsRng;

    /// Length of the desired symmetric key
    const SYM_KEY_LENGTH: usize = 32;

    #[test]
    fn test_partitions() -> Result<(), Error> {
        let mut values: Vec<u32> = vec![12, 0, u32::MAX, 1];
        let partition = Partition::from_attributes(values.clone())?;
        let bytes = partition.0;
        let mut readable = &bytes[..];
        // values are sorted n Partition
        values.sort_unstable();
        for v in values {
            let val = leb128::read::unsigned(&mut readable).expect("Should read number") as u32;
            assert_eq!(v, val);
        }
        Ok(())
    }

    #[test]
    fn test_serialization() -> Result<(), Error> {
        let admin_partition = Partition(b"admin".to_vec());
        let dev_partition = Partition(b"dev".to_vec());
        // partition list
        let partitions_set = HashSet::from([admin_partition.clone(), dev_partition.clone()]);
        // user list
        let user_set = HashSet::from([admin_partition.clone(), dev_partition]);
        // target set
        let target_set = HashSet::from([admin_partition]);
        // secure random number generator
        let mut rng = CsRng::new();
        // setup scheme
        let (msk, mpk) = setup(&mut rng, &partitions_set);
        let msk_ = MasterPrivateKey::try_from_bytes(&msk.try_to_bytes()?)?;
        assert_eq!(msk, msk_, "Master secret key comparisons failed");
        let mpk_ = PublicKey::try_from_bytes(&mpk.try_to_bytes()?)?;
        assert_eq!(mpk, mpk_, "Master public key comparison failed");
        let usk = join(&mut rng, &msk, &user_set)?;
        let usk_ = UserPrivateKey::try_from_bytes(&usk.try_to_bytes()?)?;
        assert_eq!(usk, usk_, "User secret key comparison failed");
        let sym_key = SecretKey(rng.generate_random_bytes(SYM_KEY_LENGTH));
        let encapsulation = encaps(&mut rng, &mpk, &target_set, &sym_key)?;
        let encapsulation_ = Encapsulation::try_from_bytes(&encapsulation.try_to_bytes()?)?;
        assert_eq!(
            encapsulation, encapsulation_,
            "Encapsulation comparison failed"
        );
        Ok(())
    }

    #[test]
    fn test_cover_crypt() -> Result<(), Error> {
        let admin_partition = Partition(b"admin".to_vec());
        let dev_partition = Partition(b"dev".to_vec());
        // partition list
        let partitions_set = HashSet::from([admin_partition.clone(), dev_partition.clone()]);
        // user list
        let users_set = vec![
            HashSet::from([dev_partition.clone()]),
            HashSet::from([admin_partition.clone(), dev_partition.clone()]),
        ];
        // target set
        let target_set = HashSet::from([admin_partition]);
        // secure random number generator
        let mut rng = CsRng::new();
        // setup scheme
        let (mut msk, mut mpk) = setup(&mut rng, &partitions_set);
        // generate user private keys
        let mut sk0 = join(&mut rng, &msk, &users_set[0])?;
        let sk1 = join(&mut rng, &msk, &users_set[1])?;
        // encapsulate for the target set
        let sym_key = SecretKey(rng.generate_random_bytes(SYM_KEY_LENGTH));
        let encapsulation = encaps(&mut rng, &mpk, &target_set, &sym_key)?;
        // decapsulate for users 1 and 3
        let res0 = decaps(&sk0, &encapsulation)?;
        let res1 = decaps(&sk1, &encapsulation)?;
        let mut is_found = false;
        for key in res0 {
            if key == sym_key {
                is_found = true;
                break;
            }
        }
        assert!(!is_found, "User 0 shouldn't be able to decapsulate!");
        for key in res1 {
            if key == sym_key {
                is_found = true;
                break;
            }
        }
        assert!(is_found, "Wrong decapsulation for user 1!");

        // rotate and refresh keys
        println!("Rotate");
        let client_partition = Partition(b"client".to_vec());
        let new_partitions_set = HashSet::from([dev_partition, client_partition.clone()]);
        update(&mut rng, &mut msk, &mut mpk, &new_partitions_set)?;
        refresh(&msk, &mut sk0, &HashSet::from([client_partition]))?;
        println!("msk: {:?}", msk.x);
        println!("usk: {:?}", sk0.x);
        println!("{sym_key:?}");
        let new_encapsulation = encaps(&mut rng, &mpk, &new_partitions_set, &sym_key)?;
        let res0 = decaps(&sk0, &new_encapsulation)?;
        let mut is_found = false;
        for key in res0 {
            if key == sym_key {
                is_found = true;
                break;
            }
        }
        assert!(is_found, "User 0 should be able to decapsulate!");
        Ok(())
    }

    #[test]
    fn test_master_keys_update() -> Result<(), Error> {
        let partition_1 = Partition(b"1".to_vec());
        let partition_2 = Partition(b"2".to_vec());
        // partition list
        let partitions_set = HashSet::from([partition_1.clone(), partition_2.clone()]);
        // secure random number generator
        let mut rng = CsRng::new();
        // setup scheme
        let (mut msk, mut mpk) = setup(&mut rng, &partitions_set);

        // now remove partition 1 and add partition 3
        let partition_3 = Partition(b"3".to_vec());
        let new_partitions_set = HashSet::from([partition_2.clone(), partition_3.clone()]);
        update(&mut rng, &mut msk, &mut mpk, &new_partitions_set)?;
        assert!(!msk.x.contains_key(&partition_1));
        assert!(msk.x.contains_key(&partition_2));
        assert!(msk.x.contains_key(&partition_3));
        assert!(!mpk.H.contains_key(&partition_1));
        assert!(mpk.H.contains_key(&partition_2));
        assert!(mpk.H.contains_key(&partition_3));
        Ok(())
    }

    #[test]
    fn test_user_key_refresh() -> Result<(), Error> {
        let partition_1 = Partition(b"1".to_vec());
        let partition_2 = Partition(b"2".to_vec());
        let partition_3 = Partition(b"3".to_vec());
        // partition list
        let partitions_set = HashSet::from([
            partition_1.clone(),
            partition_2.clone(),
            partition_3.clone(),
        ]);
        // secure random number generator
        let mut rng = CsRng::new();
        // setup scheme
        let (mut msk, mut mpk) = setup(&mut rng, &partitions_set);
        // create a user key with access to partition 1 and 2
        let mut usk = join(
            &mut rng,
            &msk,
            &HashSet::from([partition_1.clone(), partition_2.clone()]),
        )?;

        // now remove partition 1 and add partition 4
        let partition_4 = Partition(b"4".to_vec());
        let new_partitions_set = HashSet::from([
            partition_2.clone(),
            partition_3.clone(),
            partition_4.clone(),
        ]);
        // update the master keys
        update(&mut rng, &mut msk, &mut mpk, &new_partitions_set)?;
        // refresh the user key with partitions 2 and 4
        refresh(
            &msk,
            &mut usk,
            &HashSet::from([partition_2.clone(), partition_4.clone()]),
        )?;
        assert!(!usk.x.contains_key(&partition_1));
        assert!(usk.x.contains_key(&partition_2));
        assert!(!usk.x.contains_key(&partition_3));
        assert!(usk.x.contains_key(&partition_4));
        Ok(())
    }
}
