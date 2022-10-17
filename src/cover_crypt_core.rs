// Needed to use the paper naming conventions
#![allow(non_snake_case)]

use crate::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    error::Error,
    partitions::Partition,
};
use cosmian_crypto_core::{asymmetric_crypto::DhKeyPair, kdf, symmetric_crypto::SymKey, KeyTrait};
use rand_core::{CryptoRng, RngCore};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    ops::{Add, Div, Mul, Sub},
};
use zeroize::Zeroize;

/// Additional information to generate symmetric key using the KDF.
const KEY_GEN_INFO: &str = "key generation info";

/// CoverCrypt master secret key.
///
/// It is composed of `u`, `v` and `s`, three randomly chosen scalars,
/// and the scalars `x_i` associated to all subsets `S_i`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterSecretKey<const PRIVATE_KEY_LENGTH: usize, SK: KeyTrait<PRIVATE_KEY_LENGTH>> {
    u: SK,
    v: SK,
    s: SK,
    pub(crate) x: HashMap<Partition, SK>,
}

impl<const PRIVATE_KEY_LENGTH: usize, SK: KeyTrait<PRIVATE_KEY_LENGTH>> Serializable
    for MasterSecretKey<PRIVATE_KEY_LENGTH, SK>
{
    /// Serialize the master secret key.
    fn write(&self, ser: &mut Serializer) -> Result<usize, Error> {
        let mut n = ser.write_array(&self.u.to_bytes())?;
        n += ser.write_array(&self.v.to_bytes())?;
        n += ser.write_array(&self.s.to_bytes())?;
        n += ser.write_u64(self.x.len() as u64)?;
        for (partition, x_i) in &self.x {
            n += ser.write_vec(partition)?;
            n += ser.write_array(&x_i.to_bytes())?;
        }
        Ok(n)
    }

    /// Deserialize the master secret key from the given bytes.
    ///
    /// - `bytes`   : bytes from which to read the master secret key
    fn read(de: &mut Deserializer) -> Result<Self, Error> {
        let u = SK::try_from_bytes(&de.read_array::<PRIVATE_KEY_LENGTH>()?)?;
        let v = SK::try_from_bytes(&de.read_array::<PRIVATE_KEY_LENGTH>()?)?;
        let s = SK::try_from_bytes(&de.read_array::<PRIVATE_KEY_LENGTH>()?)?;
        let x_len = de.read_u64()?.try_into()?;
        let mut x = HashMap::with_capacity(x_len);
        for _ in 0..x_len {
            let partition = de.read_vec()?;
            let x_i = de.read_array::<PRIVATE_KEY_LENGTH>()?;
            x.insert(Partition::from(partition), SK::try_from_bytes(&x_i)?);
        }
        Ok(Self { u, v, s, x })
    }
}

impl<const PRIVATE_KEY_LENGTH: usize, SK: KeyTrait<PRIVATE_KEY_LENGTH>> Zeroize
    for MasterSecretKey<PRIVATE_KEY_LENGTH, SK>
{
    fn zeroize(&mut self) {
        self.u.zeroize();
        self.v.zeroize();
        self.s.zeroize();
        self.x.iter_mut().for_each(|(_, x_i)| {
            x_i.zeroize();
        });
    }
}

impl<const PRIVATE_KEY_LENGTH: usize, SK: KeyTrait<PRIVATE_KEY_LENGTH>> Drop
    for MasterSecretKey<PRIVATE_KEY_LENGTH, SK>
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// CoverCrypt user secret key.
///
/// It is composed of:
///
/// - `a` and `b` such that `a * u + b * v = s`, where `u`, `v` and `s` are
/// scalars from the master secret key
/// - the scalars `x_i` associated to the subsets `S_i` for which the user has
/// been given the rights.
///
/// Therefore, a user can decrypt messages encrypted for any subset `S_i` his
/// secret key holds the associated `x_i`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSecretKey<const PRIVATE_KEY_LENGTH: usize, SK: KeyTrait<PRIVATE_KEY_LENGTH>> {
    a: SK,
    b: SK,
    pub(crate) x: HashMap<Partition, SK>,
}

impl<const PRIVATE_KEY_LENGTH: usize, SK: KeyTrait<PRIVATE_KEY_LENGTH>> Serializable
    for UserSecretKey<PRIVATE_KEY_LENGTH, SK>
{
    /// Serialize the user secret key.
    fn write(&self, ser: &mut Serializer) -> Result<usize, Error> {
        let mut n = ser.write_array(&self.a.to_bytes())?;
        n += ser.write_array(&self.b.to_bytes())?;
        n += ser.write_u64(self.x.len() as u64)?;
        for (partition, x_i) in &self.x {
            n += ser.write_vec(partition)?;
            n += ser.write_array(&x_i.to_bytes())?;
        }
        Ok(n)
    }

    /// Deserialize the user secret key.
    ///
    /// - `bytes`   : bytes from which to read the user secret key
    fn read(de: &mut Deserializer) -> Result<Self, Error> {
        let a = SK::try_from_bytes(&de.read_array::<PRIVATE_KEY_LENGTH>()?)?;
        let b = SK::try_from_bytes(&de.read_array::<PRIVATE_KEY_LENGTH>()?)?;
        let x_len = de.read_u64()?.try_into()?;
        let mut x = HashMap::with_capacity(x_len);
        for _ in 0..x_len {
            let partition = de.read_vec()?;
            let x_i = de.read_array::<PRIVATE_KEY_LENGTH>()?;
            x.insert(Partition::from(partition), SK::try_from_bytes(&x_i)?);
        }
        Ok(Self { a, b, x })
    }
}

impl<const PRIVATE_KEY_LENGTH: usize, SK: KeyTrait<PRIVATE_KEY_LENGTH>> Zeroize
    for UserSecretKey<PRIVATE_KEY_LENGTH, SK>
{
    fn zeroize(&mut self) {
        self.a.zeroize();
        self.b.zeroize();
        self.x.iter_mut().for_each(|(_, x_i)| {
            x_i.zeroize();
        });
    }
}

impl<const PRIVATE_KEY_LENGTH: usize, SK: KeyTrait<PRIVATE_KEY_LENGTH>> Drop
    for UserSecretKey<PRIVATE_KEY_LENGTH, SK>
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// CoverCrypt public key.
///
/// It is composed of:
///
/// - `U` and `V` such that `U = g * u` and `V = g * v`, where `u` and `v` are
/// scalars from the master secret key and `g` is the group generator.
///
/// - the `H_i` such that `H_i = g * s * x_i` with `x_i` the scalars associated
/// to each subset `S_i`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey<const PUBLIC_KEY_LENGTH: usize, PK: KeyTrait<PUBLIC_KEY_LENGTH>> {
    U: PK,
    V: PK,
    pub(crate) H: HashMap<Partition, PK>,
}

impl<const PUBLIC_KEY_LENGTH: usize, PK: KeyTrait<PUBLIC_KEY_LENGTH>> Serializable
    for PublicKey<PUBLIC_KEY_LENGTH, PK>
{
    /// Serialize the public key.
    fn write(&self, ser: &mut Serializer) -> Result<usize, Error> {
        let mut n = ser.write_array(&self.U.to_bytes())?;
        n += ser.write_array(&self.V.to_bytes())?;
        n += ser.write_u64(self.H.len() as u64)?;
        for (partition, H_i) in &self.H {
            n += ser.write_vec(partition)?;
            n += ser.write_array(&H_i.to_bytes())?;
        }
        Ok(n)
    }

    /// Deserialize the public key.
    ///
    /// - `bytes`   : bytes from which to read the public key
    fn read(de: &mut Deserializer) -> Result<Self, Error> {
        let U = PK::try_from_bytes(&de.read_array::<PUBLIC_KEY_LENGTH>()?)?;
        let V = PK::try_from_bytes(&de.read_array::<PUBLIC_KEY_LENGTH>()?)?;
        let H_len = de.read_u64()?.try_into()?;
        let mut H = HashMap::with_capacity(H_len);
        for _ in 0..H_len {
            let partition = de.read_vec()?;
            let H_i = de.read_array::<PUBLIC_KEY_LENGTH>()?;
            H.insert(Partition::from(partition), PK::try_from_bytes(&H_i)?);
        }
        Ok(Self { U, V, H })
    }
}

/// CoverCrypt encapsulation.
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
pub struct Encapsulation<
    const KEY_LENGTH: usize,
    const PUBLIC_KEY_LENGTH: usize,
    SymmetricKey: SymKey<KEY_LENGTH>,
    PublicKey: KeyTrait<PUBLIC_KEY_LENGTH>,
> {
    C: PublicKey,
    D: PublicKey,
    E: HashSet<SymmetricKey>,
}

impl<
        const SYM_KEY_LENGTH: usize,
        const PUBLIC_KEY_LENGTH: usize,
        SymmetricKey: SymKey<SYM_KEY_LENGTH>,
        PublicKey: KeyTrait<PUBLIC_KEY_LENGTH>,
    > Serializable for Encapsulation<SYM_KEY_LENGTH, PUBLIC_KEY_LENGTH, SymmetricKey, PublicKey>
{
    /// Serialize the encapsulation.
    fn write(&self, ser: &mut Serializer) -> Result<usize, Error> {
        let mut n = ser.write_array(&self.C.to_bytes())?;
        n += ser.write_array(&self.D.to_bytes())?;
        n += ser.write_u64(self.E.len() as u64)?;
        for K_i in &self.E {
            n += ser.write_array(K_i.as_bytes())?;
        }
        Ok(n)
    }

    /// Deserialize the encapsulation.
    ///
    /// - `bytes`   : bytes from which to read the encapsulation
    fn read(de: &mut Deserializer) -> Result<Self, Error> {
        let C = PublicKey::try_from_bytes(&de.read_array::<PUBLIC_KEY_LENGTH>()?)?;
        let D = PublicKey::try_from_bytes(&de.read_array::<PUBLIC_KEY_LENGTH>()?)?;
        let K_len = de.read_u64()?.try_into()?;
        let mut K = HashSet::with_capacity(K_len);
        for _ in 0..K_len {
            K.insert(SymmetricKey::from_bytes(de.read_array::<SYM_KEY_LENGTH>()?));
        }
        Ok(Self { C, D, E: K })
    }
}

/// Generate the master secret key and master public key of the CoverCrypt
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
pub fn setup<const PUBLIC_KEY_LENGTH: usize, const PRIVATE_KEY_LENGTH: usize, R, KeyPair>(
    rng: &mut R,
    partitions: &HashSet<Partition>,
) -> (
    MasterSecretKey<PRIVATE_KEY_LENGTH, KeyPair::PrivateKey>,
    PublicKey<PUBLIC_KEY_LENGTH, KeyPair::PublicKey>,
)
where
    R: CryptoRng + RngCore,
    KeyPair: DhKeyPair<PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH>,
    KeyPair::PublicKey: From<KeyPair::PrivateKey>,
    for<'a, 'b> &'a KeyPair::PublicKey: Add<&'b KeyPair::PublicKey, Output = KeyPair::PublicKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PublicKey>,
    for<'a, 'b> &'a KeyPair::PrivateKey: Add<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Sub<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Div<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>,
{
    let msk = MasterSecretKey {
        u: KeyPair::PrivateKey::new(rng),
        v: KeyPair::PrivateKey::new(rng),
        s: KeyPair::PrivateKey::new(rng),
        x: partitions
            .iter()
            .map(|partition| (partition.clone(), KeyPair::PrivateKey::new(rng)))
            .collect(),
    };

    let S = KeyPair::PublicKey::from(msk.s.clone());
    let mpk = PublicKey {
        U: KeyPair::PublicKey::from(msk.u.clone()),
        V: KeyPair::PublicKey::from(msk.v.clone()),
        H: msk
            .x
            .iter()
            .map(|(partition, x_i)| (partition.clone(), &S * x_i))
            .collect(),
    };
    (msk, mpk)
}

/// Generate a user secret key for the given decryption sets.
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

pub fn join<const PUBLIC_KEY_LENGTH: usize, const PRIVATE_KEY_LENGTH: usize, R, KeyPair>(
    rng: &mut R,
    msk: &MasterSecretKey<PRIVATE_KEY_LENGTH, KeyPair::PrivateKey>,
    decryption_set: &HashSet<Partition>,
) -> Result<UserSecretKey<PRIVATE_KEY_LENGTH, KeyPair::PrivateKey>, Error>
where
    R: CryptoRng + RngCore,
    KeyPair: DhKeyPair<PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH>,
    KeyPair::PublicKey: From<KeyPair::PrivateKey>,
    for<'a, 'b> &'a KeyPair::PublicKey: Add<&'b KeyPair::PublicKey, Output = KeyPair::PublicKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PublicKey>,
    for<'a, 'b> &'a KeyPair::PrivateKey: Add<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Sub<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Div<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>,
{
    let a = KeyPair::PrivateKey::new(rng);
    let b = &(&msk.s - &(&a * &msk.u)) / &msk.v;
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
    Ok(UserSecretKey { a, b, x })
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
/// - `encryption_set`  : sets for which to generate a ciphertext
/// - `K`               : secret key
pub fn encaps<
    const SYM_KEY_LENGTH: usize,
    const PUBLIC_KEY_LENGTH: usize,
    const PRIVATE_KEY_LENGTH: usize,
    R,
    SymmetricKey,
    KeyPair,
>(
    rng: &mut R,
    mpk: &PublicKey<PUBLIC_KEY_LENGTH, KeyPair::PublicKey>,
    encryption_set: &HashSet<Partition>,
    K: &SymmetricKey,
) -> Result<Encapsulation<SYM_KEY_LENGTH, PUBLIC_KEY_LENGTH, SymmetricKey, KeyPair::PublicKey>, Error>
where
    R: CryptoRng + RngCore,
    SymmetricKey: SymKey<SYM_KEY_LENGTH>,
    KeyPair: DhKeyPair<PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH>,
    KeyPair::PublicKey: From<KeyPair::PrivateKey>,
    for<'a, 'b> &'a KeyPair::PublicKey: Add<&'b KeyPair::PublicKey, Output = KeyPair::PublicKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PublicKey>,
    for<'a, 'b> &'a KeyPair::PrivateKey: Add<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Sub<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Div<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>,
{
    let r = KeyPair::PrivateKey::new(rng);
    let C = &mpk.U * &r;
    let D = &mpk.V * &r;
    let mut E = HashSet::with_capacity(encryption_set.len());
    for partition in encryption_set {
        if let Some(H_i) = mpk.H.get(partition) {
            let mut E_i = kdf!(
                SYM_KEY_LENGTH,
                &(H_i * &r).to_bytes(),
                KEY_GEN_INFO.as_bytes()
            );
            for (e_1, e_2) in E_i.iter_mut().zip(K.as_bytes()) {
                *e_1 ^= e_2;
            }
            E.insert(SymmetricKey::from_bytes(E_i));
        } // else may log a warning about unknown target partition
    }
    Ok(Encapsulation { C, D, E })
}

/// Decapsulate the secret key if the given user ID is in the target set.
///
/// # Paper
///
/// Dec(`SK_𝑗`, `(𝐶, 𝐷, (𝐸_𝑖 = 𝐾_𝑖 ⊕ 𝐾)_{𝑖∈𝐵})`): it takes as input a user’s
/// secret key and a ciphertext, it outputs the decrypted key `𝐾`.
///
/// - the user first chooses an index `𝑖 ∈ 𝐵 ∩ 𝐴_𝑗` , in both its set of rights
/// `𝐴_𝑗` and the rights `𝐵` of the ciphertext, and then uses `𝑥_𝑖 = sk_𝑖 ∈ SK_𝑗`;
///
/// - it can compute `𝐾_𝑖 = (𝐶 ^ 𝑎_𝑗 𝐷 ^ 𝑏_𝑗 ) ^ 𝑥_𝑖` , and extract
/// `𝐾 = 𝐸_𝑖 ⊕ ℋ (𝐾_𝑖)`.
///
/// # Arguments
///
/// - `sk_j`                : user secret key
/// - `encapsulation`       : symmetric key encapsulation
pub fn decaps<
    const SYM_KEY_LENGTH: usize,
    const PUBLIC_KEY_LENGTH: usize,
    const PRIVATE_KEY_LENGTH: usize,
    SymmetricKey,
    KeyPair,
>(
    sk_j: &UserSecretKey<PRIVATE_KEY_LENGTH, KeyPair::PrivateKey>,
    encapsulation: &Encapsulation<
        SYM_KEY_LENGTH,
        PUBLIC_KEY_LENGTH,
        SymmetricKey,
        KeyPair::PublicKey,
    >,
) -> Result<Vec<SymmetricKey>, Error>
where
    SymmetricKey: SymKey<SYM_KEY_LENGTH>,
    KeyPair: DhKeyPair<PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH>,
    KeyPair::PublicKey: From<KeyPair::PrivateKey>,
    for<'a, 'b> &'a KeyPair::PublicKey: Add<&'b KeyPair::PublicKey, Output = KeyPair::PublicKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PublicKey>,
    for<'a, 'b> &'a KeyPair::PrivateKey: Add<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Sub<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Div<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>,
{
    let mut res = Vec::with_capacity(sk_j.x.len() * encapsulation.E.len());
    let precomp = &(&encapsulation.C * &sk_j.a) + &(&encapsulation.D * &sk_j.b);
    for E_i in &encapsulation.E {
        for x_k in sk_j.x.values() {
            let K_k = &precomp * x_k;
            let mut K = kdf!(SYM_KEY_LENGTH, &K_k.to_bytes(), KEY_GEN_INFO.as_bytes());
            for (e_1, e_2) in K.iter_mut().zip(E_i.as_bytes()) {
                *e_1 ^= e_2;
            }
            res.push(SymmetricKey::from_bytes(K));
        }
    }
    Ok(res)
}

/// Update the master secret key and master public key of the CoverCrypt
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
pub fn update<const PUBLIC_KEY_LENGTH: usize, const PRIVATE_KEY_LENGTH: usize, R, KeyPair>(
    rng: &mut R,
    msk: &mut MasterSecretKey<PRIVATE_KEY_LENGTH, KeyPair::PrivateKey>,
    mpk: &mut PublicKey<PUBLIC_KEY_LENGTH, KeyPair::PublicKey>,
    partitions_set: &HashSet<Partition>,
) -> Result<(), Error>
where
    R: CryptoRng + RngCore,
    KeyPair: DhKeyPair<PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH>,
    KeyPair::PublicKey: From<KeyPair::PrivateKey>,
    for<'a, 'b> &'a KeyPair::PublicKey: Add<&'b KeyPair::PublicKey, Output = KeyPair::PublicKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PublicKey>,
    for<'a, 'b> &'a KeyPair::PrivateKey: Add<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Sub<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Div<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>,
{
    // add keys for partitions that do not exist in the master keys
    let S = KeyPair::PublicKey::from(msk.s.clone());
    for partition in partitions_set {
        if !msk.x.contains_key(partition) || !mpk.H.contains_key(partition) {
            let x_i = KeyPair::PrivateKey::new(rng);
            let H_i = &S * &x_i;
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

/// Refresh a user key from the master secret key and a list of partitions.
/// The partitions MUST exist in the master secret key.
///
/// If a partition exists in the user key but is not in the list, it will be removed from the user key.
///
/// If a partition exists in the list, but not in the user key, it will be "added" to the user key,
/// by copying the proper partition key from the master secret key
pub fn refresh<const PRIVATE_KEY_LENGTH: usize, PrivateKey>(
    msk: &MasterSecretKey<PRIVATE_KEY_LENGTH, PrivateKey>,
    usk: &mut UserSecretKey<PRIVATE_KEY_LENGTH, PrivateKey>,
    user_set: &HashSet<Partition>,
) -> Result<(), Error>
where
    PrivateKey: KeyTrait<PRIVATE_KEY_LENGTH>,
{
    // add keys for partitions that do not exist
    for partition in user_set {
        if !usk.x.contains_key(partition) {
            // extract key from master secret key (see join)
            let kem_private_key = msk.x.get(partition).ok_or_else(|| {
                Error::UnknownPartition(format!(
                    "the master secret key does not contain the partition: {partition:?}"
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
    use cosmian_crypto_core::{
        asymmetric_crypto::curve25519::X25519KeyPair,
        entropy::CsRng,
        symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, key::Key, Dem},
    };

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
        let (msk, mpk) = setup::<
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            X25519KeyPair,
        >(&mut rng, &partitions_set);
        let msk_ = MasterSecretKey::try_from_bytes(&msk.try_to_bytes()?)?;
        assert_eq!(msk, msk_, "Master secret key comparisons failed");
        let mpk_ = PublicKey::try_from_bytes(&mpk.try_to_bytes()?)?;
        assert_eq!(mpk, mpk_, "Master public key comparison failed");
        let usk = join::<
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            X25519KeyPair,
        >(&mut rng, &msk, &user_set)?;
        let usk_ = UserSecretKey::try_from_bytes(&usk.try_to_bytes()?)?;
        assert_eq!(usk, usk_, "User secret key comparison failed");
        let sym_key = Key::<SYM_KEY_LENGTH>::new(&mut rng);
        let encapsulation = encaps::<
            { Aes256GcmCrypto::KEY_LENGTH },
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            <Aes256GcmCrypto as Dem<{ Aes256GcmCrypto::KEY_LENGTH }>>::Key,
            X25519KeyPair,
        >(&mut rng, &mpk, &target_set, &sym_key)?;
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
        let (mut msk, mut mpk) = setup::<
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            X25519KeyPair,
        >(&mut rng, &partitions_set);
        // generate user secret keys
        let mut sk0 = join::<
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            X25519KeyPair,
        >(&mut rng, &msk, &users_set[0])?;
        let sk1 = join::<
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            X25519KeyPair,
        >(&mut rng, &msk, &users_set[1])?;
        // encapsulate for the target set
        let sym_key = Key::<SYM_KEY_LENGTH>::new(&mut rng);
        let encapsulation = encaps::<
            { Aes256GcmCrypto::KEY_LENGTH },
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            <Aes256GcmCrypto as Dem<{ Aes256GcmCrypto::KEY_LENGTH }>>::Key,
            X25519KeyPair,
        >(&mut rng, &mpk, &target_set, &sym_key)?;
        // decapsulate for users 1 and 3
        let res0 = decaps::<
            { Aes256GcmCrypto::KEY_LENGTH },
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            <Aes256GcmCrypto as Dem<{ Aes256GcmCrypto::KEY_LENGTH }>>::Key,
            X25519KeyPair,
        >(&sk0, &encapsulation)?;
        let res1 = decaps::<
            { Aes256GcmCrypto::KEY_LENGTH },
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            <Aes256GcmCrypto as Dem<{ Aes256GcmCrypto::KEY_LENGTH }>>::Key,
            X25519KeyPair,
        >(&sk1, &encapsulation)?;
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
        update::<
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            X25519KeyPair,
        >(&mut rng, &mut msk, &mut mpk, &new_partitions_set)?;
        refresh(&msk, &mut sk0, &HashSet::from([client_partition]))?;
        println!("msk: {:?}", msk.x);
        println!("usk: {:?}", sk0.x);
        println!("{sym_key:?}");
        let new_encapsulation = encaps::<
            { Aes256GcmCrypto::KEY_LENGTH },
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            <Aes256GcmCrypto as Dem<{ Aes256GcmCrypto::KEY_LENGTH }>>::Key,
            X25519KeyPair,
        >(&mut rng, &mpk, &new_partitions_set, &sym_key)?;
        let res0 = decaps::<
            { Aes256GcmCrypto::KEY_LENGTH },
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            <Aes256GcmCrypto as Dem<{ Aes256GcmCrypto::KEY_LENGTH }>>::Key,
            X25519KeyPair,
        >(&sk0, &new_encapsulation)?;
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
        let (mut msk, mut mpk) = setup::<
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            X25519KeyPair,
        >(&mut rng, &partitions_set);

        // now remove partition 1 and add partition 3
        let partition_3 = Partition(b"3".to_vec());
        let new_partitions_set = HashSet::from([partition_2.clone(), partition_3.clone()]);
        update::<
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            X25519KeyPair,
        >(&mut rng, &mut msk, &mut mpk, &new_partitions_set)?;
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
        let (mut msk, mut mpk) = setup::<
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            X25519KeyPair,
        >(&mut rng, &partitions_set);
        // create a user key with access to partition 1 and 2
        let mut usk = join::<
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            X25519KeyPair,
        >(
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
        update::<
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            X25519KeyPair,
        >(&mut rng, &mut msk, &mut mpk, &new_partitions_set)?;
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
