//! Implements the cryptographic primitives of CoverCrypt, based on
//! `../bib/CoverCrypt.pdf`.

// Allows using the paper notations
#![allow(non_snake_case)]

use crate::{eakem_hash, encapsulation_length, error::Error, partitions::Partition};
use cosmian_crypto_core::{
    asymmetric_crypto::DhKeyPair,
    bytes_ser_de::{to_leb128_len, Deserializer, Serializable, Serializer},
    kdf,
    reexport::rand_core::{CryptoRng, RngCore},
    symmetric_crypto::SymKey,
    KeyTrait,
};
#[cfg(feature = "hybrid")]
use pqc_kyber::{
    indcpa::{indcpa_dec, indcpa_enc, indcpa_keypair},
    KYBER_INDCPA_BYTES, KYBER_INDCPA_PUBLICKEYBYTES, KYBER_INDCPA_SECRETKEYBYTES, KYBER_SSBYTES,
    KYBER_SYMBYTES,
};
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
    ops::{Add, Div, Mul, Sub},
};
use zeroize::Zeroize;

/// Xor the two given byte arrays.
fn xor<const LENGTH: usize>(a: &[u8; LENGTH], b: &[u8; LENGTH]) -> [u8; LENGTH] {
    let mut res = [0; LENGTH];
    for (i, byte) in res.iter_mut().enumerate() {
        *byte = a[i] ^ b[i];
    }
    res
}

/// Length of the EAKEM tag
// TODO TBZ: use as constant generic ?
type Tag<const LENGTH: usize> = [u8; LENGTH];

/// Length of the symmetric key. When hybridizing with Kyber, this length
/// should be `KYBER_SSBYTES` to ensure the `Xor` operation covers the whole
/// key and the AES security is still 128 post-quantum bits.
#[cfg(feature = "hybrid")]
pub const SYM_KEY_LENGTH: usize = KYBER_SSBYTES;

/// Additional information to generate symmetric key using the KDF.
const KEY_GEN_INFO: &[u8] = b"key generation info";

// Kyber public key length
#[cfg(feature = "hybrid")]
type KyberPublicKey = [u8; KYBER_INDCPA_PUBLICKEYBYTES];

// Kyber secret key length
#[cfg(feature = "hybrid")]
type KyberSecretKey = [u8; KYBER_INDCPA_SECRETKEYBYTES];

/// CoverCrypt master secret key.
///
/// It is composed of `u`, `v` and `s`, three randomly chosen scalars,
/// and the scalars `x_i` associated to all subsets `S_i`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterSecretKey<
    const PRIVATE_KEY_LENGTH: usize,
    PrivateKey: KeyTrait<PRIVATE_KEY_LENGTH>,
> {
    u: PrivateKey,
    v: PrivateKey,
    s: PrivateKey,
    #[cfg(feature = "hybrid")]
    pub(crate) x: HashMap<Partition, (KyberSecretKey, PrivateKey)>,
    #[cfg(not(feature = "hybrid"))]
    pub(crate) x: HashMap<Partition, PrivateKey>,
}

impl<const PRIVATE_KEY_LENGTH: usize, PrivateKey: KeyTrait<PRIVATE_KEY_LENGTH>> Serializable
    for MasterSecretKey<PRIVATE_KEY_LENGTH, PrivateKey>
{
    type Error = Error;

    #[inline]
    fn length(&self) -> usize {
        let length = 3 * PRIVATE_KEY_LENGTH
                + to_leb128_len(self.x.len())
                // compute the length of all the partitions
                + self
                    .x
                    .iter()
                    .map(|(partition, _)| to_leb128_len(partition.len()) + partition.len())
                    .sum::<usize>();
        #[cfg(feature = "hybrid")]
        {
            length + self.x.len() * (PRIVATE_KEY_LENGTH + KYBER_INDCPA_SECRETKEYBYTES)
        }
        #[cfg(not(feature = "hybrid"))]
        {
            length + self.x.len() * PRIVATE_KEY_LENGTH
        }
    }

    /// Serialize the master secret key.
    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(&self.u.to_bytes())?;
        n += ser.write_array(&self.v.to_bytes())?;
        n += ser.write_array(&self.s.to_bytes())?;
        n += ser.write_u64(self.x.len() as u64)?;
        #[cfg(feature = "hybrid")]
        for (partition, (sk_i, x_i)) in &self.x {
            n += ser.write_vec(partition)?;
            n += ser.write_array(sk_i)?;
            n += ser.write_array(&x_i.to_bytes())?;
        }
        #[cfg(not(feature = "hybrid"))]
        for (partition, x_i) in &self.x {
            n += ser.write_vec(partition)?;
            n += ser.write_array(&x_i.to_bytes())?;
        }
        Ok(n)
    }

    /// Deserialize the master secret key from the given bytes.
    ///
    /// - `bytes`   : bytes from which to read the master secret key
    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let u = PrivateKey::try_from_bytes(&de.read_array::<PRIVATE_KEY_LENGTH>()?)?;
        let v = PrivateKey::try_from_bytes(&de.read_array::<PRIVATE_KEY_LENGTH>()?)?;
        let s = PrivateKey::try_from_bytes(&de.read_array::<PRIVATE_KEY_LENGTH>()?)?;
        let x_len = <usize>::try_from(de.read_u64()?)?;
        let mut x = HashMap::with_capacity(x_len);
        for _ in 0..x_len {
            let partition = de.read_vec()?;
            #[cfg(feature = "hybrid")]
            let sk_i = de.read_array::<KYBER_INDCPA_SECRETKEYBYTES>()?;
            let x_i = de.read_array::<PRIVATE_KEY_LENGTH>()?;
            #[cfg(feature = "hybrid")]
            x.insert(
                Partition::from(partition),
                (sk_i, PrivateKey::try_from_bytes(&x_i)?),
            );
            #[cfg(not(feature = "hybrid"))]
            x.insert(
                Partition::from(partition),
                PrivateKey::try_from_bytes(&x_i)?,
            );
        }
        Ok(Self { u, v, s, x })
    }
}

impl<const PRIVATE_KEY_LENGTH: usize, PrivateKey: KeyTrait<PRIVATE_KEY_LENGTH>> Zeroize
    for MasterSecretKey<PRIVATE_KEY_LENGTH, PrivateKey>
{
    #[inline]
    fn zeroize(&mut self) {
        self.u.zeroize();
        self.v.zeroize();
        self.s.zeroize();
        #[cfg(feature = "hybrid")]
        self.x.iter_mut().for_each(|(_, (sk_i, x_i))| {
            sk_i.zeroize();
            x_i.zeroize();
        });
        #[cfg(not(feature = "hybrid"))]
        self.x.iter_mut().for_each(|(_, x_i)| {
            x_i.zeroize();
        });
    }
}

impl<const PRIVATE_KEY_LENGTH: usize, PrivateKey: KeyTrait<PRIVATE_KEY_LENGTH>> Drop
    for MasterSecretKey<PRIVATE_KEY_LENGTH, PrivateKey>
{
    #[inline]
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
pub struct UserSecretKey<
    const PRIVATE_KEY_LENGTH: usize,
    PrivateKey: KeyTrait<PRIVATE_KEY_LENGTH> + Hash,
> {
    a: PrivateKey,
    b: PrivateKey,
    #[cfg(feature = "hybrid")]
    pub(crate) x: HashSet<(KyberSecretKey, PrivateKey)>,
    #[cfg(not(feature = "hybrid"))]
    pub(crate) x: HashSet<PrivateKey>,
}

impl<const PRIVATE_KEY_LENGTH: usize, PrivateKey: KeyTrait<PRIVATE_KEY_LENGTH> + Hash> Serializable
    for UserSecretKey<PRIVATE_KEY_LENGTH, PrivateKey>
{
    type Error = Error;

    #[inline]
    fn length(&self) -> usize {
        let length = 2 * PRIVATE_KEY_LENGTH + to_leb128_len(self.x.len());
        #[cfg(feature = "hybrid")]
        {
            length + self.x.len() * (PRIVATE_KEY_LENGTH + KYBER_INDCPA_SECRETKEYBYTES)
        }
        #[cfg(not(feature = "hybrid"))]
        {
            length + self.x.len() * PRIVATE_KEY_LENGTH
        }
    }

    /// Serializes the user secret key.
    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(&self.a.to_bytes())?;
        n += ser.write_array(&self.b.to_bytes())?;
        n += ser.write_u64(self.x.len() as u64)?;
        #[cfg(feature = "hybrid")]
        for (sk_i, x_i) in &self.x {
            n += ser.write_array(sk_i)?;
            n += ser.write_array(&x_i.to_bytes())?;
        }
        #[cfg(not(feature = "hybrid"))]
        for x_i in &self.x {
            n += ser.write_array(&x_i.to_bytes())?;
        }
        Ok(n)
    }

    /// Deserializes the user secret key.
    ///
    /// - `bytes`   : bytes from which to read the user secret key
    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let a = PrivateKey::try_from_bytes(&de.read_array::<PRIVATE_KEY_LENGTH>()?)?;
        let b = PrivateKey::try_from_bytes(&de.read_array::<PRIVATE_KEY_LENGTH>()?)?;
        let x_len = <usize>::try_from(de.read_u64()?)?;
        let mut x = HashSet::with_capacity(x_len);
        for _ in 0..x_len {
            #[cfg(feature = "hybrid")]
            let sk_i = de.read_array::<KYBER_INDCPA_SECRETKEYBYTES>()?;
            let x_i = de.read_array::<PRIVATE_KEY_LENGTH>()?;
            #[cfg(feature = "hybrid")]
            x.insert((sk_i, PrivateKey::try_from_bytes(&x_i)?));
            #[cfg(not(feature = "hybrid"))]
            x.insert(PrivateKey::try_from_bytes(&x_i)?);
        }
        Ok(Self { a, b, x })
    }
}

impl<const PRIVATE_KEY_LENGTH: usize, PrivateKey: KeyTrait<PRIVATE_KEY_LENGTH> + Hash> Zeroize
    for UserSecretKey<PRIVATE_KEY_LENGTH, PrivateKey>
{
    #[inline]
    fn zeroize(&mut self) {
        self.a.zeroize();
        self.b.zeroize();
        self.x.clear();
    }
}

impl<const PRIVATE_KEY_LENGTH: usize, PrivateKey: KeyTrait<PRIVATE_KEY_LENGTH> + Hash> Drop
    for UserSecretKey<PRIVATE_KEY_LENGTH, PrivateKey>
{
    #[inline]
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
pub struct PublicKey<const PUBLIC_KEY_LENGTH: usize, DhPublicKey: KeyTrait<PUBLIC_KEY_LENGTH>> {
    U: DhPublicKey,
    V: DhPublicKey,
    #[cfg(feature = "hybrid")]
    pub(crate) H: HashMap<Partition, (KyberPublicKey, DhPublicKey)>,
    #[cfg(not(feature = "hybrid"))]
    pub(crate) H: HashMap<Partition, DhPublicKey>,
}

impl<const PUBLIC_KEY_LENGTH: usize, PK: KeyTrait<PUBLIC_KEY_LENGTH>> Serializable
    for PublicKey<PUBLIC_KEY_LENGTH, PK>
{
    type Error = Error;

    #[inline]
    fn length(&self) -> usize {
        let length = 2 * PUBLIC_KEY_LENGTH
            + to_leb128_len(self.H.len())
            // compute the length of all the partitions
            + self
                .H
                .iter()
                .map(|(partition, _)| to_leb128_len(partition.len()) + partition.len())
                .sum::<usize>();

        #[cfg(feature = "hybrid")]
        {
            length + self.H.len() * (PUBLIC_KEY_LENGTH + KYBER_INDCPA_PUBLICKEYBYTES)
        }
        #[cfg(not(feature = "hybrid"))]
        {
            length + self.H.len() * PUBLIC_KEY_LENGTH
        }
    }

    /// Serializes the public key.
    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(&self.U.to_bytes())?;
        n += ser.write_array(&self.V.to_bytes())?;
        n += ser.write_u64(self.H.len() as u64)?;
        #[cfg(feature = "hybrid")]
        for (partition, (pk_i, H_i)) in &self.H {
            n += ser.write_vec(partition)?;
            n += ser.write_array(pk_i)?;
            n += ser.write_array(&H_i.to_bytes())?;
        }
        #[cfg(not(feature = "hybrid"))]
        for (partition, H_i) in &self.H {
            n += ser.write_vec(partition)?;
            n += ser.write_array(&H_i.to_bytes())?;
        }
        Ok(n)
    }

    /// Deserializes the public key.
    ///
    /// - `bytes`   : bytes from which to read the public key
    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let U = PK::try_from_bytes(&de.read_array::<PUBLIC_KEY_LENGTH>()?)?;
        let V = PK::try_from_bytes(&de.read_array::<PUBLIC_KEY_LENGTH>()?)?;
        let H_len = <usize>::try_from(de.read_u64()?)?;
        let mut H = HashMap::with_capacity(H_len);
        for _ in 0..H_len {
            let partition = de.read_vec()?;
            #[cfg(feature = "hybrid")]
            let pk_i = de.read_array::<KYBER_INDCPA_PUBLICKEYBYTES>()?;
            let H_i = de.read_array::<PUBLIC_KEY_LENGTH>()?;
            H.insert(
                Partition::from(partition),
                #[cfg(feature = "hybrid")]
                (pk_i, PK::try_from_bytes(&H_i)?),
                #[cfg(not(feature = "hybrid"))]
                PK::try_from_bytes(&H_i)?,
            );
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
    const TAG_LENGTH: usize,
    const ENCAPSULATION_LENGTH: usize,
    const PUBLIC_KEY_LENGTH: usize,
    PublicKey: KeyTrait<PUBLIC_KEY_LENGTH>,
> {
    C: PublicKey,
    D: PublicKey,
    tag: Tag<TAG_LENGTH>,
    E: HashSet<[u8; ENCAPSULATION_LENGTH]>,
}

impl<
        const TAG_LENGTH: usize,
        const ENCAPSULATION_LENGTH: usize,
        const PUBLIC_KEY_LENGTH: usize,
        PublicKey: KeyTrait<PUBLIC_KEY_LENGTH>,
    > Serializable
    for Encapsulation<TAG_LENGTH, ENCAPSULATION_LENGTH, PUBLIC_KEY_LENGTH, PublicKey>
{
    type Error = Error;

    fn length(&self) -> usize {
        2 * PUBLIC_KEY_LENGTH
            + TAG_LENGTH
            + to_leb128_len(self.E.len())
            + self.E.len() * ENCAPSULATION_LENGTH
    }

    /// Serializes the encapsulation.
    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(&self.C.to_bytes())?;
        n += ser.write_array(&self.D.to_bytes())?;
        n += ser.write_array(&self.tag)?;
        n += ser.write_u64(self.E.len() as u64)?;
        for encapsulation in &self.E {
            n += ser.write_array(encapsulation)?;
        }
        Ok(n)
    }

    /// Deserializes the encapsulation.
    ///
    /// - `bytes`   : bytes from which to read the encapsulation
    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let C = PublicKey::try_from_bytes(&de.read_array::<PUBLIC_KEY_LENGTH>()?)?;
        let D = PublicKey::try_from_bytes(&de.read_array::<PUBLIC_KEY_LENGTH>()?)?;
        let tag = de.read_array::<TAG_LENGTH>()?;
        let E_len = <usize>::try_from(de.read_u64()?)?;
        let mut E = HashSet::with_capacity(E_len);
        for _ in 0..E_len {
            E.insert(de.read_array::<ENCAPSULATION_LENGTH>()?);
        }
        Ok(Self { C, D, tag, E })
    }
}

/// Generates the master secret key and master public key of the CoverCrypt
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
    let u = KeyPair::PrivateKey::new(rng);
    let v = KeyPair::PrivateKey::new(rng);
    let s = KeyPair::PrivateKey::new(rng);
    let U = KeyPair::PublicKey::from(u.clone());
    let V = KeyPair::PublicKey::from(v.clone());
    let S = KeyPair::PublicKey::from(s.clone());

    let mut x = HashMap::with_capacity(partitions.len());
    let mut H = HashMap::with_capacity(partitions.len());

    #[cfg(feature = "hybrid")]
    for partition in partitions {
        let (mut sk_pq, mut pk_pq) = (
            [0; KYBER_INDCPA_SECRETKEYBYTES],
            [0; KYBER_INDCPA_PUBLICKEYBYTES],
        );
        pqc_kyber::indcpa::indcpa_keypair(&mut pk_pq, &mut sk_pq, None, rng);
        let x_i = KeyPair::PrivateKey::new(rng);
        let H_i = &S * &x_i;
        x.insert(partition.clone(), (sk_pq, x_i));
        H.insert(partition.clone(), (pk_pq, H_i));
    }
    #[cfg(not(feature = "hybrid"))]
    for partition in partitions {
        let x_i = KeyPair::PrivateKey::new(rng);
        let H_i = &S * &x_i;
        x.insert(partition.clone(), x_i);
        H.insert(partition.clone(), H_i);
    }

    (MasterSecretKey { u, v, s, x }, PublicKey { U, V, H })
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
    KeyPair::PrivateKey: Hash,
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
                Some(x_i.clone())
            } else {
                None
            }
        })
        .collect();
    Ok(UserSecretKey { a, b, x })
}

/// Generates the secret key encapsulation.
///
/// Implements the Early Abort KEM (EAKEM) encapsulation to filter
/// encapsulations in the decapsulation phase.
///
/// Encaps(pk):
///     (c, k) ← KEM.encaps(pk)
///     (k1, k2) ← H(k)
///     return (k1, k2, c)
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
    const TAG_LENGTH: usize,
    #[cfg(not(feature = "hybrid"))] const SYM_KEY_LENGTH: usize,
    const PUBLIC_KEY_LENGTH: usize,
    const PRIVATE_KEY_LENGTH: usize,
    R,
    SymmetricKey,
    KeyPair,
>(
    rng: &mut R,
    mpk: &PublicKey<PUBLIC_KEY_LENGTH, KeyPair::PublicKey>,
    encryption_set: &HashSet<Partition>,
) -> Result<
    (
        SymmetricKey,
        Encapsulation<
            TAG_LENGTH,
            { encapsulation_length!() },
            PUBLIC_KEY_LENGTH,
            KeyPair::PublicKey,
        >,
    ),
    Error,
>
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
    let mut K = [0; SYM_KEY_LENGTH];
    rng.fill_bytes(&mut K);
    let r = KeyPair::PrivateKey::new(rng);
    let C = &mpk.U * &r;
    let D = &mpk.V * &r;
    let mut E = HashSet::with_capacity(encryption_set.len());
    for partition in encryption_set {
        #[cfg(feature = "hybrid")]
        if let Some((pk_i, H_i)) = mpk.H.get(partition) {
            let K_i = (H_i * &r).to_bytes();
            let E_i = xor(&kdf!(SYM_KEY_LENGTH, &K_i), &K);
            // TODO TBZ: which coin to use ?
            let mut EPQ_i = [0; KYBER_INDCPA_BYTES];
            indcpa_enc(&mut EPQ_i, &E_i, pk_i, &[0; KYBER_SYMBYTES]);
            E.insert(EPQ_i);
        } // else may log a warning about unknown target partition
        #[cfg(not(feature = "hybrid"))]
        if let Some(H_i) = mpk.H.get(partition) {
            let K_i = (H_i * &r).to_bytes();
            let E_i = xor(&kdf!(SYM_KEY_LENGTH, &K_i), &K);
            E.insert(E_i);
        } // else may log a warning about unknown target partition
    }
    let (tag, K) = eakem_hash!(TAG_LENGTH, SYM_KEY_LENGTH, &K, KEY_GEN_INFO);
    Ok((SymmetricKey::from_bytes(K), Encapsulation { C, D, tag, E }))
}

/// Decapsulates the secret key if the given user ID is in the target set.
///
/// Implements the Early Abort KEM (EAKEM) decapsulation to filter
/// encapsulations that do not correspond to the user secret key.
///
/// Decaps(sk, k1, c):
///     k ← KEM.decaps(sk, c)
///     (k1*, k2*) ← H(k)
///     if k1 != k1':
///         abort
///     return k2*
///
/// # Paper
///
/// Dec(`SK_𝑗`, `(𝐶, 𝐷, (𝐸_𝑖 = 𝐾_𝑖 ⊕ 𝐾)_{𝑖∈𝐵})`): it takes as input a user’s
/// secret key and a ciphertext, it outputs the decrypted key `𝐾`.
///
/// - the user first chooses an index `𝑖 ∈ 𝐵 ∩ 𝐴_𝑗` , in both its set of rights
/// `𝐴_𝑗` and the rights `𝐵` of the ciphertext, and then uses `𝑥_𝑖 = sk_𝑖 ∈
/// SK_𝑗`;
///
/// - it can compute `𝐾_𝑖 = (𝐶 ^ 𝑎_𝑗 𝐷 ^ 𝑏_𝑗 ) ^ 𝑥_𝑖` , and extract
/// `𝐾 = 𝐸_𝑖 ⊕ ℋ (𝐾_𝑖)`.
///
/// # Arguments
///
/// - `sk_j`                : user secret key
/// - `encapsulation`       : symmetric key encapsulation
pub fn decaps<
    const TAG_LENGTH: usize,
    #[cfg(not(feature = "hybrid"))] const SYM_KEY_LENGTH: usize,
    const PUBLIC_KEY_LENGTH: usize,
    const PRIVATE_KEY_LENGTH: usize,
    SymmetricKey,
    KeyPair,
>(
    usk: &UserSecretKey<PRIVATE_KEY_LENGTH, KeyPair::PrivateKey>,
    encapsulation: &Encapsulation<
        TAG_LENGTH,
        { encapsulation_length!() },
        PUBLIC_KEY_LENGTH,
        KeyPair::PublicKey,
    >,
) -> Result<SymmetricKey, Error>
where
    SymmetricKey: SymKey<SYM_KEY_LENGTH>,
    KeyPair: DhKeyPair<PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH>,
    KeyPair::PublicKey: From<KeyPair::PrivateKey>,
    KeyPair::PrivateKey: Hash,
    for<'a, 'b> &'a KeyPair::PublicKey: Add<&'b KeyPair::PublicKey, Output = KeyPair::PublicKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PublicKey>,
    for<'a, 'b> &'a KeyPair::PrivateKey: Add<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Sub<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Div<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>,
{
    let precomp = &(&encapsulation.C * &usk.a) + &(&encapsulation.D * &usk.b);
    for encapsulation_i in &encapsulation.E {
        #[cfg(feature = "hybrid")]
        for (sk_j, x_j) in &usk.x {
            let mut E_j = [0; KYBER_SSBYTES];
            // TODO TBZ: which coin to use ?
            indcpa_dec(&mut E_j, encapsulation_i, sk_j);
            let K_j = (&precomp * x_j).to_bytes();
            let K = xor(&kdf!(SYM_KEY_LENGTH, &K_j), &E_j);
            let (tag, K) = eakem_hash!(TAG_LENGTH, SYM_KEY_LENGTH, &K, KEY_GEN_INFO);
            if tag == encapsulation.tag {
                return Ok(SymmetricKey::from_bytes(K));
            }
        }
        #[cfg(not(feature = "hybrid"))]
        for x_j in &usk.x {
            let K_j = (&precomp * x_j).to_bytes();
            let K = xor(&kdf!(SYM_KEY_LENGTH, &K_j), encapsulation_i);
            let (tag, K) = eakem_hash!(TAG_LENGTH, SYM_KEY_LENGTH, &K, KEY_GEN_INFO);
            if tag == encapsulation.tag {
                return Ok(SymmetricKey::from_bytes(K));
            }
        }
    }
    Err(Error::InsufficientAccessPolicy)
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
    #[cfg(feature = "hybrid")]
    for partition in partitions_set {
        if !msk.x.contains_key(partition) || !mpk.H.contains_key(partition) {
            let x_i = KeyPair::PrivateKey::new(rng);
            let H_i = &S * &x_i;
            let (mut sk_pq, mut pk_pq) = (
                [0; KYBER_INDCPA_SECRETKEYBYTES],
                [0; KYBER_INDCPA_PUBLICKEYBYTES],
            );
            indcpa_keypair(&mut pk_pq, &mut sk_pq, None, rng);
            msk.x.insert(partition.to_owned(), (sk_pq, x_i));
            mpk.H.insert(partition.to_owned(), (pk_pq, H_i));
        }
    }
    #[cfg(not(feature = "hybrid"))]
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
/// If a partition exists in the user key but is not in the list, it will be
/// removed from the user key.
///
/// If a partition exists in the list, but not in the user key, it will be
/// "added" to the user key, by copying the proper partition key from the master
/// secret key
pub fn refresh<const PRIVATE_KEY_LENGTH: usize, PrivateKey>(
    msk: &MasterSecretKey<PRIVATE_KEY_LENGTH, PrivateKey>,
    usk: &mut UserSecretKey<PRIVATE_KEY_LENGTH, PrivateKey>,
    user_set: &HashSet<Partition>,
    keep_old_accesses: bool,
) -> Result<(), Error>
where
    PrivateKey: KeyTrait<PRIVATE_KEY_LENGTH> + Hash,
{
    if !keep_old_accesses {
        // generate a fresh key
        usk.x = Default::default();
    }

    // add keys for partitions that do not exist
    for partition in user_set {
        if let Some(x_i) = msk.x.get(partition) {
            usk.x.insert(x_i.clone());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decaps, encaps, join, refresh, setup, update};
    use cosmian_crypto_core::{
        asymmetric_crypto::curve25519::X25519KeyPair,
        reexport::rand_core::SeedableRng,
        symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Dem},
        CsRng,
    };

    //
    // Define types and constants used in the tests
    //
    const TAG_LENGTH: usize = 32;
    #[cfg(not(feature = "hybrid"))]
    const SYM_KEY_LENGTH: usize = Aes256GcmCrypto::KEY_LENGTH;
    type KeyPair = X25519KeyPair;
    #[allow(clippy::upper_case_acronyms)]
    type DEM = Aes256GcmCrypto;
    //
    //

    #[test]
    fn test_serialization() -> Result<(), Error> {
        let admin_partition = Partition(b"admin".to_vec());
        let dev_partition = Partition(b"dev".to_vec());
        // partition list
        let partitions_set = HashSet::from([admin_partition.clone(), dev_partition.clone()]);
        // user list
        let user_set = HashSet::from([admin_partition.clone(), dev_partition.clone()]);
        // target set
        let target_set = HashSet::from([admin_partition, dev_partition]);
        // secure random number generator
        let mut rng = CsRng::from_entropy();
        // setup scheme
        let (msk, mpk) = setup::<
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            X25519KeyPair,
        >(&mut rng, &partitions_set);
        let bytes = msk.try_to_bytes()?;
        assert_eq!(bytes.len(), msk.length(), "Wrong master secret key length");
        let msk_ = MasterSecretKey::try_from_bytes(&bytes)?;
        assert_eq!(msk, msk_, "Master secret key comparisons failed");
        let bytes = mpk.try_to_bytes()?;
        assert_eq!(bytes.len(), mpk.length(), "Wrong master public key length");
        let mpk_ = PublicKey::try_from_bytes(&bytes)?;
        assert_eq!(mpk, mpk_, "Master public key comparison failed");
        let usk = join::<
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            X25519KeyPair,
        >(&mut rng, &msk, &user_set)?;
        let bytes = usk.try_to_bytes()?;
        assert_eq!(bytes.len(), usk.length(), "Wrong user secret key size");
        let usk_ = UserSecretKey::try_from_bytes(&bytes)?;
        assert_eq!(usk, usk_, "User secret key comparison failed");
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
            "Encapsulation comparison failed"
        );
        Ok(())
    }

    #[cfg(feature = "hybrid")]
    #[test]
    fn test_kyber() {
        let mut rng = CsRng::from_entropy();
        let keypair = pqc_kyber::keypair(&mut rng);
        let (ct, ss) = pqc_kyber::encapsulate(&keypair.public, &mut rng).unwrap();
        let res = pqc_kyber::decapsulate(&ct, &keypair.secret).unwrap();
        assert_eq!(ss, res, "Decapsulation failed!");
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
        let mut rng = CsRng::from_entropy();
        // setup scheme
        let (mut msk, mut mpk) = setup!(&mut rng, &partitions_set);
        // generate user secret keys
        let mut sk0 = join!(&mut rng, &msk, &users_set[0])?;
        let sk1 = join!(&mut rng, &msk, &users_set[1])?;
        // encapsulate for the target set
        let (sym_key, encapsulation) = encaps!(&mut rng, &mpk, &target_set)?;
        // decapsulate for users 1 and 3
        let res0 = decaps!(&sk0, &encapsulation);

        assert!(res0.is_err(), "User 0 shouldn't be able to decapsulate!");

        let res1 = decaps!(&sk1, &encapsulation)?;

        assert_eq!(sym_key, res1, "Wrong decapsulation for user 1!");

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
        refresh(&msk, &mut sk0, &HashSet::from([client_partition]), false)?;
        println!("msk: {:?}", msk.x);
        println!("usk: {:?}", sk0.x);
        println!("{sym_key:?}");
        let (sym_key, new_encapsulation) = encaps!(&mut rng, &mpk, &new_partitions_set)?;
        let res0 = decaps!(&sk0, &new_encapsulation)?;
        assert_eq!(sym_key, res0, "User 0 should be able to decapsulate!");
        Ok(())
    }

    #[test]
    fn test_master_keys_update() -> Result<(), Error> {
        let partition_1 = Partition(b"1".to_vec());
        let partition_2 = Partition(b"2".to_vec());
        // partition list
        let partitions_set = HashSet::from([partition_1.clone(), partition_2.clone()]);
        // secure random number generator
        let mut rng = CsRng::from_entropy();
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
        let mut rng = CsRng::from_entropy();
        // setup scheme
        let (mut msk, mut mpk) = setup!(&mut rng, &partitions_set);
        // create a user key with access to partition 1 and 2
        let mut usk = join!(
            &mut rng,
            &msk,
            &HashSet::from([partition_1.clone(), partition_2.clone()])
        )?;

        // now remove partition 1 and add partition 4
        let partition_4 = Partition(b"4".to_vec());
        let new_partition_set = HashSet::from([
            partition_2.clone(),
            partition_3.clone(),
            partition_4.clone(),
        ]);
        // update the master keys
        let old_msk = msk.clone();
        update!(&mut rng, &mut msk, &mut mpk, &new_partition_set)?;
        // refresh the user key with partitions 2 and 4
        refresh!(
            &msk,
            &mut usk,
            &HashSet::from([partition_2.clone(), partition_4.clone()]),
            false
        )?;
        assert!(!usk.x.contains(old_msk.x.get(&partition_1).unwrap()));
        assert!(usk.x.contains(msk.x.get(&partition_2).unwrap()));
        assert!(!usk.x.contains(old_msk.x.get(&partition_3).unwrap()));
        assert!(usk.x.contains(msk.x.get(&partition_4).unwrap()));
        Ok(())
    }
}
