use crate::{byte_scanner::BytesScanner, error::Error, utils};
use cosmian_crypto_base::{asymmetric::KeyPair, hybrid_crypto::Kem, KeyTrait};
use rand_core::{CryptoRng, RngCore};
use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
};

/// Partition associated to a KEM keypair. It corresponds to a combination
/// of attributes across all axes.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct Partition(Vec<u8>);

impl Partition {
    /// Create a Partition from the list of the attribute values
    /// which constitutes the "coordinates" of the partitions
    /// across all axes of the policy
    ///
    /// The attribute values MUST be unique across all axes
    pub fn new(mut attribute_values: Vec<u32>) -> Partition {
        // the sort operation allows to get the same hash for :
        // `Department::HR || Level::Secret`
        // and
        // `Level::Secret || Department::HR`
        attribute_values.sort_unstable();
        let mut bytes = Vec::with_capacity(attribute_values.len() * 4);
        for value in attribute_values {
            bytes.extend(value.to_be_bytes())
        }
        Partition(bytes)
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

impl TryFrom<String> for Partition {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let res = hex::decode(&value).map_err(|_e| Error::ConversionFailed)?;
        Ok(Partition(res))
    }
}

impl From<Vec<u8>> for Partition {
    fn from(value: Vec<u8>) -> Self {
        Partition(value)
    }
}

impl From<&[u8]> for Partition {
    fn from(value: &[u8]) -> Self {
        Partition(value.to_vec())
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

/// CovCrypt private keys are a set of KEM private keys.
///
/// The partition A into bytes MUST not exceed 2^32 bytes
/// The PrivateKey into bytes MUST not exceed 2^32 bytes
#[derive(Clone)]
pub struct PrivateKey<KEM>(pub HashMap<Partition, <<KEM as Kem>::KeyPair as KeyPair>::PrivateKey>)
where
    KEM: Kem;

impl<KEM> std::ops::Deref for PrivateKey<KEM>
where
    KEM: Kem,
{
    type Target = HashMap<Partition, <<KEM as Kem>::KeyPair as KeyPair>::PrivateKey>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<KEM> std::ops::DerefMut for PrivateKey<KEM>
where
    KEM: Kem,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<KEM> Debug for PrivateKey<KEM>
where
    KEM: Kem,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("Private Key: {:#?}", self.0.keys()))
    }
}

impl<KEM> PrivateKey<KEM>
where
    KEM: Kem,
{
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = vec![];
        self.0.iter().for_each(|(k, v)| {
            let p_bytes: Vec<u8> = k.into();
            res.extend((p_bytes.len() as u32).to_be_bytes());
            res.extend(p_bytes);
            let key_bytes = v.to_bytes();
            res.extend((key_bytes.len() as u32).to_be_bytes());
            res.extend(key_bytes);
        });
        res
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut scanner = BytesScanner::new(bytes);
        let mut map: HashMap<Partition, <<KEM as Kem>::KeyPair as KeyPair>::PrivateKey> =
            HashMap::new();
        while scanner.has_more() {
            let p_bytes_size = scanner.read_u32()? as usize;
            let p_bytes = scanner.next(p_bytes_size)?;
            let partition = Partition::try_from(p_bytes.to_vec())
                .map_err(|_| Error::Other("Failed generating partition from bytes".to_string()))?;
            let key_bytes_size = scanner.read_u32()? as usize;
            let key_bytes = scanner.next(key_bytes_size)?;
            let key =
                <<KEM as Kem>::KeyPair as KeyPair>::PrivateKey::try_from_bytes(key_bytes.to_vec())?;
            map.insert(partition, key);
        }
        Ok(Self(map))
    }
}

impl<KEM> PartialEq for PrivateKey<KEM>
where
    KEM: Kem,
{
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        for (k, v) in &self.0 {
            match other.0.get(k) {
                Some(v_other) => {
                    if v.to_bytes() != v_other.to_bytes() {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
}

/// CovCrypt public keys are a set of KEM public keys.
///
/// The partition A into bytes MUST not exceed 2^32 bytes
/// The PublicKey into bytes MUST not exceed 2^32 bytes
#[derive(Clone)]
pub struct PublicKey<KEM: Kem>(
    pub HashMap<Partition, <<KEM as Kem>::KeyPair as KeyPair>::PublicKey>,
);

impl<KEM: Kem> std::ops::Deref for PublicKey<KEM> {
    type Target = HashMap<Partition, <<KEM as Kem>::KeyPair as KeyPair>::PublicKey>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<KEM: Kem> std::ops::DerefMut for PublicKey<KEM> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<KEM> Debug for PublicKey<KEM>
where
    KEM: Kem,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("Public Key: {:#?}", self.0.keys()))
    }
}

impl<KEM> PublicKey<KEM>
where
    KEM: Kem,
{
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = vec![];
        self.0.iter().for_each(|(k, v)| {
            let p_bytes: Vec<u8> = k.into();
            let key_bytes = v.to_bytes();
            res.extend((p_bytes.len() as u32).to_be_bytes());
            res.extend(p_bytes);
            res.extend((key_bytes.len() as u32).to_be_bytes());
            res.extend(key_bytes);
        });
        res
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut scanner = BytesScanner::new(bytes);
        let mut map: HashMap<Partition, <<KEM as Kem>::KeyPair as KeyPair>::PublicKey> =
            HashMap::new();
        while scanner.has_more() {
            let p_bytes_size = scanner.read_u32()? as usize;
            let p_bytes = scanner.next(p_bytes_size)?;
            let partition = Partition::from(p_bytes.to_vec());
            let key_bytes_size = scanner.read_u32()? as usize;
            let key_bytes = scanner.next(key_bytes_size)?;
            let key =
                <<KEM as Kem>::KeyPair as KeyPair>::PublicKey::try_from_bytes(key_bytes.to_vec())?;
            map.insert(partition, key);
        }
        Ok(Self(map))
    }
}

impl<KEM> PartialEq for PublicKey<KEM>
where
    KEM: Kem,
{
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        for (k, v) in &self.0 {
            match other.0.get(k) {
                Some(v_other) => {
                    if v.to_bytes() != v_other.to_bytes() {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
}

/// CovCrypt ciphertexts are a list of secret key / encapsulation couples
/// generated by the underlying KEM scheme.
///
/// The partition A into bytes MUST not exceed 2^32 bytes
/// The Key and encryption of the key into bytes MUST not exceed 2^32 bytes each
#[derive(Clone)]
pub struct Encapsulation(pub HashMap<Partition, (Vec<u8>, Vec<u8>)>);

impl std::ops::Deref for Encapsulation {
    type Target = HashMap<Partition, (Vec<u8>, Vec<u8>)>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Encapsulation {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Encapsulation {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = vec![];
        self.0.iter().for_each(|(k, (key, ciphertext))| {
            let p_bytes: Vec<u8> = k.into();
            res.extend((p_bytes.len() as u32).to_be_bytes());
            res.extend(p_bytes);
            res.extend((key.len() as u32).to_be_bytes());
            res.extend(key);
            res.extend((ciphertext.len() as u32).to_be_bytes());
            res.extend(ciphertext);
        });
        res
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut scanner = BytesScanner::new(bytes);
        let mut map: HashMap<Partition, (Vec<u8>, Vec<u8>)> = HashMap::new();
        while scanner.has_more() {
            let p_bytes_size = scanner.read_u32()? as usize;
            let p_bytes = scanner.next(p_bytes_size)?;
            let partition = Partition::from(p_bytes.to_vec());
            let key_bytes_size = scanner.read_u32()? as usize;
            let key_bytes = scanner.next(key_bytes_size)?;
            let key = key_bytes.to_vec();
            let ct_bytes_size = scanner.read_u32()? as usize;
            let ct_bytes = scanner.next(ct_bytes_size)?;
            let ciphertext = ct_bytes.to_vec();
            map.insert(partition, (key, ciphertext));
        }
        Ok(Self(map))
    }
}

/// CovCrypt secret key is a vector of bytes of the same length as secret key
/// of the underlying KEM.
#[derive(Clone, PartialEq, Debug)]
pub struct SecretKey(pub Vec<u8>);

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
        SecretKey(v)
    }
}

impl From<SecretKey> for Vec<u8> {
    fn from(sk: SecretKey) -> Self {
        sk.0.to_vec()
    }
}

/// Generate the master private key and master public key of the CoverCrypt scheme.
///
/// - `n`   : number of partition groups
///
/// Setup : `λ → (msk,mpk)`
///  - takes the security parameter (number of security bits we would like to
/// reach).
///
/// It first defines the partition of subsets Sᵢ that covers the set S
/// with respect to the target users’ rights.
///
/// And for each Sᵢ, it invokes (`KEM.KeyGen` which outputs `(pkᵢ,skᵢ)` and
/// defines `mpk = (pkᵢ)ᵢ` and `msk = (skᵢ)ᵢ` the master public key and master
/// secret key.
pub fn setup<R, KEM>(
    rng: &mut R,
    partitions_set: &HashSet<Partition>,
) -> (PrivateKey<KEM>, PublicKey<KEM>)
where
    R: CryptoRng + RngCore,
    KEM: Kem,
{
    let (mut msk, mut mpk) = (
        PrivateKey(HashMap::with_capacity(partitions_set.len())),
        PublicKey(HashMap::with_capacity(partitions_set.len())),
    );
    for partition in partitions_set.iter() {
        let keypair = KEM::key_gen(rng);
        // let partition = partition.to_owned();
        msk.insert(partition.to_owned(), keypair.private_key().to_owned());
        mpk.insert(partition.to_owned(), keypair.public_key().to_owned());
    }
    (msk, mpk)
}

/// Generate a user private key for a given list of user groups. It is composed
/// by the list of the KEM private keys associated with the user groups
/// containing the given user ID.
///
/// - `msk` : master secret key
/// - `U`   : user partitions
///
/// Join : `(msk, U) → skU`
///
/// For a user U, define skU as the set of secret keys ski for each i such that
/// U ∈ Si (meaning U has rights associated to set Si).
pub fn join<KEM>(
    msk: &PrivateKey<KEM>,
    user_set: &HashSet<Partition>,
) -> Result<PrivateKey<KEM>, Error>
where
    KEM: Kem,
{
    user_set.iter()
        .map(|partition| {
            let kem_private_ley = msk
                .get(partition)
                .ok_or_else(|| Error::UnknownPartition(format!("{partition:?}")))?;
            Ok((partition.to_owned(), kem_private_ley.to_owned()))
        })
        .collect::<Result<HashMap<Partition, <<KEM as Kem>::KeyPair as KeyPair>::PrivateKey>, Error>>()
        .map(|m| PrivateKey(m))
}

/// Generate the secret key and its encapsulation.
///
/// - `rng` : secure random number generator
/// - `mpk` : master public key
/// - `T`   : target groups
/// - `S`   : user groups
///
/// Encaps : `(mpk, T) → C = (K, Ci = (Ki ⊕ K, Ei)i∈A)`
///
/// Takes as input mpk and target set T. It first samples a random key K and
/// express T as set of covering subsets, i.e T = ∪i∈ASi.
/// Then for each i ∈ A, it invokes KEM.Encaps which Ci = (Ki, Ei)i∈A. It
/// finally returns (K, C = (Ki ⊕ K, Ei)i∈A).
pub fn encaps<R, KEM>(
    rng: &mut R,
    mpk: &PublicKey<KEM>,
    target_group: &HashSet<Partition>,
    secret_key_length: usize,
) -> Result<(SecretKey, Encapsulation), Error>
where
    R: CryptoRng + RngCore,
    KEM: Kem,
{
    // secret key
    let secret_key = SecretKey(utils::generate_random_bytes(rng, secret_key_length));

    // construct secret key encapsulation
    let encapsulation = target_group
        .iter()
        .map(|partition| {
            let kem_public_key = mpk
                .get(partition)
                .ok_or_else(|| Error::UnknownPartition(format!("{partition:?}")))?;
            let (k_i, e_i) =
                KEM::encaps(rng, kem_public_key, secret_key_length).map_err(Error::CryptoError)?;
            println!("k_i size: {}, e_i size: {}", k_i.len(), e_i.len());
            Ok((
                partition.to_owned(),
                (
                    k_i.iter()
                        .zip(secret_key.iter())
                        .map(|(e1, e2)| e1 ^ e2)
                        .collect(),
                    e_i,
                ),
            ))
        })
        .collect::<Result<HashMap<Partition, (Vec<u8>, Vec<u8>)>, Error>>()
        .map(Encapsulation)?;

    Ok((secret_key, encapsulation))
}

/// Decapsulate the secret key if the given user ID is in the target set.
///
/// - `uid`     : user ID
/// - `sk_u`    : user private key
/// - `E`       : encapsulation
/// - `T`       : target set
/// - `S`       : list of all user groups
///
/// • Decaps: (skU, C) → K
///
/// Let T = ∪i∈BSi for some integers set B and A the indices of sets associated
/// to C.
/// If user U is in T, and there exists an index i ∈ A such that U is in
/// Si ⊆ T, it invokes KEM.Decaps(ski, Ei) which gives Ki. Then using the
/// corresponding Ci parsed as Ki', Ei, it obtains K = Ki' ⊕ Ki.
pub fn decaps<KEM>(
    sk_u: &PrivateKey<KEM>,
    encapsulation: &Encapsulation,
    secret_key_length: usize,
) -> Result<Option<SecretKey>, Error>
where
    KEM: Kem,
{
    for (partition, (ki_1, e_i)) in encapsulation.iter() {
        if let Some(sk) = sk_u.get(partition) {
            let ki_2 = KEM::decaps(sk, e_i, secret_key_length).map_err(Error::CryptoError)?;

            // XOR the two `K_i`
            let secret_key = SecretKey(
                ki_1.iter()
                    .zip(ki_2.iter())
                    .map(|(e1, e2)| e1 ^ e2)
                    .collect::<Vec<u8>>(),
            );
            return Ok(Some(secret_key));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmian_crypto_base::asymmetric::ristretto::X25519Crypto;
    use cosmian_crypto_base::entropy::CsRng;

    #[test]
    fn test_ser_de() -> Result<(), Error> {
        let admin_partition = Partition("admin".as_bytes().to_vec());
        let dev_partition = Partition("dev".as_bytes().to_vec());
        // partition list
        let partitions_set = HashSet::from([admin_partition.clone(), dev_partition.clone()]);
        // user list
        let user_set = HashSet::from([admin_partition, dev_partition]);
        // secure random number generator
        let mut rng = CsRng::new();
        // setup scheme
        let (msk, mpk) = setup::<_, X25519Crypto>(&mut rng, &partitions_set);
        let msk_: PrivateKey<X25519Crypto> = PrivateKey::try_from_bytes(&msk.to_bytes())?;
        assert_eq!(msk, msk_, "master key comparisons failed");
        let mpk_: PublicKey<X25519Crypto> = PublicKey::try_from_bytes(&mpk.to_bytes())?;
        assert_eq!(mpk, mpk_);
        let usk = join::<X25519Crypto>(&msk, &user_set)?;
        let usk_: PrivateKey<X25519Crypto> = PrivateKey::try_from_bytes(&usk.to_bytes())?;
        assert_eq!(usk, usk_);
        Ok(())
    }

    #[test]
    fn test_cover_crypt() -> Result<(), Error> {
        const SECRET_KEY_LENGTH: usize = 32;
        let admin_partition = Partition("admin".as_bytes().to_vec());
        let dev_partition = Partition("dev".as_bytes().to_vec());
        // partition list
        let partitions_set = HashSet::from([admin_partition.clone(), dev_partition.clone()]);
        // user list
        let users_set = vec![
            HashSet::from([dev_partition.clone()]),
            HashSet::from([admin_partition.clone(), dev_partition]),
        ];
        // target set
        let target_set = HashSet::from([admin_partition]);
        // secure random number generator
        let mut rng = CsRng::new();
        // setup scheme
        let (msk, mpk) = setup::<_, X25519Crypto>(&mut rng, &partitions_set);
        // generate user private keys
        let sk0 = join::<X25519Crypto>(&msk, &users_set[0])?;
        let sk1 = join::<X25519Crypto>(&msk, &users_set[1])?;
        // encapsulate for the target set
        let (secret_key, encapsulation) =
            encaps::<_, X25519Crypto>(&mut rng, &mpk, &target_set, SECRET_KEY_LENGTH)?;
        println!(
            "Secret Key size: {}, Encapsulation size: {}",
            secret_key.to_vec().len(),
            encapsulation.to_bytes().len()
        );
        // decapsulate for users 1 and 3
        let res0 = decaps::<X25519Crypto>(&sk0, &encapsulation, SECRET_KEY_LENGTH)?;
        let res1 = decaps::<X25519Crypto>(&sk1, &encapsulation, SECRET_KEY_LENGTH)?;
        assert!(res0.is_none(), "User 0 shouldn't be able to decapsulate!");
        assert!(Some(secret_key) == res1, "Wrong decapsulation for user 1!");
        Ok(())
    }
}
