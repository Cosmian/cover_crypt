use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
};

use cosmian_crypto_base::{asymmetric::KeyPair, hybrid_crypto::Kem, KeyTrait};
use rand_core::{CryptoRng, RngCore};

use crate::{
    bytes_ser_de::{Deserializer, Serializer},
    error::Error,
    utils,
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
    pub fn from_attributes(mut attribute_values: Vec<u32>) -> Result<Partition, Error> {
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
        Ok(Partition(buf[0..len].to_vec()))
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
        f.write_fmt(format_args!("Private Key: {:#?}", self.keys()))
    }
}

impl<KEM> PrivateKey<KEM>
where
    KEM: Kem,
{
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut serializer = Serializer::new();
        for (partition, key) in self.iter() {
            serializer.write_array(partition.into())?;
            serializer.write_array(key.to_bytes())?;
        }
        // write an empty array to mak the end (wastes one byte)
        serializer.write_array(vec![])?;
        Ok(serializer.value().to_vec())
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyPrivateKey);
        }
        let mut map: HashMap<Partition, <<KEM as Kem>::KeyPair as KeyPair>::PrivateKey> =
            HashMap::new();
        let mut de = Deserializer::new(bytes);
        loop {
            let partition_bytes = de.read_array()?;
            if partition_bytes.is_empty() {
                //empty array marks the end
                break;
            }
            let partition = Partition::from(partition_bytes);
            let key_bytes = de.read_array()?;
            let key = <<KEM as Kem>::KeyPair as KeyPair>::PrivateKey::try_from_bytes(&key_bytes)?;
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
        for (k, v) in self.iter() {
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
        f.write_fmt(format_args!("Public Key: {:#?}", self.keys()))
    }
}

impl<KEM> PublicKey<KEM>
where
    KEM: Kem,
{
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut serializer = Serializer::new();
        for (partition, key) in self.iter() {
            serializer.write_array(partition.into())?;
            serializer.write_array(key.to_bytes())?;
        }
        // write an empty array to mark the end (wastes one byte)
        serializer.write_array(vec![])?;
        Ok(serializer.value().to_vec())
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut map: HashMap<Partition, <<KEM as Kem>::KeyPair as KeyPair>::PublicKey> =
            HashMap::new();
        let mut de = Deserializer::new(bytes);
        loop {
            let partition_bytes = de.read_array()?;
            if partition_bytes.is_empty() {
                //empty array marks the end
                break;
            }
            let partition = Partition::from(partition_bytes);
            let key_bytes = de.read_array()?;
            let key = <<KEM as Kem>::KeyPair as KeyPair>::PublicKey::try_from_bytes(&key_bytes)?;
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
        for (k, v) in self.iter() {
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
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut serializer = Serializer::new();
        for (partition, (key, ciphertext)) in &self.0 {
            serializer.write_array(partition.into())?;
            serializer.write_array(key.to_owned())?;
            serializer.write_array(ciphertext.to_owned())?;
        }
        // write an empty array to mark the end (wastes one byte)
        serializer.write_array(vec![])?;
        Ok(serializer.value().to_vec())
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut map = HashMap::new();
        let mut de = Deserializer::new(bytes);
        loop {
            let partition_bytes = de.read_array()?;
            if partition_bytes.is_empty() {
                //empty array marks the end
                break;
            }
            let partition = Partition::from(partition_bytes);
            let key = de.read_array()?;
            let ciphertext = de.read_array()?;
            map.insert(partition, (key, ciphertext));
        }
        Ok(Self(map))
    }
}

/// CovCrypt secret key is a vector of bytes of the same length as secret key
/// of the underlying KEM.
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
        SecretKey(v)
    }
}

impl From<SecretKey> for Vec<u8> {
    fn from(sk: SecretKey) -> Self {
        sk.to_vec()
    }
}

/// Generate the master private key and master public key of the CoverCrypt
/// scheme.
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
            let kem_private_key = msk
                .get(partition)
                .ok_or_else(|| Error::UnknownPartition(format!("{partition:?}")))?;
            Ok((partition.to_owned(), kem_private_key.to_owned()))
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

/// Update the master private key and master public key of the CoverCrypt
/// scheme with the given list of partitions.
///
/// If a partition exists in the keys but not in the list, it will be removed from the keys.
///
/// If a partition exists in the list, but not in the keys, it will be "added" to the keys,
/// by adding a new partition key pair as performed in the setup procedure above
pub fn update<R, KEM>(
    rng: &mut R,
    msk: &mut PrivateKey<KEM>,
    mpk: &mut PublicKey<KEM>,
    partitions_set: &HashSet<Partition>,
) -> Result<(), Error>
where
    R: CryptoRng + RngCore,
    KEM: Kem,
{
    // add keys for partitions that do not exist
    for partition in partitions_set.iter() {
        if !msk.contains_key(partition) || !mpk.contains_key(partition) {
            // add a new Keypair
            let keypair = KEM::key_gen(rng);
            msk.insert(partition.to_owned(), keypair.private_key().to_owned());
            mpk.insert(partition.to_owned(), keypair.public_key().to_owned());
        }
    }
    // remove keys for partitions not in the list
    let partitions_in_private_key: Vec<Partition> = msk.clone().into_keys().collect();
    for partition in partitions_in_private_key {
        if !partitions_set.contains(&partition) {
            msk.remove_entry(&partition);
        }
    }
    let partitions_in_public_key: Vec<Partition> = mpk.clone().into_keys().collect();
    for partition in partitions_in_public_key {
        if !partitions_set.contains(&partition) {
            mpk.remove_entry(&partition);
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
pub fn refresh<KEM>(
    msk: &PrivateKey<KEM>,
    usk: &mut PrivateKey<KEM>,
    user_set: &HashSet<Partition>,
) -> Result<(), Error>
where
    KEM: Kem,
{
    // add keys for partitions that do not exist
    for partition in user_set.iter() {
        if !usk.contains_key(partition) {
            // extract key from master private key (see join)
            let kem_private_key = msk
                .get(partition)
                .ok_or_else(|| Error::UnknownPartition(format!("{partition:?}")))?;
            usk.insert(partition.to_owned(), kem_private_key.to_owned());
        }
    }
    // remove keys for partitions not in the list
    let partitions_in_user_key: Vec<Partition> = usk.clone().into_keys().collect();
    for partition in partitions_in_user_key {
        if !user_set.contains(&partition) {
            usk.remove_entry(&partition);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_base::{asymmetric::ristretto::X25519Crypto, entropy::CsRng};

    use super::*;

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
        let msk_: PrivateKey<X25519Crypto> = PrivateKey::try_from_bytes(&msk.try_to_bytes()?)?;
        assert_eq!(msk, msk_, "master key comparisons failed");
        let mpk_: PublicKey<X25519Crypto> = PublicKey::try_from_bytes(&mpk.try_to_bytes()?)?;
        assert_eq!(mpk, mpk_);
        let usk = join::<X25519Crypto>(&msk, &user_set)?;
        let usk_: PrivateKey<X25519Crypto> = PrivateKey::try_from_bytes(&usk.try_to_bytes()?)?;
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
            encapsulation.try_to_bytes()?.len()
        );
        // decapsulate for users 1 and 3
        let res0 = decaps::<X25519Crypto>(&sk0, &encapsulation, SECRET_KEY_LENGTH)?;
        let res1 = decaps::<X25519Crypto>(&sk1, &encapsulation, SECRET_KEY_LENGTH)?;
        assert!(res0.is_none(), "User 0 shouldn't be able to decapsulate!");
        assert!(Some(secret_key) == res1, "Wrong decapsulation for user 1!");
        Ok(())
    }

    #[test]
    fn test_master_keys_update() -> Result<(), Error> {
        let partition_1 = Partition("1".as_bytes().to_vec());
        let partition_2 = Partition("2".as_bytes().to_vec());
        // partition list
        let partitions_set = HashSet::from([partition_1.clone(), partition_2.clone()]);
        // secure random number generator
        let mut rng = CsRng::new();
        // setup scheme
        let (mut msk, mut mpk) = setup::<_, X25519Crypto>(&mut rng, &partitions_set);

        // now remove partition 1 and add partition 3
        let partition_3 = Partition("3".as_bytes().to_vec());
        let new_partitions_set = HashSet::from([partition_2.clone(), partition_3.clone()]);
        update(&mut rng, &mut msk, &mut mpk, &new_partitions_set)?;
        assert!(!msk.contains_key(&partition_1));
        assert!(msk.contains_key(&partition_2));
        assert!(msk.contains_key(&partition_3));
        assert!(!mpk.contains_key(&partition_1));
        assert!(mpk.contains_key(&partition_2));
        assert!(mpk.contains_key(&partition_3));
        Ok(())
    }

    #[test]
    fn test_user_key_refresh() -> Result<(), Error> {
        let partition_1 = Partition("1".as_bytes().to_vec());
        let partition_2 = Partition("2".as_bytes().to_vec());
        let partition_3 = Partition("3".as_bytes().to_vec());
        // partition list
        let partitions_set = HashSet::from([
            partition_1.clone(),
            partition_2.clone(),
            partition_3.clone(),
        ]);
        // secure random number generator
        let mut rng = CsRng::new();
        // setup scheme
        let (mut msk, mut mpk) = setup::<_, X25519Crypto>(&mut rng, &partitions_set);
        // create a user key with access to partition 1 and 2
        let mut usk = join(
            &msk,
            &HashSet::from([partition_1.clone(), partition_2.clone()]),
        )?;

        // now remove partition 1 and add partition 4
        let partition_4 = Partition("4".as_bytes().to_vec());
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
        assert!(!usk.contains_key(&partition_1));
        assert!(usk.contains_key(&partition_2));
        assert!(!usk.contains_key(&partition_3));
        assert!(usk.contains_key(&partition_4));
        Ok(())
    }
}
