use crate::{
    cover_crypt_core,
    error::Error,
    policies::{AccessPolicy, Attribute, Policy},
};
use cosmian_crypto_base::{entropy::CsRng, hybrid_crypto::Kem};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    fmt::Display,
    marker::PhantomData,
    ops::DerefMut,
    sync::Mutex,
};

const KDF_INFO: &[u8] = b"Need to extend generated secret key.";

/// Partition associated to a KEM keypair. It corresponds to a combination
/// of attributes across all axes.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Hash)]
#[serde(try_from = "String", into = "String")]
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
        // Partition(Sha3_256::digest(bytes).to_vec())
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

/// Ciphertext of the CoverCrypt algorithm. This is a `HashMap` of the KEM
/// encapsulations for some authorisations.
pub type CipherText = cover_crypt_core::Encapsulation<Partition>;

/// Private key of the CoverCrypt algorithm. This is a `HashMap` of the KEM
/// private keys for some authorisations.
pub type PrivateKey<KEM> = cover_crypt_core::PrivateKey<Partition, KEM>;

/// Public key of the CoverCrypt algorithm. This is a `HashMap` of the KEM
/// public keys for some authorisations.
pub type PublicKey<KEM> = cover_crypt_core::PublicKey<Partition, KEM>;

/// CoverCrypt public and private key pair.
#[derive(Clone, PartialEq)]
pub struct CCKeyPair<KEM: Kem> {
    pub(crate) pk: PublicKey<KEM>,
    pub(crate) sk: PrivateKey<KEM>,
}

impl<KEM: Kem> CCKeyPair<KEM> {
    pub fn public_key(&self) -> &PublicKey<KEM> {
        &self.pk
    }

    pub fn private_key(&self) -> &PrivateKey<KEM> {
        &self.sk
    }
}

/// The engine is the main entry point for the core functionalities.
///
/// It supplies a simple API that lets generate keys, encrypt and decrypt
/// messages.
///
/// In addition, two methods are supplied to generate random symmetric keys and
/// their corresponding cipher texts which are suitable for use in a hybrid
/// encryption scheme.
pub struct CoverCrypt<KEM> {
    pub(crate) rng: Mutex<CsRng>,
    phantom_kem: PhantomData<KEM>,
}

impl<KEM: Kem> CoverCrypt<KEM> {
    /// Instantiate a new CoverCrypt object.
    pub fn new() -> Self {
        Self {
            rng: Mutex::new(CsRng::new()),
            phantom_kem: PhantomData,
        }
    }

    /// Generate the master authority keys for supplied Policy
    ///
    ///  - `policy` : Policy to use to generate the keys
    pub fn generate_master_keys(
        &self,
        policy: &Policy,
    ) -> Result<(PrivateKey<KEM>, PublicKey<KEM>), Error> {
        Ok(cover_crypt_core::setup::<_, CsRng, KEM>(
            &mut self.rng.lock().expect("a mutex lock failed"),
            &all_partitions(policy)?,
        ))
    }

    /// Generate a user private key.
    ///
    /// - `msk`             : master secret key
    /// - `access_policy`   : user access policy
    /// - `policy`          : global policy
    pub fn generate_user_private_key(
        &self,
        msk: &PrivateKey<KEM>,
        access_policy: &AccessPolicy,
        policy: &Policy,
    ) -> Result<PrivateKey<KEM>, Error> {
        cover_crypt_core::join::<_, KEM>(msk, &ap_to_partitions(access_policy, policy)?)
    }

    /// Generate a user public key.
    ///
    /// - `mpk`             : master public key
    /// - `access_policy`   : user access policy
    /// - `policy`          : global policy
    pub fn generate_user_public_key(
        &self,
        mpk: &PublicKey<KEM>,
        access_policy: &AccessPolicy,
        policy: &Policy,
    ) -> Result<PublicKey<KEM>, Error> {
        ap_to_partitions(access_policy, policy)?
        .iter()
        .map(|partition| {
                // partition should be contained in the master key in
                // order to generate a valid user key
                let kem_public_key = mpk
                    .get(partition)
                    .ok_or_else(|| Error::UnknownPartition(format!("generate user public key: the master public key does not have partition {:?}", partition))) ?;
                Ok((partition.to_owned(), kem_public_key.to_owned()))
            })
            // `PublicKey` is an alias to a `HashMap` which is collected here
            .collect()
    }

    /// Generate a random symmetric key of `symmetric_key_len` to be used in an
    /// hybrid encryption scheme and generate its CoverCrypt encrypted version with the
    /// supplied policy `attributes`.
    ///
    /// - `policy`          : global policy
    /// - `pk`              : public key
    /// - `access_policy`   : access policy to use for key encryption
    /// - `sym_key_len`     : length of the symmetric key to generate
    pub fn generate_symmetric_key(
        &self,
        policy: &Policy,
        pk: &PublicKey<KEM>,
        attributes: &[Attribute],
        sym_key_len: usize,
    ) -> Result<(Vec<u8>, CipherText), Error> {
        // get the authorisations associated to the given access policy
        let partitions = to_partitions(attributes, policy)?;
        let (mut K, E) = cover_crypt_core::encaps::<_, _, KEM>(
            &mut self.rng.lock().expect("Mutex lock failed!").deref_mut(),
            pk,
            &partitions,
        )?;
        // expend keying data if needed
        if sym_key_len > K.len() {
            K = cosmian_crypto_base::kdf::hkdf_256(&K, sym_key_len, KDF_INFO)
                .map_err(Error::CryptoError)?;
        } else {
            K = K[..sym_key_len].to_owned();
        }
        Ok((K, E))
    }

    /// Decrypt a symmetric key generated with `generate_symmetric_key()`
    ///
    /// - `sk_u`        : user secret key
    /// - `c`           : encrypted symmetric key
    /// - `sym_key_len` : length of the symmetric key to generate
    pub fn decrypt_symmetric_key(
        &self,
        sk_u: &PrivateKey<KEM>,
        c: &CipherText,
        sym_key_len: usize,
    ) -> Result<Vec<u8>, Error> {
        let key =
            cover_crypt_core::decaps::<_, KEM>(sk_u, c)?.ok_or(Error::InsufficientAccessPolicy)?;
        if sym_key_len > key.len() {
            cosmian_crypto_base::kdf::hkdf_256(&key, sym_key_len, KDF_INFO)
                .map_err(Error::CryptoError)
        } else {
            Ok(key[..sym_key_len].to_owned())
        }
    }
}

impl<KEM: Kem> Default for CoverCrypt<KEM> {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn all_partitions(policy: &Policy) -> Result<HashSet<Partition>, Error> {
    // Build a map of all attribute value for all axis
    let mut map = HashMap::<String, Vec<u32>>::new();
    // We also a collect a Vec of axes which is used later
    let mut axes: Vec<String> = vec![];
    for (axis, (attribute_names, _hierarchical)) in policy.as_map() {
        axes.push(axis.to_owned());
        let mut values: Vec<u32> = vec![];
        for name in attribute_names {
            let attribute = Attribute::new(axis, name);
            let av = policy.attribute_values(&attribute)?;
            values.extend(av);
        }
        map.insert(axis.to_owned(), values);
    }

    // perform all the combinations to get all the partitions
    Ok(combine_attribute_values(0, axes.as_slice(), &map)?
        .into_iter()
        .map(Partition::new)
        .collect())
}

/// Convert a list of attributes used to encrypt ciphertexts into the corresponding
/// list of CoverCrypt partitions
fn to_partitions(attributes: &[Attribute], policy: &Policy) -> Result<HashSet<Partition>, Error> {
    // First split the attributes per axis using their latest value and check that they exist
    let mut map = HashMap::<String, Vec<u32>>::new();
    for attribute in attributes.iter() {
        let value = policy.attribute_current_value(attribute)?;
        let entry = map.entry(attribute.axis()).or_insert(Vec::new());
        entry.push(value);
    }

    // when an axis is not mentioned in the attributes list,
    // assume that the user wants to cover all the attribute names
    // in this axis
    // We also a collect a Vec of axes which is used later
    let mut axes: Vec<String> = vec![];
    for (axis, (attribute_names, _hierarchical)) in policy.as_map() {
        axes.push(axis.to_owned());
        if !map.contains_key(axis) {
            // gather all the latest value for that axis
            let mut values: Vec<u32> = Vec::with_capacity(attribute_names.len());
            for name in attribute_names {
                let attribute = Attribute::new(axis, name);
                let value = policy.attribute_current_value(&attribute)?;
                values.push(value);
            }
            map.insert(axis.to_owned(), values);
        }
    }

    // perform all the combinations to get all the partitions
    Ok(combine_attribute_values(0, axes.as_slice(), &map)?
        .into_iter()
        .map(Partition::new)
        .collect())
}

fn combine_attribute_values(
    current_axis: usize,
    axes: &[String],
    map: &HashMap<String, Vec<u32>>,
) -> Result<Vec<Vec<u32>>, Error> {
    // get the current axis or return if there is no more axis
    let axis = match axes.get(current_axis) {
        None => return Ok(vec![]),
        Some(axis) => axis,
    };
    // get the axes attribute value, wrapped into a vec
    let axis_values: &[u32] = map.get(axis).ok_or_else(|| {
        Error::AttributeNotFound(format!(
            "unexpected error: attribute values not found for axis: {}",
            &axis
        ))
    })?;

    // combine these values with all attribute values from the next axes
    let other_values = combine_attribute_values(current_axis + 1, axes, map)?;
    if other_values.is_empty() {
        // no combination: return the axis values wrapped in vec
        return Ok(axis_values.iter().map(|v| vec![*v]).collect());
    }

    let mut combinations = Vec::with_capacity(axis_values.len() * other_values.len());

    for av in axis_values {
        for ov in &other_values {
            let mut combined = Vec::with_capacity(1 + ov.len());
            combined.push(*av);
            combined.extend_from_slice(ov);
            combinations.push(combined);
        }
    }
    Ok(combinations)
}

/// Convert an access policy used to decrypt ciphertexts into the corresponding
/// list of CoverCrypt partitions that can be decrypted by that access policy
fn ap_to_partitions(
    access_policy: &AccessPolicy,
    policy: &Policy,
) -> Result<HashSet<Partition>, Error> {
    Ok(to_attribute_combinations(access_policy, policy)?
        .iter()
        .map(|comb| Partition::new(comb.to_owned()))
        .collect())
}

/// Returns the list of partitions that can be built using the values of
/// each attribute in the given access policy. This corresponds to an OR
/// expression of AND expressions.
///
/// - `policy`  : global policy
fn to_attribute_combinations(
    access_policy: &AccessPolicy,
    policy: &Policy,
) -> Result<Vec<Vec<u32>>, Error> {
    match access_policy {
        AccessPolicy::Attr(attr) => {
            let mut res = vec![];
            let (attribute_names, is_hierarchical) = policy
                .as_map()
                .get(&attr.axis())
                .ok_or_else(|| Error::UnknownPartition(attr.axis()))?;
            res.extend(
                policy
                    .attribute_values(attr)?
                    .iter()
                    .map(|&value| vec![value])
                    .collect::<Vec<Vec<u32>>>(),
            );
            if *is_hierarchical {
                // add attribute values for all attributes below the given one
                for name in attribute_names.iter() {
                    if *name == attr.name() {
                        break;
                    }
                    res.extend(
                        policy
                            .attribute_values(&Attribute::new(&attr.axis(), name))?
                            .iter()
                            .map(|&value| vec![value])
                            .collect::<Vec<Vec<u32>>>(),
                    );
                }
            }
            Ok(res)
        }
        AccessPolicy::And(ap_left, ap_right) => {
            let mut res = vec![];
            // avoid computing this many times
            let combinations_right = to_attribute_combinations(ap_right, policy)?;
            for value_left in to_attribute_combinations(ap_left, policy)? {
                for value_right in combinations_right.iter() {
                    let mut combined = Vec::with_capacity(value_left.len() + value_right.len());
                    combined.extend_from_slice(&value_left);
                    combined.extend_from_slice(value_right);
                    res.push(combined)
                }
            }
            Ok(res)
        }
        AccessPolicy::Or(ap_left, ap_right) => {
            let mut res = to_attribute_combinations(ap_left, policy)?;
            res.extend(to_attribute_combinations(ap_right, policy)?);
            Ok(res)
        }
        // TODO: check if this is correct
        AccessPolicy::All => Ok(vec![vec![]]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policies::{Attribute, PolicyAxis};
    use cosmian_crypto_base::asymmetric::ristretto::X25519Crypto;

    fn policy() -> Result<Policy, Error> {
        let sec_level = PolicyAxis::new(
            "Security Level",
            &["Protected", "Confidential", "Top Secret"],
            true,
        );
        let department = PolicyAxis::new("Department", &["R&D", "HR", "MKG", "FIN"], false);
        let mut policy = Policy::new(100);
        policy.add_axis(&sec_level)?;
        policy.add_axis(&department)?;
        Ok(policy)
    }

    fn axes_attributes_from_policy(
        axes: &[String],
        policy: &Policy,
    ) -> Result<Vec<Vec<(Attribute, u32)>>, Error> {
        let mut axes_attributes: Vec<Vec<(Attribute, u32)>> = vec![];
        for axis in axes {
            let mut axis_attributes: Vec<(Attribute, u32)> = vec![];
            let attribute_names = &policy.as_map()[axis].0;
            for name in attribute_names {
                let attribute = Attribute::new(axis, name);
                let value = policy.attribute_current_value(&attribute)?;
                axis_attributes.push((attribute, value));
            }
            axes_attributes.push(axis_attributes);
        }
        Ok(axes_attributes)
    }

    #[test]
    fn test_combine_attribute_values() -> Result<(), Error> {
        let mut policy = policy()?;
        let axes: Vec<String> = policy.as_map().keys().into_iter().cloned().collect();

        let axes_attributes = axes_attributes_from_policy(&axes, &policy)?;

        // this should create the combination of the first attribute
        // with all those of the second axis
        let partitions_0 = super::to_partitions(&[axes_attributes[0][0].0.clone()], &policy)?;
        assert_eq!(axes_attributes[1].len(), partitions_0.len());
        let att_0_0 = axes_attributes[0][0].1;
        for (_attribute, value) in &axes_attributes[1] {
            let partition = Partition::new(vec![att_0_0, *value]);
            assert!(partitions_0.contains(&partition));
        }

        // this should create the single combination of the first attribute
        // of the first axis with that of the second axis
        let partitions_1 = super::to_partitions(
            &[
                axes_attributes[0][0].0.clone(),
                axes_attributes[1][0].0.clone(),
            ],
            &policy,
        )?;
        assert_eq!(partitions_1.len(), 1);
        let att_1_0 = axes_attributes[1][0].1;
        assert!(partitions_1.contains(&Partition::new(vec![att_0_0, att_1_0])));

        // this should create the 2combination of the first attribute
        // of the first axis with that the wo of the second axis
        let partitions_2 = super::to_partitions(
            &[
                axes_attributes[0][0].0.clone(),
                axes_attributes[1][0].0.clone(),
                axes_attributes[1][1].0.clone(),
            ],
            &policy,
        )?;
        assert_eq!(partitions_2.len(), 2);
        let att_1_0 = axes_attributes[1][0].1;
        let att_1_1 = axes_attributes[1][1].1;
        assert!(partitions_2.contains(&Partition::new(vec![att_0_0, att_1_0]),));
        assert!(partitions_2.contains(&Partition::new(vec![att_0_0, att_1_1]),));

        // rotation
        policy.rotate(&axes_attributes[0][0].0)?;
        let axes_attributes = axes_attributes_from_policy(&axes, &policy)?;

        // this should create the single combination of the first attribute
        // of the first axis with that of the second axis
        let partitions_3 = super::to_partitions(
            &[
                axes_attributes[0][0].0.clone(),
                axes_attributes[1][0].0.clone(),
            ],
            &policy,
        )?;
        assert_eq!(partitions_3.len(), 1);
        let att_1_0 = axes_attributes[1][0].1;
        let att_0_0_new = axes_attributes[0][0].1;
        assert!(partitions_3.contains(&Partition::new(vec![att_0_0_new, att_1_0])));
        assert!(!partitions_3.contains(&Partition::new(vec![att_0_0, att_1_0])));

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_sym_key() -> Result<(), Error> {
        const KEY_LENGTH: usize = 256;
        let mut policy = policy()?;
        policy.rotate(&Attribute::new("Department", "FIN"))?;
        println!("{:?}", &policy);
        let access_policy = (AccessPolicy::new("Department", "R&D")
            | AccessPolicy::new("Department", "FIN"))
            & AccessPolicy::new("Security Level", "Top Secret");
        let cc = CoverCrypt::<X25519Crypto>::default();
        let (msk, mpk) = cc.generate_master_keys(&policy)?;
        let (key, encrypted_key) = cc.generate_symmetric_key(
            &policy,
            &mpk,
            &[
                Attribute::new("Department", "R&D"),
                Attribute::new("Security Level", "Top Secret"),
            ],
            KEY_LENGTH,
        )?;
        let sk_u = cc.generate_user_private_key(&msk, &access_policy, &policy)?;
        let recovered_key = cc.decrypt_symmetric_key(&sk_u, &encrypted_key, KEY_LENGTH)?;
        assert!(key == recovered_key, "Wrong decryption of the key!");
        Ok(())
    }

    #[test]
    fn test_to_attribute_combinations() -> Result<(), Error> {
        let mut policy = policy()?;

        policy.rotate(&Attribute::new("Department", "FIN"))?;
        let access_policy = (AccessPolicy::new("Department", "HR")
            | AccessPolicy::new("Department", "FIN"))
            & AccessPolicy::new("Security Level", "Confidential");
        let combinations = to_attribute_combinations(&access_policy, &policy)?;
        let partitions_: HashSet<Partition> =
            combinations.into_iter().map(Partition::new).collect();

        // combine attribute values to verify
        let mut map: HashMap<String, Vec<u32>> = HashMap::new();
        let mut dpt_axis_attributes =
            policy.attribute_values(&Attribute::new("Department", "FIN"))?;
        dpt_axis_attributes.extend(policy.attribute_values(&Attribute::new("Department", "HR"))?);
        map.insert("Department".to_owned(), dpt_axis_attributes);
        let mut lvl_axis_attributes =
            policy.attribute_values(&Attribute::new("Security Level", "Confidential"))?;
        lvl_axis_attributes
            .extend(policy.attribute_values(&Attribute::new("Security Level", "Protected"))?);
        map.insert("Security Level".to_owned(), lvl_axis_attributes);

        let axes: Vec<String> = policy.as_map().keys().cloned().collect();
        let partitions: HashSet<Partition> = combine_attribute_values(0, axes.as_slice(), &map)?
            .into_iter()
            .map(Partition::new)
            .collect();

        assert_eq!(partitions, partitions_);
        Ok(())
    }
}
