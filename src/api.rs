use crate::{
    cover_crypt_core::{self, Partition},
    error::Error,
    policies::{AccessPolicy, Attribute, Policy},
};
use cosmian_crypto_base::{asymmetric::KeyPair, entropy::CsRng, hybrid_crypto::Kem};
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    ops::DerefMut,
    sync::Mutex,
};

const KDF_INFO: &[u8] = b"Need to extend generated secret key.";

/// Private key of the CoverCrypt algorithm. This is a `HashMap` of the KEM
/// private keys for some authorisations.
pub type PrivateKey<KEM> = cover_crypt_core::PrivateKey<KEM>;

/// Public key of the CoverCrypt algorithm. This is a `HashMap` of the KEM
/// public keys for some authorisations.
pub type PublicKey<KEM> = cover_crypt_core::PublicKey<KEM>;

pub type Encapsulation = cover_crypt_core::Encapsulation;

pub type SecretKey = cover_crypt_core::SecretKey;
/// CoverCrypt public and private key pair.
#[derive(Clone)]
pub struct CCKeyPair<KEM: Kem> {
    pub(crate) pk: PublicKey<KEM>,
    pub(crate) sk: PrivateKey<KEM>,
}

impl<KEM: Kem> CCKeyPair<KEM> {
    /// Return the public key.
    pub fn public_key(&self) -> &PublicKey<KEM> {
        &self.pk
    }

    /// Return the private key.
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
        Ok(cover_crypt_core::setup::<CsRng, KEM>(
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
        cover_crypt_core::join::<KEM>(msk, &access_policy_to_partitions(access_policy, policy)?)
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
        access_policy_to_partitions(access_policy, policy)?
            .iter()
            .map(|partition| {
                // partition should be contained in the master key in
                // order to generate a valid user key
                let kem_public_key = mpk.get(partition).ok_or_else(|| {
                    Error::UnknownPartition(format!(
                        "generate user public key: the master public key does not have partition \
                         {:?}",
                        partition
                    ))
                })?;
                Ok((partition.to_owned(), kem_public_key.to_owned()))
            })
            // `PublicKey` is an alias to a `HashMap` which is collected here
            .collect::<Result<HashMap<Partition, <<KEM as Kem>::KeyPair as KeyPair>::PublicKey>, Error>>()
            .map(|m| cover_crypt_core::PublicKey(m))
    }

    /// Generate a random symmetric key of `symmetric_key_len` to be used in an
    /// hybrid encryption scheme and generate its CoverCrypt encrypted version
    /// with the supplied policy `attributes`.
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
    ) -> Result<(SecretKey, Encapsulation), Error> {
        // get the authorisations associated to the given access policy
        let partitions = to_partitions(attributes, policy)?;
        let (mut secret_key, encapsulation) = cover_crypt_core::encaps::<_, KEM>(
            &mut self.rng.lock().expect("Mutex lock failed!").deref_mut(),
            pk,
            &partitions,
            sym_key_len,
        )?;
        // expend keying data if needed
        if sym_key_len > secret_key.len() {
            secret_key = SecretKey::from(
                cosmian_crypto_base::kdf::hkdf_256(&secret_key, sym_key_len, KDF_INFO)
                    .map_err(Error::CryptoError)?,
            );
        } else {
            secret_key = SecretKey::from(secret_key[..sym_key_len].to_owned());
        }
        Ok((secret_key, encapsulation))
    }

    /// Decrypt a symmetric key generated with `generate_symmetric_key()`
    ///
    /// - `sk_u`        : user secret key
    /// - `c`           : encrypted symmetric key
    /// - `sym_key_len` : length of the symmetric key to generate
    pub fn decrypt_symmetric_key(
        &self,
        sk_u: &PrivateKey<KEM>,
        ciphertext: &Encapsulation,
        sym_key_len: usize,
    ) -> Result<SecretKey, Error> {
        let key = cover_crypt_core::decaps::<KEM>(sk_u, ciphertext, sym_key_len)?
            .ok_or(Error::InsufficientAccessPolicy)?;
        Ok(SecretKey::from(if sym_key_len > key.len() {
            cosmian_crypto_base::kdf::hkdf_256(&key, sym_key_len, KDF_INFO)
                .map_err(Error::CryptoError)?
        } else {
            key[..sym_key_len].to_owned()
        }))
    }
}

impl<KEM: Kem> Default for CoverCrypt<KEM> {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn all_partitions(policy: &Policy) -> Result<HashSet<Partition>, Error> {
    // Build a map of all attribute value for all axis
    let mut map = HashMap::with_capacity(policy.as_map().len());
    // We also a collect a Vec of axes which is used later
    let mut axes = Vec::with_capacity(policy.as_map().len());
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
    let combinations = combine_attribute_values(0, axes.as_slice(), &map)?;
    let mut set: HashSet<Partition> = HashSet::new();
    for combination in combinations {
        set.insert(Partition::from_attributes(combination)?);
    }
    Ok(set)
}

/// Convert a list of attributes used to encrypt ciphertexts into the
/// corresponding list of CoverCrypt partitions
fn to_partitions(attributes: &[Attribute], policy: &Policy) -> Result<HashSet<Partition>, Error> {
    // First split the attributes per axis using their latest value and check that
    // they exist
    let mut map = HashMap::new();
    for attribute in attributes.iter() {
        let value = policy.attribute_current_value(attribute)?;
        let entry = map.entry(attribute.axis()).or_insert(Vec::new());
        entry.push(value);
    }

    // when an axis is not mentioned in the attributes list,
    // assume that the user wants to cover all the attribute names
    // in this axis
    // We also a collect a Vec of axes which is used later
    let mut axes = Vec::with_capacity(policy.as_map().len());
    for (axis, (attribute_names, _hierarchical)) in policy.as_map() {
        axes.push(axis.to_owned());
        if !map.contains_key(axis) {
            // gather all the latest value for that axis
            let values = attribute_names
                .iter()
                .map(|name| policy.attribute_current_value(&Attribute::new(axis, name)))
                .collect::<Result<Vec<u32>, Error>>()?;
            map.insert(axis.to_owned(), values);
        }
    }

    let combinations = combine_attribute_values(0, axes.as_slice(), &map)?;
    let mut set: HashSet<Partition> = HashSet::with_capacity(combinations.len());
    for combination in combinations {
        set.insert(Partition::from_attributes(combination)?);
    }
    Ok(set)
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
        Ok(axis_values.iter().map(|v| vec![*v]).collect())
    } else {
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
}

/// Convert an access policy used to decrypt ciphertexts into the corresponding
/// list of CoverCrypt partitions that can be decrypted by that access policy
fn access_policy_to_partitions(
    access_policy: &AccessPolicy,
    policy: &Policy,
) -> Result<HashSet<Partition>, Error> {
    let combinations = to_attribute_combinations(access_policy, policy)?;
    let mut set: HashSet<Partition> = HashSet::with_capacity(combinations.len());
    for combination in combinations {
        set.insert(Partition::from_attributes(combination)?);
    }
    Ok(set)
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
            let (attribute_names, is_hierarchical) = policy
                .as_map()
                .get(&attr.axis())
                .ok_or_else(|| Error::UnknownPartition(attr.axis()))?;
            let mut res = policy
                .attribute_values(attr)?
                .iter()
                .map(|&value| vec![value])
                .collect::<Vec<Vec<u32>>>();
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
            let combinations_left = to_attribute_combinations(ap_left, policy)?;
            let combinations_right = to_attribute_combinations(ap_right, policy)?;
            let mut res = Vec::with_capacity(combinations_left.len() * combinations_right.len());
            for value_left in combinations_left {
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
            let combinations_left = to_attribute_combinations(ap_left, policy)?;
            let combinations_right = to_attribute_combinations(ap_right, policy)?;
            let mut res = Vec::with_capacity(combinations_left.len() + combinations_right.len());
            res.extend(combinations_left);
            res.extend(combinations_right);
            Ok(res)
        }
        // TODO: check if this is correct
        AccessPolicy::All => Ok(vec![vec![]]),
    }
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_base::asymmetric::ristretto::X25519Crypto;

    use super::*;
    use crate::policies::{Attribute, PolicyAxis};

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
            let partition = Partition::from_attributes(vec![att_0_0, *value])?;
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
        assert!(partitions_1.contains(&Partition::from_attributes(vec![att_0_0, att_1_0])?));

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
        assert!(partitions_2.contains(&Partition::from_attributes(vec![att_0_0, att_1_0])?,));
        assert!(partitions_2.contains(&Partition::from_attributes(vec![att_0_0, att_1_1])?,));

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
        assert!(partitions_3.contains(&Partition::from_attributes(vec![att_0_0_new, att_1_0])?));
        assert!(!partitions_3.contains(&Partition::from_attributes(vec![att_0_0, att_1_0])?));

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
        let mut partitions_: HashSet<Partition> = HashSet::with_capacity(combinations.len());
        for combination in combinations {
            partitions_.insert(Partition::from_attributes(combination)?);
        }

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

        let combinations = combine_attribute_values(0, axes.as_slice(), &map)?;
        let mut partitions: HashSet<Partition> = HashSet::with_capacity(combinations.len());
        for combination in combinations {
            partitions.insert(Partition::from_attributes(combination)?);
        }

        assert_eq!(partitions, partitions_);
        Ok(())
    }
}
