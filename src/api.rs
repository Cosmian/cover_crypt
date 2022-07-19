use crate::{
    cover_crypt_core::{
        self, Encapsulation, MasterPrivateKey, Partition, PublicKey, SecretKey, UserPrivateKey,
    },
    error::Error,
};
use abe_policy::{AccessPolicy, Attribute, Policy};
use cosmian_crypto_base::entropy::CsRng;
use std::{
    collections::{HashMap, HashSet},
    ops::DerefMut,
    sync::Mutex,
};

/// The engine is the main entry point for the core functionalities.
///
/// It supplies a simple API that lets generate keys, encrypt and decrypt
/// messages.
///
/// In addition, two methods are supplied to generate random symmetric keys and
/// their corresponding cipher texts which are suitable for use in a hybrid
/// encryption scheme.
pub struct CoverCrypt {
    pub(crate) rng: Mutex<CsRng>,
}

impl CoverCrypt {
    /// Instantiate a new CoverCrypt object.
    pub fn new() -> Self {
        Self {
            rng: Mutex::new(CsRng::new()),
        }
    }

    /// Generate the master authority keys for supplied Policy
    ///
    ///  - `policy` : Policy to use to generate the keys
    pub fn generate_master_keys(
        &self,
        policy: &Policy,
    ) -> Result<(MasterPrivateKey, PublicKey), Error> {
        Ok(cover_crypt_core::setup::<CsRng>(
            &mut self.rng.lock().expect("a mutex lock failed"),
            &all_partitions(policy)?,
        ))
    }

    /// Update the master keys according to this new policy.
    /// When a partition exists in the new policy but not in the master keys,
    /// a new keypair is added to the master keys for that partition.
    /// When a partition exists on the master keys, but not in the new policy,
    /// it is removed from the master keys.
    ///
    ///  - `policy` : Policy to use to generate the keys
    pub fn update_master_keys(
        &self,
        policy: &Policy,
        msk: &mut MasterPrivateKey,
        mpk: &mut PublicKey,
    ) -> Result<(), Error> {
        cover_crypt_core::update(
            &mut self.rng.lock().expect("a mutex lock failed").deref_mut(),
            msk,
            mpk,
            &all_partitions(policy)?,
        )
    }

    /// Generate a user private key.
    /// A new user private key does NOT include to old (i.e. rotated) partitions
    ///
    /// - `msk`             : master secret key
    /// - `access_policy`   : user access policy
    /// - `policy`          : global policy
    pub fn generate_user_private_key(
        &self,
        msk: &MasterPrivateKey,
        access_policy: &AccessPolicy,
        policy: &Policy,
    ) -> Result<UserPrivateKey, Error> {
        cover_crypt_core::join(
            self.rng.lock().expect("a mutex lock failed").deref_mut(),
            msk,
            &access_policy_to_current_partitions(access_policy, policy)?,
        )
    }

    /// Refresh the user key according to the given master key and access policy.
    ///
    /// The user key will be granted access to the current partitions, as determined by its access policy.
    /// If preserve_old_partitions_access is set, the user access to rotated partitions will be preserved
    ///
    /// - `usk`                  : the user key to refresh
    /// - `access_policy`        : the access policy of the user key
    /// - `msk`                  : master secret key
    /// - `policy`               : global policy of the master secret key
    /// - preserve_old_partitions_access:  whether access to old partitions (i.e. before rotation) should be kept
    pub fn refresh_user_private_key(
        &self,
        usk: &mut UserPrivateKey,
        access_policy: &AccessPolicy,
        msk: &MasterPrivateKey,
        policy: &Policy,
        preserve_old_partitions_access: bool,
    ) -> Result<(), Error> {
        let mut current_partitions = access_policy_to_current_partitions(access_policy, policy)?;
        if preserve_old_partitions_access {
            for key_partition in usk.map().keys() {
                current_partitions.insert(key_partition.to_owned());
            }
        }
        cover_crypt_core::refresh(msk, usk, &current_partitions)
    }

    /// Generate a random symmetric key of `symmetric_key_len` to be used in an
    /// hybrid encryption scheme and generate its CoverCrypt encrypted version
    /// with the supplied policy `attributes`.
    ///
    /// - `policy`          : global policy
    /// - `pk`              : public key
    /// - `attributes`      : the list of attributes to compose to generate the symmetric key
    /// - `sym_key_len`     : length of the symmetric key to generate
    pub fn generate_symmetric_key(
        &self,
        policy: &Policy,
        pk: &PublicKey,
        attributes: &[Attribute],
        sym_key_len: usize,
    ) -> Result<(SecretKey, Encapsulation), Error> {
        let bytes = self
            .rng
            .lock()
            .expect("Mutex lock failed!")
            .generate_random_bytes(sym_key_len);
        let sym_key = SecretKey::from(bytes);
        let encapsulation = cover_crypt_core::encrypt(
            &mut self.rng.lock().expect("Mutex lock failed!").deref_mut(),
            pk,
            &to_partitions(attributes, policy)?,
            &sym_key,
        )?;
        Ok((sym_key, encapsulation))
    }

    /// Decapsulate a symmetric key generated with `generate_symmetric_key()`.
    ///
    /// - `sk_u`            : user secret key
    /// - `encapsulation`   : encrypted symmetric key
    /// - `sym_key_len`     : length of the symmetric key to generate
    pub fn decaps_symmetric_key(
        &self,
        sk_u: &UserPrivateKey,
        encapsulation: &Encapsulation,
        sym_key_len: usize,
    ) -> Result<SecretKey, Error> {
        cover_crypt_core::decaps(sk_u, encapsulation, sym_key_len)?
            .ok_or(Error::InsufficientAccessPolicy)
    }
}

impl Default for CoverCrypt {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate all possible partitions from the given policy.
///
/// - `policy`  : policy from which to generate partitions
fn all_partitions(policy: &Policy) -> Result<HashSet<Partition>, Error> {
    // Build a map of all attribute values for all axes
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
    let mut set: HashSet<Partition> = HashSet::with_capacity(combinations.len());
    for combination in combinations {
        set.insert(Partition::from_attributes(combination)?);
    }
    Ok(set)
}

/// Convert a list of attributes used to encrypt ciphertexts into the
/// corresponding list of CoverCrypt partitions; this only gets the current
/// partitions, not the old ones
///
/// - `attributes`  : liste of attributes
/// - `policy`      : security policy
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
                .collect::<Result<Vec<u32>, abe_policy::Error>>()?;
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

/// Generate all attribute values combinations from the given axes.
///
/// - `current_axis`    : axis from which to start to combine values with other axes
/// - `axes`            : list of axes
/// - `map`             : map axes with their associated attribute values
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
/// list of CoverCrypt current partitions that can be decrypted by that access policy
fn access_policy_to_current_partitions(
    access_policy: &AccessPolicy,
    policy: &Policy,
) -> Result<HashSet<Partition>, Error> {
    let attr_combinations = to_attribute_combinations(access_policy, policy)?;
    let mut set = HashSet::with_capacity(attr_combinations.len());
    for attr_combination in &attr_combinations {
        for partition in to_partitions(attr_combination, policy)? {
            let is_unique = set.insert(partition);
            if !is_unique {
                return Err(Error::ExistingCombination(format!("{attr_combination:?}")));
            }
        }
    }
    Ok(set)
}

/// Returns the list of attribute combinations that can be built using the
/// values of each attribute in the given access policy. This corresponds to
/// an OR expression of AND expressions.
///
/// - `policy`  : global policy
fn to_attribute_combinations(
    access_policy: &AccessPolicy,
    policy: &Policy,
) -> Result<Vec<Vec<Attribute>>, Error> {
    match access_policy {
        AccessPolicy::Attr(attr) => {
            let (attribute_names, is_hierarchical) = policy
                .as_map()
                .get(&attr.axis())
                .ok_or_else(|| Error::UnknownPartition(attr.axis()))?;
            let mut res = vec![vec![attr.clone()]];
            if *is_hierarchical {
                // add attribute values for all attributes below the given one
                for name in attribute_names.iter() {
                    if *name == attr.name() {
                        break;
                    }
                    res.push(vec![Attribute::new(&attr.axis(), name)]);
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
    use super::*;
    use abe_policy::{Attribute, PolicyAxis};

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
    fn test_update_master_keys() -> Result<(), Error> {
        let mut policy = policy()?;
        let cc = CoverCrypt::default();
        let (mut msk, mut mpk) = cc.generate_master_keys(&policy)?;
        let partitions_msk: Vec<Partition> = msk.map().clone().into_keys().collect();
        let partitions_mpk: Vec<Partition> = mpk.map().clone().into_keys().collect();
        assert_eq!(partitions_msk.len(), partitions_mpk.len());
        for p in &partitions_msk {
            assert!(partitions_mpk.contains(p));
        }
        // rotate he FIN department
        policy.rotate(&Attribute::new("Department", "FIN"))?;
        // update the master keys
        cc.update_master_keys(&policy, &mut msk, &mut mpk)?;
        let new_partitions_msk: Vec<Partition> = msk.map().clone().into_keys().collect();
        let new_partitions_mpk: Vec<Partition> = mpk.map().clone().into_keys().collect();
        assert_eq!(new_partitions_msk.len(), new_partitions_mpk.len());
        for p in &new_partitions_msk {
            assert!(new_partitions_mpk.contains(p));
        }
        // 3 is the size of the security level axis
        assert_eq!(new_partitions_msk.len(), partitions_msk.len() + 3);
        Ok(())
    }

    #[test]
    fn test_refresh_user_key() -> Result<(), Error> {
        let mut policy = policy()?;
        let cc = CoverCrypt::default();
        let (mut msk, mut mpk) = cc.generate_master_keys(&policy)?;
        let access_policy = AccessPolicy::from_boolean_expression(
            "Department::MKG && Security Level::Confidential",
        )?;
        let mut usk = cc.generate_user_private_key(&msk, &access_policy, &policy)?;
        let original_user_partitions: Vec<Partition> = usk.map().clone().into_keys().collect();
        // rotate he FIN department
        policy.rotate(&Attribute::new("Department", "MKG"))?;
        // update the master keys
        cc.update_master_keys(&policy, &mut msk, &mut mpk)?;
        // refresh the user key and preserve access to old partitions
        cc.refresh_user_private_key(&mut usk, &access_policy, &msk, &policy, true)?;
        let new_user_partitions: Vec<Partition> = usk.map().clone().into_keys().collect();
        // 2 partitions accessed by the user were rotated (MKG Confidential and MKG Protected)
        assert_eq!(
            new_user_partitions.len(),
            original_user_partitions.len() + 2
        );
        for original_partition in &original_user_partitions {
            assert!(new_user_partitions.contains(original_partition));
        }
        // refresh the user key but do NOT preserve access to old partitions
        cc.refresh_user_private_key(&mut usk, &access_policy, &msk, &policy, false)?;
        let new_user_partitions: Vec<Partition> = usk.map().clone().into_keys().collect();
        // the user should still have access to the same number of partitions
        assert_eq!(new_user_partitions.len(), original_user_partitions.len());
        for original_partition in &original_user_partitions {
            assert!(!new_user_partitions.contains(original_partition));
        }
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
        let cc = CoverCrypt::default();
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
        let recovered_key = cc.decaps_symmetric_key(&sk_u, &encrypted_key, KEY_LENGTH)?;
        assert!(key == recovered_key, "Wrong decryption of the key!");
        Ok(())
    }

    #[test]
    fn test_access_policy_to_partition() -> Result<(), Error> {
        //
        // create policy
        let mut policy = policy()?;
        policy.rotate(&Attribute::new("Department", "FIN"))?;

        //
        // create access policy
        let access_policy = AccessPolicy::new("Department", "HR")
            | (AccessPolicy::new("Department", "FIN")
                & AccessPolicy::new("Security Level", "Confidential"));

        //
        // create partitions from access policy
        let partitions = access_policy_to_current_partitions(&access_policy, &policy)?;

        //
        // manually create the partitions
        let mut partitions_ = HashSet::new();
        // add the partitions associated with the HR department: combine with
        // all attributes of the Security Level axis
        let hr_value = policy.attribute_current_value(&Attribute::new("Department", "HR"))?;
        let (security_levels, _) = policy.as_map().get("Security Level").unwrap();
        for attr_name in security_levels {
            let attr_value =
                policy.attribute_current_value(&Attribute::new("Security Level", attr_name))?;
            let mut partition = vec![hr_value, attr_value];
            partition.sort_unstable();
            partitions_.insert(Partition::from_attributes(partition)?);
        }

        // add the other attribute combination: FIN && Confidential
        let fin_value = policy.attribute_current_value(&Attribute::new("Department", "FIN"))?;
        let conf_value =
            policy.attribute_current_value(&Attribute::new("Security Level", "Confidential"))?;
        let mut partition = vec![fin_value, conf_value];
        partition.sort_unstable();
        partitions_.insert(Partition::from_attributes(partition)?);
        // since this is a hyerachical axis, add the lower values: here only protected
        let prot_value =
            policy.attribute_current_value(&Attribute::new("Security Level", "Protected"))?;
        let mut partition = vec![fin_value, prot_value];
        partition.sort_unstable();
        partitions_.insert(Partition::from_attributes(partition)?);

        assert_eq!(partitions, partitions_);
        Ok(())
    }
}
