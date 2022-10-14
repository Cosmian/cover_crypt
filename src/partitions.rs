use crate::{bytes_ser_de::Serializer, Error};
use abe_policy::{AccessPolicy, Attribute, Policy};
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    ops::Deref,
};

/// Partition associated to a subset. It corresponds to a combination
/// of attributes across all axes.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct Partition(pub(crate) Vec<u8>);

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
        let mut ser = Serializer::new();
        for value in attribute_values {
            ser.write_u64(value as u64)?;
        }
        Ok(Self(ser.finalize()))
    }
}

impl Deref for Partition {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for Partition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
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

/// Generate all possible partitions from the given policy.
///
/// - `policy`  : policy from which to generate partitions
pub(crate) fn all_partitions(policy: &Policy) -> Result<HashSet<Partition>, Error> {
    // Build a map of all attribute values for all axes
    let mut map = HashMap::with_capacity(policy.axes.len());
    // We also collect a `Vec` of axes which is used later
    let mut axes = Vec::with_capacity(policy.axes.len());
    for (axis, (attribute_names, _hierarchical)) in &policy.axes {
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
pub(crate) fn to_partitions(
    attributes: &[Attribute],
    policy: &Policy,
) -> Result<HashSet<Partition>, Error> {
    // First split the attributes per axis using their latest value and check that
    // they exist
    let mut map = HashMap::new();
    for attribute in attributes.iter() {
        let value = policy.attribute_current_value(attribute)?;
        let entry: &mut Vec<u32> = map.entry(attribute.axis.to_owned()).or_default();
        entry.push(value);
    }

    // when an axis is not mentioned in the attributes list,
    // assume that the user wants to cover all the attribute names
    // in this axis
    // We also collect a `Vec` of axes which is used later
    let mut axes = Vec::with_capacity(policy.axes.len());
    for (axis, (attribute_names, _hierarchical)) in &policy.axes {
        axes.push(axis.to_owned());
        if !map.contains_key(axis) {
            // gather all the latest value for that axis
            let values = attribute_names
                .iter()
                .map(|name| policy.attribute_current_value(&Attribute::new(axis, name)))
                .collect::<Result<_, _>>()?;
            map.insert(axis.to_owned(), values);
        }
    }

    let combinations = combine_attribute_values(0, axes.as_slice(), &map)?;
    let mut set = HashSet::with_capacity(combinations.len());
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
    // get the axes attribute value, wrapped into a `Vec`
    let axis_values = map.get(axis).ok_or_else(|| {
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
pub(crate) fn access_policy_to_current_partitions(
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
/// - `access_policy`   : access policy to convert into attribute combinations
/// - `policy`          : global policy
fn to_attribute_combinations(
    access_policy: &AccessPolicy,
    policy: &Policy,
) -> Result<Vec<Vec<Attribute>>, Error> {
    match access_policy {
        AccessPolicy::Attr(attr) => {
            let (attribute_names, is_hierarchical) = policy
                .axes
                .get(&attr.axis)
                .ok_or_else(|| Error::UnknownPartition(attr.axis.to_owned()))?;
            let mut res = vec![vec![attr.clone()]];
            if *is_hierarchical {
                // add attribute values for all attributes below the given one
                for name in attribute_names.iter() {
                    if *name == attr.name {
                        break;
                    }
                    res.push(vec![Attribute::new(&attr.axis, name)]);
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
        AccessPolicy::All => Ok(vec![vec![]]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abe_policy::PolicyAxis;

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
            let attribute_names = &policy.axes[axis].0;
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
        let axes: Vec<String> = policy.axes.keys().into_iter().cloned().collect();

        let axes_attributes = axes_attributes_from_policy(&axes, &policy)?;

        // this should create the combination of the first attribute
        // with all those of the second axis
        let partitions_0 = to_partitions(&[axes_attributes[0][0].0.clone()], &policy)?;
        assert_eq!(axes_attributes[1].len(), partitions_0.len());
        let att_0_0 = axes_attributes[0][0].1;
        for (_attribute, value) in &axes_attributes[1] {
            let partition = Partition::from_attributes(vec![att_0_0, *value])?;
            assert!(partitions_0.contains(&partition));
        }

        // this should create the single combination of the first attribute
        // of the first axis with that of the second axis
        let partitions_1 = to_partitions(
            &[
                axes_attributes[0][0].0.clone(),
                axes_attributes[1][0].0.clone(),
            ],
            &policy,
        )?;
        assert_eq!(partitions_1.len(), 1);
        let att_1_0 = axes_attributes[1][0].1;
        assert!(partitions_1.contains(&Partition::from_attributes(vec![att_0_0, att_1_0])?));

        // this should create the 2 combinations of the first attribute
        // of the first axis with that the wo of the second axis
        let partitions_2 = to_partitions(
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
        let partitions_3 = to_partitions(
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
}
