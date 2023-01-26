use crate::Error;
use abe_policy::{AccessPolicy, Attribute, EncryptionHint, Policy};
use cosmian_crypto_core::bytes_ser_de::Serializer;
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    hash::Hash,
    ops::Deref,
};

/// Partition associated to a subset. It corresponds to a combination
/// of attributes across all axes.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct Partition(pub(crate) Vec<u8>);

impl Partition {
    /// Creates a `Partition` from the given list of the attribute values.
    pub fn from_attribute_values(mut attribute_values: Vec<u32>) -> Result<Self, Error> {
        // guard against overflow of the 1024 bytes buffer below
        if attribute_values.len() > 200 {
            return Err(Error::InvalidAttribute(
                "The current implementation does not currently support more than 200 attributes \
                 for a partition"
                    .to_string(),
            ));
        }
        // the sort operation allows to get the same `Partition` for :
        // `Department::HR || Level::Secret`
        // and
        // `Level::Secret || Department::HR`
        attribute_values.sort_unstable();
        // the actual size in bytes will be at least equal to the length
        let mut ser = Serializer::with_capacity(attribute_values.len());
        for value in attribute_values {
            ser.write_u64(u64::from(value))?;
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

/// Generates all possible partitions from the given policy. Each partition is
/// returned with a hint about whether hybridized encryption should be used.
///
/// - `policy`  : policy from which to generate partitions
pub fn generate_all_partitions(
    policy: &Policy,
) -> Result<HashMap<Partition, EncryptionHint>, Error> {
    let mut attr_values_per_axis = HashMap::with_capacity(policy.axes.len());
    for (axis_name, axis_properties) in &policy.axes {
        let mut values = Vec::with_capacity(axis_properties.attribute_names.len());
        for attr_name in &axis_properties.attribute_names {
            let attribute = Attribute::new(axis_name, attr_name);
            // Hybridization hint is interleaved to allow easy combinations.
            let is_hybridized = policy.attribute_hybridization_hint(&attribute)?;
            let av = policy
                .attribute_values(&attribute)?
                .into_iter()
                .map(|v| (v, is_hybridized));
            values.extend(av);
        }
        attr_values_per_axis.insert(axis_name.clone(), values);
    }

    // Combine axes values into partitions.
    let axes = attr_values_per_axis.keys().cloned().collect::<Vec<_>>();
    let combinations = combine_attribute_values(0, &axes, &attr_values_per_axis)?;
    let mut res = HashMap::with_capacity(combinations.len());
    for (combination, is_hybridized) in combinations {
        res.insert(
            Partition::from_attribute_values(combination)?,
            is_hybridized,
        );
    }
    Ok(res)
}

/// Converts a list of attributes into the list of current `Partitions`, with
/// their associated hybridization hints.
///
/// - `attributes`  : list of attributes
/// - `policy`      : global policy data
fn generate_current_attribute_partitions(
    attributes: &[Attribute],
    policy: &Policy,
) -> Result<HashSet<Partition>, Error> {
    let mut current_attr_value_per_axis = HashMap::<String, Vec<(u32, EncryptionHint)>>::new();
    for attribute in attributes.iter() {
        let entry = current_attr_value_per_axis
            .entry(attribute.axis.clone())
            .or_default();
        entry.push((
            policy.attribute_current_value(attribute)?,
            policy.attribute_hybridization_hint(attribute)?,
        ));
    }

    // When an axis is not mentioned in the attribute list, all the attribute
    // from this axis are used.
    for (axis, axis_properties) in &policy.axes {
        if !current_attr_value_per_axis.contains_key(axis) {
            // gather all the latest value for that axis
            let values = axis_properties
                .attribute_names
                .iter()
                .map(|name| {
                    let attribute = Attribute::new(axis, name);
                    Ok((
                        policy.attribute_current_value(&attribute)?,
                        policy.attribute_hybridization_hint(&attribute)?,
                    ))
                })
                .collect::<Result<_, Error>>()?;
            current_attr_value_per_axis.insert(axis.clone(), values);
        }
    }

    // Combine axes values into partitions.
    let axes = current_attr_value_per_axis
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let combinations = combine_attribute_values(0, axes.as_slice(), &current_attr_value_per_axis)?;
    let mut res = HashSet::with_capacity(combinations.len());
    for (combination, _) in combinations {
        res.insert(Partition::from_attribute_values(combination)?);
    }
    Ok(res)
}

/// Generates all cross-axes combinations of attribute values.
///
/// - `current_axis`            : axis for which to combine values with other axes
/// - `axes`                    : list of axes
/// - `attr_values_per_axis`    : map axes with their associated attribute values
fn combine_attribute_values(
    current_axis: usize,
    axes: &[String],
    attr_values_per_axis: &HashMap<String, Vec<(u32, EncryptionHint)>>,
) -> Result<Vec<(Vec<u32>, EncryptionHint)>, Error> {
    let current_axis_name = match axes.get(current_axis) {
        None => return Ok(vec![(vec![], EncryptionHint::Classic)]),
        Some(axis) => axis,
    };

    let current_axis_values = attr_values_per_axis.get(current_axis_name).ok_or_else(|| {
        Error::Other(format!(
            "no attribute value found for axis: {current_axis_name}",
        ))
    })?;

    // Recursive call. Above checks ensure no empty list can be returned.
    let other_values = combine_attribute_values(current_axis + 1, axes, attr_values_per_axis)?;

    let mut combinations = Vec::with_capacity(current_axis_values.len() * other_values.len());
    for (current_values, is_hybridized) in current_axis_values {
        for (other_values, is_other_hybridized) in &other_values {
            let mut combined = Vec::with_capacity(1 + other_values.len());
            combined.push(*current_values);
            combined.extend_from_slice(other_values);
            combinations.push((
                combined,
                if (*is_hybridized == EncryptionHint::Hybridized)
                    || (*is_other_hybridized == EncryptionHint::Hybridized)
                {
                    EncryptionHint::Hybridized
                } else {
                    EncryptionHint::Classic
                },
            ));
        }
    }
    Ok(combinations)
}

/// Generates an `AccessPolicy` into the list of corresponding current partitions.
///
/// - `access_policy`               : access policy to convert
/// - `policy`                      : global policy data
/// - `follow_hierarchical_axes`    : set to `true` to combine lower axis attributes
pub fn access_policy_to_current_partitions(
    access_policy: &AccessPolicy,
    policy: &Policy,
    follow_hierarchical_axes: bool,
) -> Result<HashSet<Partition>, Error> {
    let attr_combinations =
        access_policy.to_attribute_combinations(policy, follow_hierarchical_axes)?;
    println!("All combinations: {attr_combinations:?}");
    let mut res = HashSet::with_capacity(attr_combinations.len());
    for attr_combination in &attr_combinations {
        println!("{attr_combination:?}");
        for partition in generate_current_attribute_partitions(attr_combination, policy)? {
            let is_unique = res.insert(partition);
            if !is_unique {
                return Err(Error::ExistingCombination(attr_combination.to_vec(), attr_combinations));
            }
        }
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statics::tests::policy;

    fn axes_attributes_from_policy(
        axes: &[String],
        policy: &Policy,
    ) -> Result<Vec<Vec<(Attribute, u32)>>, Error> {
        let mut axes_attributes: Vec<Vec<(Attribute, u32)>> = vec![];
        for axis in axes {
            let mut axis_attributes: Vec<(Attribute, u32)> = vec![];
            for name in &policy.axes[axis].attribute_names {
                let attribute = Attribute::new(axis, name);
                let value = policy.attribute_current_value(&attribute)?;
                axis_attributes.push((attribute, value));
            }
            axes_attributes.push(axis_attributes);
        }
        Ok(axes_attributes)
    }

    #[test]
    fn test_partitions() -> Result<(), Error> {
        let mut values: Vec<u32> = vec![12, 0, u32::MAX, 1];
        let partition = Partition::from_attribute_values(values.clone())?;
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
    fn test_combine_attribute_values() -> Result<(), Error> {
        let mut policy = policy()?;
        let axes: Vec<String> = policy.axes.keys().cloned().collect();

        let axes_attributes = axes_attributes_from_policy(&axes, &policy)?;

        // this should create the combination of the first attribute
        // with all those of the second axis
        let partitions_0 =
            generate_current_attribute_partitions(&[axes_attributes[0][0].0.clone()], &policy)?;
        assert_eq!(axes_attributes[1].len(), partitions_0.len());
        let att_0_0 = axes_attributes[0][0].1;
        for (_attribute, value) in &axes_attributes[1] {
            let partition = Partition::from_attribute_values(vec![att_0_0, *value])?;
            assert!(partitions_0.contains(&partition));
        }

        // this should create the single combination of the first attribute
        // of the first axis with that of the second axis
        let partitions_1 = generate_current_attribute_partitions(
            &[
                axes_attributes[0][0].0.clone(),
                axes_attributes[1][0].0.clone(),
            ],
            &policy,
        )?;
        assert_eq!(partitions_1.len(), 1);
        let att_1_0 = axes_attributes[1][0].1;
        assert!(partitions_1.contains(&Partition::from_attribute_values(vec![att_0_0, att_1_0])?));

        // this should create the 2 combinations of the first attribute
        // of the first axis with that the wo of the second axis
        let partitions_2 = generate_current_attribute_partitions(
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
        assert!(partitions_2.contains(&Partition::from_attribute_values(vec![att_0_0, att_1_0])?,));
        assert!(partitions_2.contains(&Partition::from_attribute_values(vec![att_0_0, att_1_1])?,));

        // rotation
        policy.rotate(&axes_attributes[0][0].0)?;
        let axes_attributes = axes_attributes_from_policy(&axes, &policy)?;

        // this should create the single combination of the first attribute
        // of the first axis with that of the second axis
        let partitions_3 = generate_current_attribute_partitions(
            &[
                axes_attributes[0][0].0.clone(),
                axes_attributes[1][0].0.clone(),
            ],
            &policy,
        )?;
        assert_eq!(partitions_3.len(), 1);
        let att_1_0 = axes_attributes[1][0].1;
        let att_0_0_new = axes_attributes[0][0].1;
        assert!(
            partitions_3.contains(&Partition::from_attribute_values(vec![
                att_0_0_new,
                att_1_0
            ])?)
        );
        assert!(!partitions_3.contains(&Partition::from_attribute_values(vec![att_0_0, att_1_0])?));

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
        let partitions = access_policy_to_current_partitions(&access_policy, &policy, true)?;

        //
        // manually create the partitions
        let mut partitions_ = HashSet::new();
        // add the partitions associated with the HR department: combine with
        // all attributes of the Security Level axis
        let hr_value = policy.attribute_current_value(&Attribute::new("Department", "HR"))?;
        let axis_properties = policy.axes.get("Security Level").unwrap();
        for attr_name in &axis_properties.attribute_names {
            let attr_value =
                policy.attribute_current_value(&Attribute::new("Security Level", attr_name))?;
            let mut partition = vec![hr_value, attr_value];
            partition.sort_unstable();
            partitions_.insert(Partition::from_attribute_values(partition)?);
        }

        // add the other attribute combination: FIN && Confidential
        let fin_value = policy.attribute_current_value(&Attribute::new("Department", "FIN"))?;
        let conf_value =
            policy.attribute_current_value(&Attribute::new("Security Level", "Confidential"))?;
        let mut partition = vec![fin_value, conf_value];
        partition.sort_unstable();
        partitions_.insert(Partition::from_attribute_values(partition)?);
        // since this is a hierarchical axis, add the lower values: here only protected
        let prot_value =
            policy.attribute_current_value(&Attribute::new("Security Level", "Protected"))?;
        let mut partition = vec![fin_value, prot_value];
        partition.sort_unstable();
        partitions_.insert(Partition::from_attribute_values(partition)?);

        assert_eq!(partitions, partitions_);

        //
        // check the number of partitions generated by some access policies
        //
        let policy_attributes_4 = AccessPolicy::from_boolean_expression(
            "(Department::FIN && Security Level::Top Secret) || (Department::MKG && Security \
             Level::Protected)",
        )
        .unwrap();
        let partition_4 =
            access_policy_to_current_partitions(&policy_attributes_4, &policy, true).unwrap();

        let policy_attributes_5 = AccessPolicy::from_boolean_expression(
            "(Department::FIN && Security Level::Top Secret) || (Department::MKG && Security \
             Level::Confidential)",
        )
        .unwrap();
        let partition_5 =
            access_policy_to_current_partitions(&policy_attributes_5, &policy, true).unwrap();
        assert_eq!(partition_4.len(), 4);
        assert_eq!(partition_5.len(), 5);
        Ok(())
    }
}
