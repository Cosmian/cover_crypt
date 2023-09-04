use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
    ops::BitOr,
};

use serde::{Deserialize, Serialize};

use super::{AccessPolicy, Partition};
use crate::{abe_policy::Attribute, Error};

/// Hint the user about which kind of encryption to use.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionHint {
    /// Hybridized encryption should be used.
    Hybridized,
    /// Classic encryption should be used.
    Classic,
}

impl BitOr for EncryptionHint {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        if self == Self::Hybridized || rhs == Self::Hybridized {
            Self::Hybridized
        } else {
            Self::Classic
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxisAttributeProperties {
    pub name: String,
    pub encryption_hint: EncryptionHint,
}

/// Defines a policy axis by its name and its underlying attribute properties.
/// An attribute property defines its name and a hint about whether hybridized
/// encryption should be used for it (hint set to `true` if this is the case).
///
/// If `hierarchical` is set to `true`, we assume a lexicographical order based
/// on the attribute name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAxis {
    /// Axis name
    pub name: String,
    /// Names of the axis attributes and hybridized encryption hints
    pub attributes_properties: Vec<AxisAttributeProperties>,
    /// `true` if the axis is hierarchical
    pub hierarchical: bool,
}

impl PolicyAxis {
    /// Generates a new policy axis with the given name and attribute names.
    /// A hierarchical axis enforces order between its attributes.
    ///
    /// - `name`                    : axis name
    /// - `attribute_properties`    : axis attribute properties
    /// - `hierarchical`            : set to `true` if the axis is hierarchical
    #[must_use]
    pub fn new(
        name: &str,
        attributes_properties: Vec<(&str, EncryptionHint)>,
        hierarchical: bool,
    ) -> Self {
        Self {
            name: name.to_string(),
            attributes_properties: attributes_properties
                .into_iter()
                .map(|(axis_name, encryption_hint)| AxisAttributeProperties {
                    name: axis_name.to_string(),
                    encryption_hint,
                })
                .collect(),
            hierarchical,
        }
    }

    /// Returns the number of attributes belonging to this axis.
    #[must_use]
    pub fn len(&self) -> usize {
        self.attributes_properties.len()
    }

    /// Return `true` if the attribute list is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attributes_properties.is_empty()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PolicyAxesParameters {
    pub attribute_names: Vec<String>,
    pub is_hierarchical: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PolicyAttributesParameters {
    pub values: Vec<u32>,
    pub encryption_hint: EncryptionHint,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LegacyPolicy {
    /// Last value taken by the attribute.
    pub(crate) last_attribute_value: u32,
    /// Maximum attribute value. Defines a maximum number of attribute
    /// creations (revocations + addition).
    pub max_attribute_creations: u32,
    /// Policy axes: maps axes name to the list of associated attribute names
    /// and a boolean defining whether or not this axis is hierarchical.
    pub axes: HashMap<String, PolicyAxesParameters>,
    /// Maps an attribute to its values and its hybridization hint.
    pub attributes: HashMap<Attribute, Vec<u32>>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyVersion {
    V1,
}

/// A policy is a set of policy axes. A fixed number of attribute creations
/// (revocations + additions) is allowed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Policy {
    /// Version number
    pub version: PolicyVersion,
    /// Last value taken by the attribute.
    pub(crate) last_attribute_value: u32,

    /// Policy axes: maps axes name to the list of associated attribute names
    /// and a boolean defining whether or not this axis is hierarchical.
    pub axes: HashMap<String, PolicyAxesParameters>,
    /// Maps an attribute to its values and its hybridization hint.
    pub attributes: HashMap<Attribute, PolicyAttributesParameters>,
}

impl Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Policy {
    /// Converts the given string into a Policy. Does not fail if the given
    /// string uses the legacy format.
    pub fn parse_and_convert(bytes: &[u8]) -> Result<Self, Error> {
        // First try to deserialize the latest `Policy` format
        match serde_json::from_slice(bytes) {
            Ok(policy) => Ok(policy),
            Err(e) => {
                if let Ok(policy) = serde_json::from_slice::<LegacyPolicy>(bytes) {
                    // Convert the legacy format to the current one.
                    Ok(Self {
                        version: PolicyVersion::V1,
                        last_attribute_value: policy.last_attribute_value,
                        axes: policy.axes,
                        attributes: policy
                            .attributes
                            .into_iter()
                            .map(|(name, values)| {
                                (
                                    name,
                                    PolicyAttributesParameters {
                                        values,
                                        encryption_hint: EncryptionHint::Classic,
                                    },
                                )
                            })
                            .collect(),
                    })
                } else {
                    Err(Error::DeserializationError(e))
                }
            }
        }
    }

    /// Generates a new policy object with the given number of attribute
    /// creation (revocation + addition) allowed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: PolicyVersion::V1,
            last_attribute_value: 0,
            axes: HashMap::new(),
            attributes: HashMap::new(),
        }
    }

    /// Adds the given policy axis to the policy.
    pub fn add_axis(&mut self, axis: PolicyAxis) -> Result<(), Error> {
        if self.axes.get(&axis.name).is_some() {
            return Err(Error::ExistingPolicy(axis.name));
        }
        let mut axis_attributes = Vec::with_capacity(axis.attributes_properties.len());

        for properties in axis.attributes_properties {
            self.last_attribute_value += 1;
            axis_attributes.push(properties.name.clone());
            let attribute = (axis.name.clone(), properties.name.clone()).into();
            if self.attributes.get(&attribute).is_some() {
                return Err(Error::ExistingPolicy(format!("{attribute:?}")));
            }
            self.attributes.insert(
                attribute,
                PolicyAttributesParameters {
                    values: [self.last_attribute_value].into(),
                    encryption_hint: properties.encryption_hint,
                },
            );
        }

        self.axes.insert(
            axis.name,
            PolicyAxesParameters {
                attribute_names: axis_attributes,
                is_hierarchical: axis.hierarchical,
            },
        );

        Ok(())
    }

    pub fn add_attribute(
        &mut self,
        attr: Attribute,
        encryption_hint: EncryptionHint,
    ) -> Result<(), Error> {
        if self.attributes.get(&attr).is_some() {
            return Err(Error::ExistingPolicy(format!("{attr:?}")));
        }

        match self.axes.get(&attr.axis) {
            Some(policy_axis) => {
                self.last_attribute_value += 1;
                let attribute_parameters = PolicyAttributesParameters {
                    values: [self.last_attribute_value].into(),
                    encryption_hint,
                };
                self.attributes.insert(attr.clone(), attribute_parameters);

                let mut new_policy_axis = policy_axis.clone();
                new_policy_axis.attribute_names.push(attr.name);
                self.axes.insert(attr.axis, new_policy_axis);

                Ok(())
            }
            None => Err(Error::AxisNotFound(attr.axis)),
        }
    }

    /// Rotates an attribute, changing its underlying value with an unused
    /// value.
    pub fn rotate(&mut self, attr: &Attribute) -> Result<(), Error> {
        if let Some(attribute_parameters) = self.attributes.get_mut(attr) {
            self.last_attribute_value += 1;
            attribute_parameters.values.push(self.last_attribute_value);
            Ok(())
        } else {
            Err(Error::AttributeNotFound(attr.to_string()))
        }
    }

    /// Returns the list of Attributes of this Policy.
    #[must_use]
    pub fn attributes(&self) -> Vec<Attribute> {
        self.attributes.keys().cloned().collect::<Vec<Attribute>>()
    }

    /// Returns the list of all values given to this attribute over rotations.
    /// The current value is returned first
    pub fn attribute_values(&self, attribute: &Attribute) -> Result<Vec<u32>, Error> {
        self.attributes
            .get(attribute)
            .map(|attribute_parameters| attribute_parameters.values.iter().rev().copied().collect())
            .ok_or_else(|| Error::AttributeNotFound(attribute.to_string()))
    }

    /// Returns the hybridization hint of the given attribute.
    pub fn attribute_hybridization_hint(
        &self,
        attribute: &Attribute,
    ) -> Result<EncryptionHint, Error> {
        self.attributes
            .get(attribute)
            .map(|attribute_parameters| attribute_parameters.encryption_hint)
            .ok_or_else(|| Error::AttributeNotFound(attribute.to_string()))
    }

    /// Retrieves the current value of an attribute.
    pub fn attribute_current_value(&self, attribute: &Attribute) -> Result<u32, Error> {
        self.attributes
            .get(attribute)
            .map(|attribute_parameters| {
                attribute_parameters.values[attribute_parameters.values.len() - 1]
            })
            .ok_or_else(|| Error::AttributeNotFound(attribute.to_string()))
    }

    /// Generates all cross-axes combinations of attribute values.
    ///
    /// - `current_axis`            : axis for which to combine values with
    ///   other axes
    /// - `axes`                    : list of axes
    /// - `attr_values_per_axis`    : map axes with their associated attribute
    ///   values
    fn combine_attribute_values(
        current_axis: usize,
        axes: &[String],
        attr_values_per_axis: &HashMap<String, Vec<(u32, EncryptionHint)>>,
    ) -> Result<Vec<(Vec<u32>, EncryptionHint)>, Error> {
        let current_axis_name = match axes.get(current_axis) {
            None => return Ok(vec![(vec![], EncryptionHint::Classic)]),
            Some(axis) => axis,
        };

        let current_axis_values = attr_values_per_axis
            .get(current_axis_name)
            .ok_or_else(|| Error::AxisNotFound(current_axis_name.to_string()))?;

        // Recursive call. Above checks ensure no empty list can be returned.
        let other_values =
            Self::combine_attribute_values(current_axis + 1, axes, attr_values_per_axis)?;

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

    /// Generates all possible partitions from this `Policy`. Each partition is
    /// returned with a hint about whether hybridized encryption should be used.
    pub fn generate_all_partitions(&self) -> Result<HashMap<Partition, EncryptionHint>, Error> {
        let mut attr_values_per_axis = HashMap::with_capacity(self.axes.len());
        for (axis_name, axis_properties) in &self.axes {
            let mut values = Vec::with_capacity(axis_properties.attribute_names.len());
            for attr_name in &axis_properties.attribute_names {
                let attribute = Attribute::new(axis_name, attr_name);
                // Hybridization hint is interleaved to allow easy combinations.
                let is_hybridized = self.attribute_hybridization_hint(&attribute)?;
                let av = self
                    .attribute_values(&attribute)?
                    .into_iter()
                    .map(|v| (v, is_hybridized));
                values.extend(av);
            }
            attr_values_per_axis.insert(axis_name.clone(), values);
        }

        // Combine axes values into partitions.
        let axes = attr_values_per_axis.keys().cloned().collect::<Vec<_>>();
        let combinations = Self::combine_attribute_values(0, &axes, &attr_values_per_axis)?;
        let mut res = HashMap::with_capacity(combinations.len());
        for (combination, is_hybridized) in combinations {
            res.insert(
                Partition::from_attribute_values(combination)?,
                is_hybridized,
            );
        }
        Ok(res)
    }

    /// Generates an `AccessPolicy` into the list of corresponding current
    /// partitions.
    ///
    /// - `access_policy`               : access policy to convert
    /// - `follow_hierarchical_axes`    : set to `true` to combine lower axis
    ///   attributes
    pub fn access_policy_to_current_partitions(
        &self,
        access_policy: &AccessPolicy,
        follow_hierarchical_axes: bool,
    ) -> Result<HashSet<Partition>, Error> {
        let attr_combinations =
            access_policy.to_attribute_combinations(self, follow_hierarchical_axes)?;
        let mut res = HashSet::with_capacity(attr_combinations.len());
        for attr_combination in &attr_combinations {
            for partition in generate_current_attribute_partitions(attr_combination, self)? {
                let is_unique = res.insert(partition);
                if !is_unique {
                    return Err(Error::ExistingCombination(format!("{attr_combination:?}")));
                }
            }
        }
        Ok(res)
    }
}

impl TryFrom<&[u8]> for Policy {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::parse_and_convert(bytes)
    }
}

impl TryFrom<&Policy> for Vec<u8> {
    type Error = Error;

    fn try_from(policy: &Policy) -> Result<Self, Self::Error> {
        serde_json::to_vec(policy).map_err(Self::Error::DeserializationError)
    }
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
    let combinations =
        Policy::combine_attribute_values(0, axes.as_slice(), &current_attr_value_per_axis)?;
    let mut res = HashSet::with_capacity(combinations.len());
    for (combination, _) in combinations {
        res.insert(Partition::from_attribute_values(combination)?);
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::policy;

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
                & AccessPolicy::new("Security Level", "Low Secret"));

        //
        // create partitions from access policy
        let partitions = policy.access_policy_to_current_partitions(&access_policy, true)?;

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

        // add the other attribute combination: FIN && Low Secret
        let fin_value = policy.attribute_current_value(&Attribute::new("Department", "FIN"))?;
        let conf_value =
            policy.attribute_current_value(&Attribute::new("Security Level", "Low Secret"))?;
        let mut partition = vec![fin_value, conf_value];
        partition.sort_unstable();
        partitions_.insert(Partition::from_attribute_values(partition)?);
        // since this is a hierarchical axis, add the lower values: here only low secret
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
            "(Department::FIN && Security Level::Low Secret) || (Department::MKG && Security \
             Level::Low Secret)",
        )
        .unwrap();
        let partition_4 = policy
            .access_policy_to_current_partitions(&policy_attributes_4, true)
            .unwrap();

        let policy_attributes_5 = AccessPolicy::from_boolean_expression(
            "(Department::FIN && Security Level::Low Secret) || (Department::MKG && Security \
             Level::Medium Secret)",
        )
        .unwrap();
        let partition_5 = policy
            .access_policy_to_current_partitions(&policy_attributes_5, true)
            .unwrap();
        assert_eq!(partition_4.len(), 4);
        assert_eq!(partition_5.len(), 5);
        Ok(())
    }
}
