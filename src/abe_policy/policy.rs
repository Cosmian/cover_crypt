use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    vec,
};

use serde_json::Value;

use super::{
    AccessPolicy, Attribute, AttributeParameters, AttributeStatus, Dimension, DimensionBuilder,
    EncryptionHint, LegacyPolicy, Partition, Policy, PolicyV1, PolicyVersion,
};
use crate::Error;

impl Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Policy {
    /// Converts the given string into a Policy. Does not fail if the given
    /// string uses the legacy format.
    pub fn parse_and_convert(bytes: &[u8]) -> Result<Self, Error> {
        let json_policy: Value =
            serde_json::from_slice(bytes).map_err(Error::DeserializationError)?;

        if let Some(policy_version) = json_policy.get("version") {
            match serde_json::from_value::<PolicyVersion>(policy_version.clone()) {
                Ok(PolicyVersion::V1) => Ok(serde_json::from_slice::<PolicyV1>(bytes)
                    .map_err(Error::DeserializationError)?
                    .into()),
                Ok(PolicyVersion::V2) => {
                    serde_json::from_value::<Self>(json_policy).map_err(Error::DeserializationError)
                }
                Err(e) => Err(Error::DeserializationError(e)),
            }
        } else {
            // Legacy Policy
            Ok(serde_json::from_slice::<LegacyPolicy>(bytes)
                .map_err(Error::DeserializationError)?
                .into())
        }
    }

    /// Generates a new policy object with the given number of attribute
    /// creation (revocation + addition) allowed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: PolicyVersion::V2,
            last_attribute_value: 0,
            dimensions: HashMap::new(),
        }
    }

    /// Adds the given dimension to the policy.
    /// /!\ Invalidates all previous keys and ciphers.
    pub fn add_dimension(&mut self, dim: DimensionBuilder) -> Result<(), Error> {
        if self.dimensions.get(&dim.name).is_some() {
            return Err(Error::ExistingPolicy(dim.name));
        }

        self.dimensions.insert(
            dim.name.clone(),
            Dimension::new(&dim, &mut self.last_attribute_value),
        );

        Ok(())
    }

    /// Removes the given dim from the policy.
    /// /!\ Invalidates all previous keys and ciphers.
    pub fn remove_dimension(&mut self, dim_name: &str) -> Result<(), Error> {
        self.dimensions
            .remove(dim_name)
            .map(|_| ())
            .ok_or(Error::DimensionNotFound(dim_name.to_string()))
    }

    /// Adds the given attribute to the policy.
    /// /!\ No old key will be able to use this attribute. In particular, keys
    /// which associated access policy was implicitly deriving rights for this
    /// dimension (e.g. "`Security::High`" implicitly derives rights for all
    /// attributes from any other dimensions) need to be regenerated. A refresh
    /// will *not* implicitly derive rights for this attribute. Fails if the
    /// dim of the attribute does not exist in the policy.
    ///
    /// * `attr` - The name and dimension of the new attribute.
    /// * `encryption_hint` - Whether to use post quantum keys for this
    ///   attribute
    pub fn add_attribute(
        &mut self,
        attr: Attribute,
        encryption_hint: EncryptionHint,
    ) -> Result<(), Error> {
        match self.dimensions.get_mut(&attr.dimension) {
            Some(policy_dim) => policy_dim.add_attribute(
                &attr.name,
                encryption_hint,
                &mut self.last_attribute_value,
            ),
            None => Err(Error::DimensionNotFound(attr.dimension)),
        }
    }

    /// Removes the given attribute from the policy.
    /// Encrypting and decrypting for this attribute will no longer be possible
    /// once the keys are updated.
    pub fn remove_attribute(&mut self, attr: &Attribute) -> Result<(), Error> {
        if let Some(dim) = self.dimensions.get_mut(&attr.dimension) {
            if dim.nb_attributes() == 1 {
                self.remove_dimension(&attr.dimension)
            } else {
                dim.remove_attribute(&attr.name)
            }
        } else {
            Err(Error::DimensionNotFound(attr.dimension.to_string()))
        }
    }

    /// Marks an attribute as read only.
    /// The corresponding attribute key will be removed from the public key.
    /// But the decryption key will be kept to allow reading old ciphertext.
    pub fn disable_attribute(&mut self, attr: &Attribute) -> Result<(), Error> {
        match self.dimensions.get_mut(&attr.dimension) {
            Some(policy_dim) => policy_dim.disable_attribute(&attr.name),
            None => Err(Error::DimensionNotFound(attr.dimension.to_string())),
        }
    }

    /// Changes the name of an attribute.
    pub fn rename_attribute(&mut self, attr: &Attribute, new_name: &str) -> Result<(), Error> {
        match self.dimensions.get_mut(&attr.dimension) {
            Some(policy_dim) => policy_dim.rename_attribute(&attr.name, new_name),
            None => Err(Error::DimensionNotFound(attr.dimension.to_string())),
        }
    }

    /// Returns the list of Attributes of this Policy.
    #[must_use]
    pub fn attributes(&self) -> Vec<Attribute> {
        self.dimensions
            .iter()
            .flat_map(|(dim_name, dim)| {
                dim.get_attributes_name()
                    .map(|attr_name| Attribute::new(dim_name, attr_name))
            })
            .collect::<Vec<_>>()
    }

    /// Returns the given attribute from the policy.
    /// Fails if there is no such attribute.
    fn get_attribute(&self, attr: &Attribute) -> Result<&AttributeParameters, Error> {
        if let Some(dim) = self.dimensions.get(&attr.dimension) {
            dim.get_attribute(&attr.name)
                .ok_or(Error::AttributeNotFound(attr.to_string()))
        } else {
            Err(Error::DimensionNotFound(attr.dimension.to_string()))
        }
    }

    /// Returns the hybridization hint of the given attribute.
    pub fn get_attribute_hybridization_hint(
        &self,
        attribute: &Attribute,
    ) -> Result<EncryptionHint, Error> {
        self.get_attribute(attribute)
            .map(AttributeParameters::get_encryption_hint)
    }

    /// Retrieves the ID of an attribute.
    pub fn get_attribute_id(&self, attribute: &Attribute) -> Result<u32, Error> {
        self.get_attribute(attribute)
            .map(AttributeParameters::get_id)
    }

    /// Generates all cross-dimension combinations of attributes.
    ///
    /// - `current_dim`            : dim for which to combine other dim
    ///   attributes
    /// - `dimensions`             : list of dimensions
    /// - `attr_values_per_dim`    : map dimensions with their associated
    ///   attribute parameters
    fn combine_attributes(
        current_dim: usize,
        dimensions: &[String],
        attr_params_per_dim: &HashMap<String, Vec<&AttributeParameters>>,
    ) -> Result<Vec<(Vec<u32>, EncryptionHint, AttributeStatus)>, Error> {
        let current_dim_name = match dimensions.get(current_dim) {
            None => {
                return Ok(vec![(
                    vec![],
                    EncryptionHint::Classic,
                    AttributeStatus::EncryptDecrypt,
                )]);
            }
            Some(dim) => dim,
        };

        let current_dim_values = attr_params_per_dim
            .get(current_dim_name)
            .ok_or_else(|| Error::DimensionNotFound(current_dim_name.to_string()))?;

        // Recursive call. Above checks ensure no empty list can be returned.
        let other_values =
            Self::combine_attributes(current_dim + 1, dimensions, attr_params_per_dim)?;

        let mut combinations = Vec::with_capacity(current_dim_values.len() * other_values.len());
        for attr in current_dim_values {
            for (other_values, is_other_hybridized, is_other_readonly) in &other_values {
                let mut combined = Vec::with_capacity(1 + other_values.len());
                combined.push(attr.get_id());
                combined.extend_from_slice(other_values);
                combinations.push((
                    combined,
                    attr.get_encryption_hint() | *is_other_hybridized,
                    attr.get_status() | *is_other_readonly,
                ));
            }
        }
        Ok(combinations)
    }

    /// Generates all possible partitions from this `Policy`. Each partition is
    /// returned with a hint about whether hybridized encryption should be used
    /// and activation status.
    pub fn generate_all_partitions(
        &self,
    ) -> Result<HashMap<Partition, (EncryptionHint, AttributeStatus)>, Error> {
        let mut attr_params_per_dim = HashMap::with_capacity(self.dimensions.len());
        for (dim_name, dim) in &self.dimensions {
            attr_params_per_dim.insert(dim_name.clone(), dim.iter_attributes().collect());
        }

        // Combine axes values into partitions.
        let dimensions = attr_params_per_dim.keys().cloned().collect::<Vec<_>>();
        let combinations = Self::combine_attributes(0, &dimensions, &attr_params_per_dim)?;
        let mut res = HashMap::with_capacity(combinations.len());
        for (combination, is_hybridized, is_readonly) in combinations {
            res.insert(
                Partition::from_attribute_ids(combination)?,
                (is_hybridized, is_readonly),
            );
        }
        Ok(res)
    }

    /// Converts an `AccessPolicy` into a list of corresponding coordinates.
    ///
    /// - `access_policy`   : access policy to convert
    /// - `cascade_rights`  : include lower rights from hierarchical dimensions
    pub fn access_policy_to_partitions(
        &self,
        access_policy: &AccessPolicy,
        cascade_rights: bool,
    ) -> Result<HashSet<Partition>, Error> {
        let attr_combinations = access_policy.to_attribute_combinations(self, cascade_rights)?;
        let mut res = HashSet::with_capacity(attr_combinations.len());
        for attr_combination in &attr_combinations {
            for partition in generate_attribute_partitions(attr_combination, self)? {
                if !res.insert(partition) {
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

/// Converts a list of attributes into a list of `Partitions`, with
/// their associated hybridization hints and attribute status.
///
/// - `attributes`  : list of attributes
/// - `policy`      : global policy data
fn generate_attribute_partitions(
    attributes: &[Attribute],
    policy: &Policy,
) -> Result<HashSet<Partition>, Error> {
    let mut attr_params_per_dim =
        HashMap::<String, Vec<&AttributeParameters>>::with_capacity(policy.dimensions.len());
    for attribute in attributes {
        let entry = attr_params_per_dim
            .entry(attribute.dimension.clone())
            .or_default();
        entry.push(policy.get_attribute(attribute)?);
    }

    // When a dimension is not mentioned in the attribute list, all the attribute
    // from this dimension are used.
    for (dim, dim_properties) in &policy.dimensions {
        if !attr_params_per_dim.contains_key(dim) {
            // gather all the latest value for that dim
            let values = dim_properties.iter_attributes().collect();
            attr_params_per_dim.insert(dim.clone(), values);
        }
    }

    // Combine dimensions attributes into partitions.
    let dimensions = attr_params_per_dim.keys().cloned().collect::<Vec<_>>();
    let combinations = Policy::combine_attributes(0, dimensions.as_slice(), &attr_params_per_dim)?;

    combinations
        .into_iter()
        .map(|(coordinate, _, _)| Partition::from_attribute_ids(coordinate))
        .collect::<Result<HashSet<_>, _>>()
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
        for dim in axes {
            let mut dim_attributes: Vec<(Attribute, u32)> = vec![];
            for name in policy.dimensions[dim].get_attributes_name() {
                let attribute = Attribute::new(dim, name);
                let value = policy.get_attribute_id(&attribute)?;
                dim_attributes.push((attribute, value));
            }
            axes_attributes.push(dim_attributes);
        }
        Ok(axes_attributes)
    }

    #[test]
    fn test_combine_attribute_values() -> Result<(), Error> {
        let policy = policy()?;
        let axes: Vec<String> = policy.dimensions.keys().cloned().collect();

        let axes_attributes = axes_attributes_from_policy(&axes, &policy)?;

        // this should create the combination of the first attribute
        // with all those of the second dim
        let partitions_0 =
            generate_attribute_partitions(&[axes_attributes[0][0].0.clone()], &policy)?;
        assert_eq!(axes_attributes[1].len(), partitions_0.len());
        let att_0_0 = axes_attributes[0][0].1;
        for (_attribute, value) in &axes_attributes[1] {
            let partition = Partition::from_attribute_ids(vec![att_0_0, *value])?;
            assert!(partitions_0.contains(&partition));
        }

        // this should create the single combination of the first attribute
        // of the first dim with that of the second dim
        let partitions_1 = generate_attribute_partitions(
            &[
                axes_attributes[0][0].0.clone(),
                axes_attributes[1][0].0.clone(),
            ],
            &policy,
        )?;
        assert_eq!(partitions_1.len(), 1);
        let att_1_0 = axes_attributes[1][0].1;
        assert!(partitions_1.contains(&Partition::from_attribute_ids(vec![att_0_0, att_1_0])?));

        // this should create the 2 combinations of the first attribute
        // of the first dim with that the wo of the second dim
        let partitions_2 = generate_attribute_partitions(
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
        assert!(partitions_2.contains(&Partition::from_attribute_ids(vec![att_0_0, att_1_0])?,));
        assert!(partitions_2.contains(&Partition::from_attribute_ids(vec![att_0_0, att_1_1])?,));

        Ok(())
    }

    #[test]
    fn test_access_policy_to_partition() -> Result<(), Error> {
        //
        // create policy
        let policy = policy()?;
        //policy.rotate(&Attribute::new("Department", "FIN"))?;

        //
        // create access policy
        let access_policy = AccessPolicy::new("Department", "HR")
            | (AccessPolicy::new("Department", "FIN")
                & AccessPolicy::new("Security Level", "Low Secret"));

        //
        // create partitions from access policy
        let partitions = policy.access_policy_to_partitions(&access_policy, true)?;

        //
        // manually create the partitions
        let mut partitions_ = HashSet::new();

        // add the partitions associated with the HR department: combine with
        // all attributes of the Security Level dim
        let hr_value = policy.get_attribute_id(&Attribute::new("Department", "HR"))?;
        let dim_properties = policy.dimensions.get("Security Level").unwrap();
        for attr_name in dim_properties.get_attributes_name() {
            let attr_value =
                policy.get_attribute_id(&Attribute::new("Security Level", attr_name))?;
            let mut partition = vec![hr_value, attr_value];
            partition.sort_unstable();
            partitions_.insert(Partition::from_attribute_ids(partition)?);
        }

        // add the other attribute combination: FIN && Low Secret
        let fin_value = policy.get_attribute_id(&Attribute::new("Department", "FIN"))?;
        let conf_value =
            policy.get_attribute_id(&Attribute::new("Security Level", "Low Secret"))?;
        let mut partition = vec![fin_value, conf_value];
        partition.sort_unstable();
        partitions_.insert(Partition::from_attribute_ids(partition)?);
        // since this is a hierarchical dim, add the lower values: here only low secret
        let prot_value = policy.get_attribute_id(&Attribute::new("Security Level", "Protected"))?;
        let mut partition = vec![fin_value, prot_value];
        partition.sort_unstable();
        partitions_.insert(Partition::from_attribute_ids(partition)?);

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
            .access_policy_to_partitions(&policy_attributes_4, true)
            .unwrap();

        let policy_attributes_5 = AccessPolicy::from_boolean_expression(
            "(Department::FIN && Security Level::Low Secret) || (Department::MKG && Security \
             Level::Medium Secret)",
        )
        .unwrap();
        let partition_5 = policy
            .access_policy_to_partitions(&policy_attributes_5, true)
            .unwrap();
        assert_eq!(partition_4.len(), 4);
        assert_eq!(partition_5.len(), 5);
        Ok(())
    }
}
