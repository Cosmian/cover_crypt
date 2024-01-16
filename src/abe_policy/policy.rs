use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    vec,
};

use super::{
    AccessPolicy, Attribute, AttributeParameters, AttributeStatus, Dimension, DimensionBuilder,
    EncryptionHint, Partition, Policy, PolicyVersion,
};
use crate::Error;

impl Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: PolicyVersion::V2,
            last_attribute_value: 0,
            dimensions: HashMap::new(),
        }
    }
}

impl Policy {
    /// Generates a new policy object with the given number of attribute
    /// creation (revocation + addition) allowed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the given dimension to the policy.
    /// /!\ Invalidates all previous keys and ciphers.
    pub fn add_dimension(&mut self, dim: DimensionBuilder) -> Result<(), Error> {
        if self.dimensions.get(&dim.name).is_some() {
            return Err(Error::ExistingPolicy(dim.name));
        }

        self.dimensions.insert(
            dim.name.clone(),
            Dimension::new(dim, &mut self.last_attribute_value),
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
    /// will *not* implicitly derive rights for this attribute.
    /// Fails if the dim of the attribute does not exist in the policy.
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
            Some(policy_dim) => {
                policy_dim.add_attribute(attr.name, encryption_hint, &mut self.last_attribute_value)
            }
            None => Err(Error::DimensionNotFound(attr.dimension)),
        }
    }

    /// Removes the given attribute from the policy.
    /// Encrypting and decrypting for this attribute will no longer be possible
    /// once the keys are updated.
    pub fn remove_attribute(&mut self, attr: &Attribute) -> Result<(), Error> {
        if let Some(dim) = self.dimensions.get_mut(&attr.dimension) {
            if dim.nb_attributes() == 1 {
                // TODO: temporary fix before we allow removing an entire dimension
                // self.remove_dimension(&attr.dimension)
                Err(Error::UnsupportedOperator(
                    "Removing the last attribute of a dimension is currently not supported"
                        .to_string(),
                ))
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
    pub fn rename_attribute(&mut self, attr: &Attribute, new_name: String) -> Result<(), Error> {
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

    /// Generates all coordinates defined by this policy and return their hybridization and
    /// activation status.
    pub fn generate_universal_coordinates(
        &self,
    ) -> Result<HashMap<Partition, (EncryptionHint, AttributeStatus)>, Error> {
        let universe = self.dimensions.iter().collect::<Vec<_>>();
        combine(universe.as_slice())
            .into_iter()
            .map(|(combination, is_hybridized, is_readonly)| {
                Partition::from_attribute_ids(combination)
                    .map(|coordinate| (coordinate, (is_hybridized, is_readonly)))
            })
            .collect()
    }

    /// Generates all coordinates defined by the semantic space of the given access policy.
    ///
    /// The semantic space is define as the smallest subspace of the universe in which the given
    /// access policy can be expressed. Equivalently, this is the envelop of the points associated
    /// to each DNF conjunction.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is invalid.
    pub fn generate_semantic_space_coordinates(
        &self,
        ap: AccessPolicy,
    ) -> Result<HashSet<Partition>, Error> {
        let dnf = ap.into_dnf();
        let mut coordinates = HashSet::new();
        for conjunction in dnf {
            let semantic_space = conjunction
                .into_iter()
                .map(|attr| {
                    self.dimensions
                        .get(&attr.dimension)
                        .ok_or_else(|| Error::DimensionNotFound(attr.dimension.clone()))
                        .and_then(|dim| dim.restrict(attr.name))
                        .map(|dim| (attr.dimension, dim))
                })
                .collect::<Result<HashMap<_, _>, Error>>()?;
            // TODO: Some coordinates may be computed twice (the lower dimensions).
            for (ids, _, _) in combine(&semantic_space.iter().collect::<Vec<_>>()) {
                coordinates.insert(Partition::from_attribute_ids(ids)?);
            }
        }
        Ok(coordinates)
    }

    /// Returns the coordinates of the points defined by the given access policy.
    ///
    /// Each conjunction of the associated DNF defines a unique universal point.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is invalid.
    pub fn generate_point_coordinates(
        &self,
        ap: AccessPolicy,
    ) -> Result<HashSet<Partition>, Error> {
        let dnf = ap.into_dnf();
        let mut coordinates = HashSet::with_capacity(dnf.len());
        for conjunction in dnf {
            let coo = Partition::from_attribute_ids(
                conjunction
                    .into_iter()
                    .map(|attr| self.get_attribute(&attr).map(|params| params.id))
                    .collect::<Result<_, Error>>()?,
            )?;
            coordinates.insert(coo);
        }
        Ok(coordinates)
    }
}

/// Combines all attributes IDs from the given dimensions using at most one attribute for each
/// dimensions. Returns the disjunction of the associated hybridization and activation status.
///
/// As an example, if dimensions D1::A1 and D2::(A2,B2) are given, the following combinations will be created:
/// - D1::A1
/// - D1::A1 && D2::A2
/// - D1::A1 && D2::B2
/// - D2::A2
/// - D2::B2
#[allow(dead_code)]
pub fn combine(
    dimensions: &[(&String, &Dimension)], // TODO: signature depends on the HashMap iterator type
) -> Vec<(Vec<u32>, EncryptionHint, AttributeStatus)> {
    if dimensions.is_empty() {
        vec![(
            vec![],
            EncryptionHint::Classic,
            AttributeStatus::EncryptDecrypt,
        )]
    } else {
        let (_, current_dimension) = &dimensions[0];
        let partial_combinations = combine(&dimensions[1..]);
        let mut res = vec![];
        for component in current_dimension.attributes() {
            for (ids, is_hybridized, is_activated) in &partial_combinations {
                res.push((
                    [vec![component.get_id()], ids.clone()].concat(),
                    *is_hybridized | component.get_encryption_hint(),
                    *is_activated | component.get_status(),
                ));
            }
        }
        [partial_combinations.clone(), res].concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::policy;

    #[test]
    fn test_combine() {
        let mut policy = policy().unwrap();

        // There should be `Prod_dim(|dim| + 1)` coordinates.
        assert_eq!(
            combine(&policy.dimensions.iter().collect::<Vec<_>>()).len(),
            policy
                .dimensions
                .values()
                .map(|dim| dim.attributes().count() + 1)
                .product::<usize>()
        );

        policy
            .add_dimension(DimensionBuilder::new(
                "Country",
                vec![
                    ("France", EncryptionHint::Classic),
                    ("Germany", EncryptionHint::Classic),
                    ("Spain", EncryptionHint::Classic),
                ],
                false,
            ))
            .unwrap();

        // There should be `Prod_dim(|dim| + 1)` coordinates.
        assert_eq!(
            combine(&policy.dimensions.iter().collect::<Vec<_>>()).len(),
            policy
                .dimensions
                .values()
                .map(|dim| dim.attributes().count() + 1)
                .product::<usize>()
        );
    }

    #[test]
    fn test_generate_semantic_coordinates() -> Result<(), Error> {
        let policy = policy()?;

        let ap = "(Department::HR || Department::FIN) && Security Level::Low Secret";

        let semantic_space_coordinates = policy
            .generate_semantic_space_coordinates(AccessPolicy::from_boolean_expression(ap)?)?;

        // Check the number of coordinates is correct.
        assert_eq!(semantic_space_coordinates.len(), (2 + 1) * (2 + 1));

        // Check the coordinates are the same as the ones manually generated, i.e.:
        // - Coordinate()
        // - Coordinate(HR)
        // - Coordinate(FIN)
        // - Coordinate(Protected)
        // - Coordinate(Low Secret)
        // - Coordinate(HR, Protected)
        // - Coordinate(HR, Low Secret)
        // - Coordinate(FIN, Protected)
        // - Coordinate(FIN, Low Secret)
        {
            let mut coordinates = HashSet::new();

            coordinates.insert(Partition::from_attribute_ids(vec![])?);

            coordinates.insert(Partition::from_attribute_ids(vec![policy
                .get_attribute_id(&Attribute {
                    dimension: "Department".to_string(),
                    name: "HR".to_string(),
                })?])?);

            coordinates.insert(Partition::from_attribute_ids(vec![policy
                .get_attribute_id(&Attribute {
                    dimension: "Department".to_string(),
                    name: "FIN".to_string(),
                })?])?);

            coordinates.insert(Partition::from_attribute_ids(vec![policy
                .get_attribute_id(&Attribute {
                    dimension: "Security Level".to_string(),
                    name: "Protected".to_string(),
                })?])?);

            coordinates.insert(Partition::from_attribute_ids(vec![policy
                .get_attribute_id(&Attribute {
                    dimension: "Security Level".to_string(),
                    name: "Low Secret".to_string(),
                })?])?);

            coordinates.insert(Partition::from_attribute_ids(vec![
                policy.get_attribute_id(&Attribute {
                    dimension: "Department".to_string(),
                    name: "HR".to_string(),
                })?,
                policy.get_attribute_id(&Attribute {
                    dimension: "Security Level".to_string(),
                    name: "Protected".to_string(),
                })?,
            ])?);

            coordinates.insert(Partition::from_attribute_ids(vec![
                policy.get_attribute_id(&Attribute {
                    dimension: "Department".to_string(),
                    name: "HR".to_string(),
                })?,
                policy.get_attribute_id(&Attribute {
                    dimension: "Security Level".to_string(),
                    name: "Low Secret".to_string(),
                })?,
            ])?);

            coordinates.insert(Partition::from_attribute_ids(vec![
                policy.get_attribute_id(&Attribute {
                    dimension: "Department".to_string(),
                    name: "FIN".to_string(),
                })?,
                policy.get_attribute_id(&Attribute {
                    dimension: "Security Level".to_string(),
                    name: "Protected".to_string(),
                })?,
            ])?);

            coordinates.insert(Partition::from_attribute_ids(vec![
                policy.get_attribute_id(&Attribute {
                    dimension: "Department".to_string(),
                    name: "FIN".to_string(),
                })?,
                policy.get_attribute_id(&Attribute {
                    dimension: "Security Level".to_string(),
                    name: "Low Secret".to_string(),
                })?,
            ])?);
            assert_eq!(semantic_space_coordinates, coordinates);
        }

        // Check the number of coordinates generated by some other access policies.
        {
            let ap = "(Department::FIN && Security Level::Low Secret) \
                || (Department::MKG && Security Level::Low Secret)";

            assert_eq!(
                policy
                    .generate_semantic_space_coordinates(AccessPolicy::from_boolean_expression(
                        ap
                    )?)?
                    .len(),
                // remove (2 + 1) not to count "Security Level::Protected" -> "Security Level::Low Secret" twice
                2 * (1 + 1) * (2 + 1) - (2 + 1)
            );

            let ap = "(Department::FIN && Security Level::Low Secret) \
                || (Department::MKG && Security Level::Medium Secret)";
            assert_eq!(
                policy
                    .generate_semantic_space_coordinates(AccessPolicy::from_boolean_expression(
                        ap
                    )?)?
                    .len(),
                // remove (2 + 1) not to count "Security Level::Protected" -> "Security Level::Low Secret" twice
                (1 + 1) * (2 + 1) + (1 + 1) * (3 + 1) - (2 + 1)
            );
        }
        Ok(())
    }
}
