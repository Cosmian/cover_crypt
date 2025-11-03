use std::collections::{hash_map::Entry, HashMap, HashSet};

use crate::{
    abe_policy::{
        attribute::SecurityMode, AccessPolicy, Attribute, Dimension, EncryptionStatus,
        QualifiedAttribute, Right, Version,
    },
    data_struct::Dict,
    Error,
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccessStructure {
    version: Version,
    // Use a hash-map to efficiently find dimensions by name.
    dimensions: HashMap<String, Dimension>,
}

impl AccessStructure {
    pub fn new() -> Self {
        Self {
            version: Version::V1,
            dimensions: HashMap::new(),
        }
    }

    /// Generate the set of USK rights described by the given access policy.
    pub fn ap_to_usk_rights(&self, ap: &AccessPolicy) -> Result<HashSet<Right>, Error> {
        self.generate_complementary_rights(ap)
    }

    /// Generate the set of ciphertext rights described by the given access policy.
    pub fn ap_to_enc_rights(&self, ap: &AccessPolicy) -> Result<HashSet<Right>, Error> {
        self.generate_associated_rights(ap)
    }

    /// Add an anarchic dimension with the given name to the access structure.
    ///
    /// Requires USK refresh
    /// ====================
    ///
    /// Only refreshed keys can decrypt for an access policy belonging to the
    /// semantic space of the new dimension.
    pub fn add_anarchy(&mut self, dimension: String) -> Result<(), Error> {
        match self.dimensions.entry(dimension) {
            Entry::Occupied(e) => Err(Error::ExistingDimension(e.key().to_string())),
            Entry::Vacant(e) => {
                e.insert(Dimension::Anarchy(HashMap::new()));
                Ok(())
            }
        }
    }

    /// Add a hierarchic dimension with the given name to the access structure.
    ///
    /// Requires USK refresh
    /// ====================
    ///
    /// Only refreshed keys can decrypt for an access policy belonging to the
    /// semantic space of the new dimension.
    pub fn add_hierarchy(&mut self, dimension: String) -> Result<(), Error> {
        match self.dimensions.entry(dimension) {
            Entry::Occupied(e) => Err(Error::ExistingDimension(e.key().to_string())),
            Entry::Vacant(e) => {
                e.insert(Dimension::Hierarchy(Dict::new()));
                Ok(())
            }
        }
    }

    /// Removes the given dim from the access structure.
    ///
    /// Requires USK refresh
    /// ====================
    ///
    /// Refreshed keys loose the ability to decrypt for an access policy
    /// belonging to the semantic space of the removed dimension.
    pub fn del_dimension(&mut self, dimension: &str) -> Result<(), Error> {
        self.dimensions
            .remove(dimension)
            .map(|_| ())
            .ok_or(Error::DimensionNotFound(dimension.to_string()))
    }

    /// Add the given qualified attribute to the access structure.
    ///
    /// If the dimension if hierarchical, specifying `after` will set the rank
    /// of the new attribute to be in-between the existing attribute which name
    /// is given as `after`, and before the attribute directly higher that
    /// `after`. Gives the new attribute the lowest rank in case no `after`
    /// attribute is specified.
    ///
    /// If `after` does not match any valid attribute, an error is
    /// returned. Specifying `after` when adding a new attribute to an anarchy
    /// has no effect.
    ///
    /// Requires USK refresh
    /// ====================
    ///
    /// Only refreshed keys will be able to decrypt for an associated access
    /// policy belonging to the semantic space of the new attribute.
    pub fn add_attribute(
        &mut self,
        attribute: QualifiedAttribute,
        security_mode: SecurityMode,
        after: Option<&str>,
    ) -> Result<(), Error> {
        let cnt = self
            .dimensions
            .values()
            .map(Dimension::nb_attributes)
            .sum::<usize>();

        self.dimensions
            .get_mut(&attribute.dimension)
            .ok_or_else(|| Error::DimensionNotFound(attribute.dimension.clone()))?
            .add_attribute(attribute.name, security_mode, after, cnt)?;

        Ok(())
    }

    /// Remove the given qualified attribute from the access structure.
    ///
    /// Requires USK refresh
    /// ====================
    /// Only refreshed keys loose the ability to decrypt for an access policy belonging to the
    /// semantic space of this attribute.
    pub fn del_attribute(&mut self, attr: &QualifiedAttribute) -> Result<(), Error> {
        if let Some(dim) = self.dimensions.get_mut(&attr.dimension) {
            dim.remove_attribute(&attr.name)
        } else {
            Err(Error::DimensionNotFound(attr.dimension.to_string()))
        }
    }
}

impl AccessStructure {
    /// Changes the name of an attribute.
    pub fn rename_attribute(
        &mut self,
        attribute: &QualifiedAttribute,
        new_name: String,
    ) -> Result<(), Error> {
        match self.dimensions.get_mut(&attribute.dimension) {
            Some(d) => d.rename_attribute(&attribute.name, new_name),
            None => Err(Error::DimensionNotFound(attribute.dimension.to_string())),
        }
    }

    pub fn dimensions(&self) -> impl Iterator<Item = &str> {
        self.dimensions.keys().map(|d| d.as_str())
    }

    pub fn attributes(&'_ self) -> impl '_ + Iterator<Item = QualifiedAttribute> {
        self.dimensions.iter().flat_map(|(dimension, d)| {
            d.get_attributes_name()
                .map(move |name| QualifiedAttribute::new(dimension, name.as_str()))
        })
    }

    /// Marks an attribute as read only.
    /// The corresponding attribute key will be removed from the public key.
    /// But the decryption key will be kept to allow reading old ciphertext.
    pub fn disable_attribute(&mut self, attr: &QualifiedAttribute) -> Result<(), Error> {
        match self.dimensions.get_mut(&attr.dimension) {
            Some(d) => d.disable_attribute(&attr.name),
            None => Err(Error::DimensionNotFound(attr.dimension.to_string())),
        }
    }

    /// Generates all rights defined by this access structure and return their
    /// hybridization and activation status.
    pub(crate) fn omega(&self) -> Result<HashMap<Right, (SecurityMode, EncryptionStatus)>, Error> {
        let universe = self.dimensions.iter().collect::<Vec<_>>();
        combine(universe.as_slice())
            .into_iter()
            .map(|(ids, is_hybridized, is_readonly)| {
                Right::from_point(ids).map(|r| (r, (is_hybridized, is_readonly)))
            })
            .collect()
    }
}

impl AccessStructure {
    /// Returns the given attribute from the access structure.
    /// Fails if there is no such attribute.
    fn get_attribute(&self, attr: &QualifiedAttribute) -> Result<&Attribute, Error> {
        if let Some(dim) = self.dimensions.get(&attr.dimension) {
            dim.get_attribute(&attr.name)
                .ok_or(Error::AttributeNotFound(attr.to_string()))
        } else {
            Err(Error::DimensionNotFound(attr.dimension.to_string()))
        }
    }

    /// Retrieves the ID of an attribute.
    #[cfg(test)]
    fn get_attribute_id(&self, attribute: &QualifiedAttribute) -> Result<usize, Error> {
        self.get_attribute(attribute).map(Attribute::get_id)
    }

    /// Generates the restriction of the semantic space of the given clause to
    /// the rights of lower rank than its associated right.
    ///
    /// The semantic space is define as the smallest subspace of the universe in
    /// which the given clause can be expressed.
    ///
    /// # Error
    ///
    /// Returns an error if the clause is invalid.
    fn generate_semantic_space(
        &self,
        clause: &[QualifiedAttribute],
    ) -> Result<HashMap<String, Dimension>, Error> {
        clause
            .iter()
            .map(|qa| {
                self.dimensions
                    .get(&qa.dimension)
                    .ok_or_else(|| Error::DimensionNotFound(qa.dimension.clone()))
                    .and_then(|d| d.restrict(qa.name.to_string()))
                    .map(|d| (qa.dimension.clone(), d))
            })
            .collect()
    }

    /// Returns the points in the complementary space of the given clause.
    ///
    /// The complementary space of a clause is generated by extending each of
    /// its semantic projections and hierarchical extensions with the
    /// complementary in Omega of its semantic space.
    fn generate_complementary_points(
        &self,
        clause: &[QualifiedAttribute],
    ) -> Result<Vec<Vec<usize>>, Error> {
        // The goal is to compute Ω_r = Ω - sem_Ω(r) + {P: P <= P_r}.

        // Compute sem_Ω(r), the semantic space of the right in Omega.
        let semantic_space = self.generate_semantic_space(clause)?;

        let semantic_points = combine(semantic_space.iter().collect::<Vec<_>>().as_slice())
            .into_iter()
            .map(|(ids, _, _)| ids)
            .collect::<Vec<_>>();

        // The restricted space is Ω\π_c(Ω).
        let restricted_space = self
            .dimensions
            .iter()
            .filter(|(name, _)| !semantic_space.contains_key(*name))
            .collect::<Vec<_>>();

        // Now generate the complementary space by combining the
        let complementary_points = combine(&restricted_space)
            .into_iter()
            .flat_map(|(prefix, _, _)| {
                semantic_points.iter().map(move |suffix| {
                    let mut prefix = prefix.clone();
                    prefix.append(&mut suffix.clone());
                    prefix
                })
            })
            .collect::<Vec<_>>();

        Ok(complementary_points)
    }

    /// Returns the rights in the complementary space of the given access policy.
    fn generate_complementary_rights(&self, ap: &AccessPolicy) -> Result<HashSet<Right>, Error> {
        // The complementary space of an access policy is the union of the
        // complementary spaces generated by each clause of the DNF of this
        // access policy.
        let points = ap
            .to_dnf()
            .iter()
            .map(|qas| self.generate_complementary_points(qas))
            .try_fold(HashSet::new(), |mut acc, ids| {
                ids?.into_iter().for_each(|ids| {
                    acc.insert(ids);
                });
                Ok::<HashSet<Vec<usize>>, Error>(acc)
            })?;

        points.into_iter().map(Right::from_point).collect()
    }

    /// Returns the rights of the points defined by the given access policy.
    ///
    /// Each conjunction of the associated DNF defines a unique right.
    ///
    /// # Error
    /// Returns an error if the access policy is invalid.
    fn generate_associated_rights(&self, ap: &AccessPolicy) -> Result<HashSet<Right>, Error> {
        let dnf = ap.to_dnf();
        let len = dnf.len();
        dnf.into_iter()
            .try_fold(HashSet::with_capacity(len), |mut rights, conjunction| {
                let r = Right::from_point(
                    conjunction
                        .into_iter()
                        .map(|attr| self.get_attribute(&attr).map(|params| params.id))
                        .collect::<Result<_, _>>()?,
                )?;
                rights.insert(r);
                Ok(rights)
            })
    }
}

/// Combines all attributes IDs from the given dimensions using at most one
/// attribute for each dimensions. Returns the disjunction of the associated
/// hybridization and activation status.
///
/// As an example, if dimensions D1::A1 and D2::(A2,B2) are given, the following
/// combinations will be created:
/// - D1::A1
/// - D1::A1 && D2::A2
/// - D1::A1 && D2::B2
/// - D2::A2
/// - D2::B2
fn combine(
    dimensions: &[(&String, &Dimension)],
) -> Vec<(Vec<usize>, SecurityMode, EncryptionStatus)> {
    if dimensions.is_empty() {
        vec![(
            vec![],
            SecurityMode::Classic,
            EncryptionStatus::EncryptDecrypt,
        )]
    } else {
        let (_, current_dimension) = &dimensions[0];
        let partial_combinations = combine(&dimensions[1..]);
        let mut res = vec![];
        for component in current_dimension.attributes() {
            for (ids, security_mode, is_activated) in partial_combinations.clone() {
                res.push((
                    [vec![component.get_id()], ids].concat(),
                    security_mode.max(component.get_security_mode()),
                    is_activated | component.get_encryption_status(),
                ));
            }
        }
        [partial_combinations, res].concat()
    }
}

impl Default for AccessStructure {
    fn default() -> Self {
        Self {
            version: Version::V1,
            dimensions: HashMap::new(),
        }
    }
}

mod serialization {

    use super::*;
    use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable, Serializer};

    impl Serializable for AccessStructure {
        type Error = Error;

        fn length(&self) -> usize {
            self.version.length() + self.dimensions.length()
        }

        fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
            Ok(self.version.write(ser)? + self.dimensions.write(ser)?)
        }

        fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
            Ok(Self {
                version: de.read()?,
                dimensions: de.read()?,
            })
        }
    }

    #[test]
    fn test_access_structure_serialization() {
        use crate::abe_policy::gen_structure;
        use cosmian_crypto_core::bytes_ser_de::test_serialization;

        let mut structure = AccessStructure::new();
        gen_structure(&mut structure, false).unwrap();
        test_serialization(&structure).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abe_policy::gen_structure;

    #[test]
    fn test_combine() {
        let mut structure = AccessStructure::new();
        gen_structure(&mut structure, false).unwrap();

        // There should be `Prod_dim(|dim| + 1)` rights.
        assert_eq!(
            combine(&structure.dimensions.iter().collect::<Vec<_>>()).len(),
            structure
                .dimensions
                .values()
                .map(|d| d.attributes().count() + 1)
                .product::<usize>()
        );

        structure.add_anarchy("Country".to_string()).unwrap();
        [
            ("France", SecurityMode::Classic),
            ("Germany", SecurityMode::Classic),
            ("Spain", SecurityMode::Classic),
        ]
        .into_iter()
        .try_for_each(|(attribute, hint)| {
            structure.add_attribute(QualifiedAttribute::new("Country", attribute), hint, None)
        })
        .unwrap();

        // There should be `Prod_dim(|dim| + 1)` rights.
        assert_eq!(
            combine(&structure.dimensions.iter().collect::<Vec<_>>()).len(),
            structure
                .dimensions
                .values()
                .map(|dim| dim.attributes().count() + 1)
                .product::<usize>()
        );
    }

    #[test]
    fn test_generate_complementary_rights() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        gen_structure(&mut structure, false).unwrap();

        {
            let ap = "(DPT::HR || DPT::FIN) && SEC::TOP";
            let comp_points = structure.generate_complementary_rights(&AccessPolicy::parse(ap)?)?;

            // Check the rights are the same as the ones manually generated, i.e.:
            // - rights()
            // - rights(HR, TOP)
            // - rights(HR, LOW)
            // - rights(FIN, TOP)
            // - rights(FIN, LOW)
            let mut rights = HashSet::new();

            rights.insert(Right::from_point(vec![])?);

            rights.insert(Right::from_point(vec![structure.get_attribute_id(
                &QualifiedAttribute {
                    dimension: "DPT".to_string(),
                    name: "FIN".to_string(),
                },
            )?])?);
            rights.insert(Right::from_point(vec![structure.get_attribute_id(
                &QualifiedAttribute {
                    dimension: "DPT".to_string(),
                    name: "HR".to_string(),
                },
            )?])?);
            rights.insert(Right::from_point(vec![structure.get_attribute_id(
                &QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "LOW".to_string(),
                },
            )?])?);
            rights.insert(Right::from_point(vec![structure.get_attribute_id(
                &QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "MED".to_string(),
                },
            )?])?);
            rights.insert(Right::from_point(vec![structure.get_attribute_id(
                &QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "TOP".to_string(),
                },
            )?])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "DPT".to_string(),
                    name: "FIN".to_string(),
                })?,
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "LOW".to_string(),
                })?,
            ])?);
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "DPT".to_string(),
                    name: "HR".to_string(),
                })?,
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "LOW".to_string(),
                })?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "DPT".to_string(),
                    name: "HR".to_string(),
                })?,
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "MED".to_string(),
                })?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "DPT".to_string(),
                    name: "FIN".to_string(),
                })?,
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "MED".to_string(),
                })?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "DPT".to_string(),
                    name: "HR".to_string(),
                })?,
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "TOP".to_string(),
                })?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "DPT".to_string(),
                    name: "FIN".to_string(),
                })?,
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "TOP".to_string(),
                })?,
            ])?);

            assert_eq!(comp_points, rights);
        }

        // Check the number of rights generated by some other access policies.
        {
            let ap = "DPT::HR";
            assert_eq!(
                structure
                    .generate_complementary_rights(&AccessPolicy::parse(ap)?)?
                    .len(),
                // There are 3 rights in the security dimension, plus the
                // broadcast for this dimension. This is the restricted
                // space. There is only one projection of DPT::HR, which is the
                // universal broadcast. The complementary space is generated by
                // extending these two points with the restricted space.
                2 * (1 + 3)
            );

            let ap = "SEC::LOW";
            assert_eq!(
                structure
                    .generate_complementary_rights(&AccessPolicy::parse(ap)?)?
                    .len(),
                // The restricted space is the department dimension, and the
                // lower points are the associated point, the point associated
                // to "SEC::LOW" and the universal broadcast.
                2 * (1 + 5)
            );
        }
        Ok(())
    }
}
