use std::collections::{hash_map::Entry, HashMap, HashSet};

use cosmian_crypto_core::bytes_ser_de::{to_leb128_len, Serializable};

use crate::{
    abe_policy::{
        AccessPolicy, AttributeParameters, AttributeStatus, Coordinate, Dimension, EncryptionHint,
        QualifiedAttribute,
    },
    data_struct::Dict,
    Error,
};

use super::PolicyVersion;

#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct PolicyV3 {
    version: PolicyVersion,
    // Use a hash-map to efficiently find dimensions by name.
    dimensions: HashMap<String, Dimension>,
}

impl PolicyV3 {
    /// Generate the set of USK rights described by the given access policy.
    pub fn ap_to_usk_rights(&self, ap: &AccessPolicy) -> Result<HashSet<Coordinate>, Error> {
        self.generate_complementary_coordinates(ap)
    }

    /// Generate the set of ciphertext rights described by the given access policy.
    pub fn ap_to_enc_rights(&self, ap: &AccessPolicy) -> Result<HashSet<Coordinate>, Error> {
        self.generate_point_coordinates(ap)
    }

    /// Add an anarchic dimension with the given name to the policy.
    ///
    /// Requires USK refresh
    /// ====================
    /// Only refreshed keys can decrypt for an access policy belonging to the semantic space of the
    /// new dimension.
    pub fn add_anarchy(&mut self, dimension: String) -> Result<(), Error> {
        match self.dimensions.entry(dimension) {
            Entry::Occupied(e) => Err(Error::ExistingDimension(e.key().to_string())),
            Entry::Vacant(e) => {
                e.insert(Dimension::Unordered(HashMap::new()));
                Ok(())
            }
        }
    }

    /// Add a hierarchic dimension with the given name to the policy.
    ///
    /// Requires USK refresh
    /// ====================
    /// Only refreshed keys can decrypt for an access policy belonging to the semantic space of the
    /// new dimension.
    pub fn add_hierarchy(&mut self, dimension: String) -> Result<(), Error> {
        match self.dimensions.entry(dimension) {
            Entry::Occupied(e) => Err(Error::ExistingDimension(e.key().to_string())),
            Entry::Vacant(e) => {
                e.insert(Dimension::Ordered(Dict::new()));
                Ok(())
            }
        }
    }

    /// Removes the given dim from the policy.
    ///
    /// Requires USK refresh
    /// ====================
    /// Refreshed keys loose the ability to decrypt for an access policy belonging to the semantic
    /// space of the removed dimension.
    pub fn del_dimension(&mut self, dimension: &str) -> Result<(), Error> {
        self.dimensions
            .remove(dimension)
            .map(|_| ())
            .ok_or(Error::DimensionNotFound(dimension.to_string()))
    }

    /// Add the given qualified attribute to the policy.
    ///
    /// If the dimension if hierarchical, specifying `after` will set the rank of the new attribute
    /// to be in-between the existing attribute which name is given as `after`, and before the
    /// attribute directly higher that `after`. Gives the new attribute the lowest rank in case no
    /// `after` attribute is specified.
    ///
    /// If `after` does not match any valid attribute, an error is returned. Specifying `after`
    /// when adding a new attribute to an anarchy has no effect.
    ///
    /// Requires USK refresh
    /// ====================
    /// Only refreshed keys will be able to decrypt for an associated access policy belonging to
    /// the semantic space of the new attribute.
    pub fn add_attribute(
        &mut self,
        attribute: QualifiedAttribute,
        encryption_hint: EncryptionHint,
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
            .add_attribute(attribute.name, encryption_hint, after, cnt)?;

        Ok(())
    }

    /// Remove the given qualified attribute from the policy.
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

impl PolicyV3 {
    /// Changes the name of an attribute.
    pub fn rename_attribute(
        &mut self,
        attr: &QualifiedAttribute,
        new_name: String,
    ) -> Result<(), Error> {
        match self.dimensions.get_mut(&attr.dimension) {
            Some(policy_dim) => policy_dim.rename_attribute(&attr.name, new_name),
            None => Err(Error::DimensionNotFound(attr.dimension.to_string())),
        }
    }

    pub fn attributes(&'_ self) -> impl '_ + Iterator<Item = QualifiedAttribute> {
        self.dimensions.iter().flat_map(|(dimension, d)| {
            d.get_attributes_name()
                .map(move |name| QualifiedAttribute::new(dimension, name.as_str()))
        })
    }

    pub fn dimensions(&self) -> impl Iterator<Item = &str> {
        self.dimensions.keys().map(|d| d.as_str())
    }

    /// Marks an attribute as read only.
    /// The corresponding attribute key will be removed from the public key.
    /// But the decryption key will be kept to allow reading old ciphertext.
    pub fn disable_attribute(&mut self, attr: &QualifiedAttribute) -> Result<(), Error> {
        match self.dimensions.get_mut(&attr.dimension) {
            Some(policy_dim) => policy_dim.disable_attribute(&attr.name),
            None => Err(Error::DimensionNotFound(attr.dimension.to_string())),
        }
    }

    /// Generates all coordinates defined by this policy and return their hybridization and
    /// activation status.
    pub fn generate_universal_coordinates(
        &self,
    ) -> Result<HashMap<Coordinate, (EncryptionHint, AttributeStatus)>, Error> {
        let universe = self.dimensions.iter().collect::<Vec<_>>();
        combine(universe.as_slice())
            .into_iter()
            .map(|(combination, is_hybridized, is_readonly)| {
                Coordinate::from_attribute_ids(combination)
                    .map(|coordinate| (coordinate, (is_hybridized, is_readonly)))
            })
            .collect()
    }
}

impl PolicyV3 {
    /// Returns the given attribute from the policy.
    /// Fails if there is no such attribute.
    fn get_attribute(&self, attr: &QualifiedAttribute) -> Result<&AttributeParameters, Error> {
        if let Some(dim) = self.dimensions.get(&attr.dimension) {
            dim.get_attribute(&attr.name)
                .ok_or(Error::AttributeNotFound(attr.to_string()))
        } else {
            Err(Error::DimensionNotFound(attr.dimension.to_string()))
        }
    }

    #[cfg(test)]
    /// Retrieves the ID of an attribute.
    fn get_attribute_id(&self, attribute: &QualifiedAttribute) -> Result<usize, Error> {
        self.get_attribute(attribute)
            .map(AttributeParameters::get_id)
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
    fn generate_semantic_space(
        &self,
        conj: &[QualifiedAttribute],
    ) -> Result<HashMap<String, Dimension>, Error> {
        conj.iter()
            .map(|qa| {
                self.dimensions
                    .get(&qa.dimension)
                    .ok_or_else(|| Error::DimensionNotFound(qa.dimension.clone()))
                    .and_then(|d| d.restrict(qa.name.to_string()))
                    .map(|d| (qa.dimension.clone(), d))
            })
            .collect()
    }

    /// Extend the given conjunction with lower-ranked ones with respect to the order defined by
    /// hierarchical dimensions.
    fn cascade(&self, conj: &[QualifiedAttribute]) -> Vec<Vec<QualifiedAttribute>> {
        conj.iter()
            .enumerate()
            .flat_map(|(i, qa)| {
                self.dimensions
                    .get(&qa.dimension)
                    .map(|d| {
                        if d.is_ordered() {
                            d.get_attributes_name()
                                .take_while(|name| *name != &qa.name)
                                .map(String::to_string)
                                .map(|name| QualifiedAttribute {
                                    dimension: qa.dimension.clone(),
                                    name,
                                })
                                .map(|qa| (i, qa))
                                .collect()
                        } else {
                            vec![]
                        }
                    })
                    .unwrap_or_default()
            })
            .fold(
                vec![conj.to_vec()],
                |mut acc: Vec<Vec<QualifiedAttribute>>, (i, qa): (usize, QualifiedAttribute)| {
                    let mut new_conj = conj.to_vec();
                    new_conj[i] = qa;
                    acc.push(new_conj);
                    acc
                },
            )
    }

    /// Returns the complementary points of the given conjugate point, following hierarchies when
    /// needed.
    fn generate_complementary_points(
        &self,
        clause: &[QualifiedAttribute],
    ) -> Result<Vec<Vec<usize>>, Error> {
        // The goal is to compute Ω_c = Ω\π_c(Ω) + P_c.

        // Compute π_c, the semantic space of the clause.
        let semantic_space = self.generate_semantic_space(clause)?;

        // The restricted space is Ω\π_c(Ω).
        let restricted_space = self
            .dimensions
            .iter()
            .filter(|(name, _)| !semantic_space.contains_key(*name))
            .collect::<Vec<_>>();

        // Compute P_c.
        let clause_points = self
            .cascade(clause)
            .iter()
            .map(|conj| {
                conj.iter()
                    .map(|qa| self.get_attribute(qa).map(|a| a.id))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<Vec<_>>, _>>()?;

        // Now generate the complementary space by combining the
        let mut complementary_points = combine(&restricted_space)
            .into_iter()
            .flat_map(|(prefix, _, _)| {
                clause_points.iter().map(move |suffix| {
                    let mut prefix = prefix.clone();
                    prefix.append(&mut suffix.clone());
                    prefix
                })
            })
            .collect::<Vec<_>>();

        let mut semantic_points = combine(semantic_space.iter().collect::<Vec<_>>().as_slice())
            .into_iter()
            .map(|(ids, _, _)| ids)
            .collect::<Vec<_>>();

        semantic_points.append(&mut complementary_points);

        Ok(semantic_points)
    }

    fn generate_complementary_coordinates(
        &self,
        ap: &AccessPolicy,
    ) -> Result<HashSet<Coordinate>, Error> {
        let ids = ap
            .to_dnf()
            .iter()
            .map(|qas| self.generate_complementary_points(qas))
            .try_fold(vec![vec![]], |mut acc, ids| {
                // Initialize fold with the empty vector to symbolize the universal broadcast.
                acc.append(&mut ids?);
                Ok::<_, Error>(acc)
            })?;

        ids.into_iter()
            .map(Coordinate::from_attribute_ids)
            .collect()
    }

    /// Returns the coordinates of the points defined by the given access policy.
    ///
    /// Each conjunction of the associated DNF defines a unique point.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is invalid.
    fn generate_point_coordinates(&self, ap: &AccessPolicy) -> Result<HashSet<Coordinate>, Error> {
        let dnf = ap.to_dnf();
        let mut coordinates = HashSet::with_capacity(dnf.len());
        for conjunction in dnf {
            let coo = Coordinate::from_attribute_ids(
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

impl Serializable for PolicyV3 {
    type Error = Error;

    fn length(&self) -> usize {
        1 + to_leb128_len(self.dimensions.len())
            + self
                .dimensions
                .iter()
                .map(|(name, dimension)| {
                    let l = name.len();
                    to_leb128_len(l) + l + dimension.length()
                })
                .sum::<usize>()
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        let mut n = ser.write_leb128_u64(self.version as u64)?;
        n += ser.write_leb128_u64(self.dimensions.len() as u64)?;
        self.dimensions.iter().try_for_each(|(name, attributes)| {
            n += ser.write_vec(name.as_bytes())?;
            n += ser.write_leb128_u64(attributes.nb_attributes() as u64)?;
            attributes.attributes().try_for_each(|a| {
                n += ser.write(a)?;
                Ok::<_, Self::Error>(())
            })?;
            Ok::<_, Self::Error>(())
        })?;
        Ok(n)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let version = de.read_leb128_u64()?;
        let dimensions = if version == PolicyVersion::V3 as u64 {
            (0..de.read_leb128_u64()?)
                .map(|_| {
                    let name = String::from_utf8(de.read_vec()?)
                        .map_err(|e| Error::ConversionFailed(e.to_string()))?;
                    let dimension = de.read::<Dimension>()?;
                    Ok((name, dimension))
                })
                .collect::<Result<HashMap<_, _>, Error>>()
        } else {
            Err(Error::ConversionFailed(
                "unable to deserialize versions prior to V3".to_string(),
            ))
        }?;
        Ok(Self {
            version: PolicyVersion::V3,
            dimensions,
        })
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
fn combine(
    dimensions: &[(&String, &Dimension)],
) -> Vec<(Vec<usize>, EncryptionHint, AttributeStatus)> {
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
    use crate::abe_policy::gen_policy;

    #[test]
    fn test_combine() {
        let mut policy = PolicyV3::default();
        gen_policy(&mut policy).unwrap();

        // There should be `Prod_dim(|dim| + 1)` coordinates.
        assert_eq!(
            combine(&policy.dimensions.iter().collect::<Vec<_>>()).len(),
            policy
                .dimensions
                .values()
                .map(|dim| dim.attributes().count() + 1)
                .product::<usize>()
        );

        policy.add_anarchy("Country".to_string()).unwrap();
        [
            ("France", EncryptionHint::Classic),
            ("Germany", EncryptionHint::Classic),
            ("Spain", EncryptionHint::Classic),
        ]
        .into_iter()
        .try_for_each(|(attribute, hint)| {
            policy.add_attribute(QualifiedAttribute::new("Country", attribute), hint, None)
        })
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
    fn test_generate_complementary_coordinates() -> Result<(), Error> {
        let mut policy = PolicyV3::default();
        gen_policy(&mut policy).unwrap();

        {
            let ap = "(Department::HR || Department::FIN) && Security Level::Low Secret";
            let comp_points =
                policy.generate_complementary_coordinates(&AccessPolicy::parse(ap)?)?;

            //assert_eq!(comp_points.len(), 1 + 4 + 4);

            // Check the coordinates are the same as the ones manually generated, i.e.:
            // - Coordinate()
            // - Coordinate(HR, Protected)
            // - Coordinate(HR, Low Secret)
            // - Coordinate(FIN, Protected)
            // - Coordinate(FIN, Low Secret)
            let mut coordinates = HashSet::new();

            coordinates.insert(Coordinate::from_attribute_ids(vec![])?);

            coordinates.insert(Coordinate::from_attribute_ids(vec![policy
                .get_attribute_id(&QualifiedAttribute {
                    dimension: "Department".to_string(),
                    name: "FIN".to_string(),
                })?])?);
            coordinates.insert(Coordinate::from_attribute_ids(vec![policy
                .get_attribute_id(&QualifiedAttribute {
                    dimension: "Department".to_string(),
                    name: "HR".to_string(),
                })?])?);
            coordinates.insert(Coordinate::from_attribute_ids(vec![policy
                .get_attribute_id(&QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "Protected".to_string(),
                })?])?);
            coordinates.insert(Coordinate::from_attribute_ids(vec![policy
                .get_attribute_id(&QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "Low Secret".to_string(),
                })?])?);

            coordinates.insert(Coordinate::from_attribute_ids(vec![
                policy.get_attribute_id(&QualifiedAttribute {
                    dimension: "Department".to_string(),
                    name: "FIN".to_string(),
                })?,
                policy.get_attribute_id(&QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "Protected".to_string(),
                })?,
            ])?);
            coordinates.insert(Coordinate::from_attribute_ids(vec![
                policy.get_attribute_id(&QualifiedAttribute {
                    dimension: "Department".to_string(),
                    name: "HR".to_string(),
                })?,
                policy.get_attribute_id(&QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "Protected".to_string(),
                })?,
            ])?);

            coordinates.insert(Coordinate::from_attribute_ids(vec![
                policy.get_attribute_id(&QualifiedAttribute {
                    dimension: "Department".to_string(),
                    name: "HR".to_string(),
                })?,
                policy.get_attribute_id(&QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "Low Secret".to_string(),
                })?,
            ])?);

            coordinates.insert(Coordinate::from_attribute_ids(vec![
                policy.get_attribute_id(&QualifiedAttribute {
                    dimension: "Department".to_string(),
                    name: "FIN".to_string(),
                })?,
                policy.get_attribute_id(&QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "Protected".to_string(),
                })?,
            ])?);

            coordinates.insert(Coordinate::from_attribute_ids(vec![
                policy.get_attribute_id(&QualifiedAttribute {
                    dimension: "Department".to_string(),
                    name: "FIN".to_string(),
                })?,
                policy.get_attribute_id(&QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "Low Secret".to_string(),
                })?,
            ])?);
            assert_eq!(comp_points, coordinates);
        }

        // Check the number of coordinates generated by some other access policies.
        {
            let ap = "Department::HR";
            assert_eq!(
                policy
                    .generate_complementary_coordinates(&AccessPolicy::parse(ap)?)?
                    .len(),
                // There are 5 coordinates in the security dimension,
                // plus the two broadcast coordinates (1D and 0D).
                1 + (1 + 5)
            );

            let ap = "Security Level::Protected";
            assert_eq!(
                policy
                    .generate_complementary_coordinates(&AccessPolicy::parse(ap)?)?
                    .len(),
                // There are 4 coordinates in the department dimension,
                // plus the two broadcast coordinates (1D and 0D).
                1 + 1 + 4
            );
        }
        Ok(())
    }
}
