use crate::{
    Error,
    abe::policy::{
        AccessPolicy, Attribute, Dimension, EncryptionStatus,
        QualifiedAttribute, Right, Version, attribute::HybridizationStatus,
    },
    data_struct::Dict,
};
use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccessStructure {
    version: Version,
    // Use a map to efficiently find dimensions by name.
    dimensions: BTreeMap<String, Dimension>,
}

impl AccessStructure {
    pub fn new() -> Self {
        Self {
            version: Version::V1,
            dimensions: BTreeMap::new(),
        }
    }

    /// Generate the set of USK rights described by the given access policy.
    pub fn ap_to_usk_rights(
        &self,
        ap: &AccessPolicy,
    ) -> Result<BTreeSet<Right>, Error> {
        self.generate_extended_rights(ap)
    }

    /// Generate the set of ciphertext rights described by the given access policy.
    pub fn ap_to_enc_rights(
        &self,
        ap: &AccessPolicy,
    ) -> Result<BTreeSet<Right>, Error> {
        self.generate_restricted_rights(ap)
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
            Entry::Occupied(e) => {
                Err(Error::ExistingDimension(e.key().to_string()))
            }
            Entry::Vacant(e) => {
                e.insert(Dimension::Anarchy(BTreeMap::new()));
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
            Entry::Occupied(e) => {
                Err(Error::ExistingDimension(e.key().to_string()))
            }
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
        security_mode: HybridizationStatus,
        after: Option<&str>,
    ) -> Result<(), Error> {
        let cnt = self
            .dimensions
            .values()
            .map(Dimension::nb_attributes)
            .sum::<usize>();

        self.dimensions
            .get_mut(&attribute.dimension)
            .ok_or_else(|| {
                Error::DimensionNotFound(attribute.dimension.clone())
            })?
            .add_attribute(attribute.attribute, security_mode, after, cnt)?;

        Ok(())
    }

    /// Remove the given qualified attribute from the access structure.
    ///
    /// Requires USK refresh
    /// ====================
    /// Only refreshed keys loose the ability to decrypt for an access policy belonging to the
    /// semantic space of this attribute.
    pub fn del_attribute(
        &mut self,
        attr: &QualifiedAttribute,
    ) -> Result<(), Error> {
        if let Some(dim) = self.dimensions.get_mut(&attr.dimension) {
            dim.remove_attribute(&attr.attribute)
        } else {
            Err(Error::DimensionNotFound(attr.dimension.to_string()))
        }
    }

    /// Changes the name of an attribute.
    pub fn rename_attribute(
        &mut self,
        attribute: &QualifiedAttribute,
        new_name: String,
    ) -> Result<(), Error> {
        match self.dimensions.get_mut(&attribute.dimension) {
            Some(d) => d.rename_attribute(&attribute.attribute, new_name),
            None => {
                Err(Error::DimensionNotFound(attribute.dimension.to_string()))
            }
        }
    }

    pub fn dimensions(&self) -> impl Iterator<Item = &str> {
        self.dimensions.keys().map(|d| d.as_str())
    }

    pub fn attributes(
        &'_ self,
    ) -> impl '_ + Iterator<Item = QualifiedAttribute> {
        self.dimensions.iter().flat_map(|(dimension, d)| {
            d.get_attributes_name().map(move |name| {
                QualifiedAttribute::new(dimension, name.as_str())
            })
        })
    }

    /// Marks an attribute as read only.
    /// The corresponding attribute key will be removed from the public key.
    /// But the decryption key will be kept to allow reading old ciphertext.
    pub fn disable_attribute(
        &mut self,
        attr: &QualifiedAttribute,
    ) -> Result<(), Error> {
        match self.dimensions.get_mut(&attr.dimension) {
            Some(d) => d.disable_attribute(&attr.attribute),
            None => Err(Error::DimensionNotFound(attr.dimension.to_string())),
        }
    }

    /// Generates all rights defined by this access structure and return their
    /// hybridization and activation status.
    pub(crate) fn omega(
        &self,
    ) -> Result<BTreeMap<Right, (HybridizationStatus, EncryptionStatus)>, Error>
    {
        let universe = self.dimensions.iter().collect::<Vec<_>>();
        combine(universe.into_iter().map(|(_, dimension)| dimension))
            .into_iter()
            .map(|(ids, mode, status)| {
                Right::from_point(ids).map(|r| (r, (mode, status)))
            })
            .collect()
    }

    /// Returns the given attribute from the access structure.
    /// Fails if there is no such attribute.
    fn get_attribute(
        &self,
        attr: &QualifiedAttribute,
    ) -> Result<Option<&Attribute>, Error> {
        if let Some(dim) = self.dimensions.get(&attr.dimension) {
            dim.get_attribute(&attr.attribute)
        } else {
            Err(Error::DimensionNotFound(attr.dimension.to_string()))
        }
    }

    /// Retrieves the ID of an attribute.
    #[cfg(test)]
    fn get_attribute_id(
        &self,
        attribute: &QualifiedAttribute,
    ) -> Result<usize, Error> {
        self.get_attribute(attribute)?.map(Attribute::get_id).ok_or(
            Error::InvalidAttribute(
                "broadcast attribute hash no ID".to_owned(),
            ),
        )
    }

    /// Extend each attribute of the given clause with the lower attributes of
    /// its dimension or with the entire dimension in case of the broadcast
    /// attribute.
    fn extend_clause(
        &self,
        clause: &[QualifiedAttribute],
    ) -> Result<Vec<Dimension>, Error> {
        clause
            .iter()
            .map(|qa| {
                self.dimensions
                    .get(&qa.dimension)
                    .ok_or_else(|| {
                        Error::DimensionNotFound(qa.dimension.clone())
                    })
                    .and_then(|d| d.restrict(qa.attribute.to_string()))
            })
            .collect()
    }

    /// Returns the rights associated to the given access policy when extended
    /// each attribute of each clause to its lower attributes or the entire
    /// dimension in the case of the broadcast attribute.
    fn generate_extended_rights(
        &self,
        ap: &AccessPolicy,
    ) -> Result<BTreeSet<Right>, Error> {
        ap.to_dnf()
            .iter()
            .map(|clause| {
                self.extend_clause(clause).map(|extended_attribute| {
                    combine(extended_attribute.iter())
                })
            })
            .try_fold(BTreeSet::new(), |s, points| {
                points?.into_iter().try_fold(s, |mut s, (point, _, _)| {
                    s.insert(Right::from_point(point)?);
                    Ok(s)
                })
            })
    }

    /// Returns the rights of the points defined by the given access policy.
    ///
    /// Each conjunction of the associated DNF defines a unique right.
    /// Mentioning the broadcast attribute is equivalent to leaving it
    /// unmentioned.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is invalid.
    fn generate_restricted_rights(
        &self,
        ap: &AccessPolicy,
    ) -> Result<BTreeSet<Right>, Error> {
        ap.to_dnf().into_iter().try_fold(
            BTreeSet::new(),
            |mut rights, clause| {
                let point = clause
                    .into_iter()
                    .filter_map(|attr| {
                        self.get_attribute(&attr)
                            .map(|attribute| attribute.map(Attribute::get_id))
                            .transpose()
                    })
                    .collect::<Result<_, _>>()?;
                rights.insert(Right::from_point(point)?);
                Ok(rights)
            },
        )
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
fn combine<'a>(
    mut dimensions: impl Iterator<Item = &'a Dimension>,
) -> Vec<(Vec<usize>, HybridizationStatus, EncryptionStatus)> {
    if let Some(current_dimension) = dimensions.next() {
        let partial_combinations = combine(dimensions);
        let mut res = vec![];
        for component in current_dimension.attributes() {
            for (ids, security_mode, encryption_status) in
                partial_combinations.clone()
            {
                res.push((
                    [vec![component.get_id()], ids].concat(),
                    security_mode.max(component.get_security_mode()),
                    encryption_status | component.get_encryption_status(),
                ));
            }
        }
        [partial_combinations, res].concat()
    } else {
        vec![(
            vec![],
            HybridizationStatus::Classic,
            EncryptionStatus::EncryptDecrypt,
        )]
    }
}

#[cfg(feature = "test-utils")]
pub fn omega_size(access_structure: &AccessStructure) -> Result<usize, Error> {
    access_structure.omega().map(|o| o.len())
}

impl Default for AccessStructure {
    fn default() -> Self {
        Self {
            version: Version::V1,
            dimensions: BTreeMap::new(),
        }
    }
}

mod serialization {

    use super::*;
    use cosmian_crypto_core::bytes_ser_de::{
        Deserializer, Serializable, Serializer,
    };

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
        use crate::abe::gen_structure;
        use cosmian_crypto_core::bytes_ser_de::test_serialization;

        let mut structure = AccessStructure::new();
        gen_structure(&mut structure, false).unwrap();
        test_serialization(&structure).unwrap();

        let bytes_1 = structure.serialize().unwrap().to_vec();
        let structure_2 = AccessStructure::deserialize(&bytes_1).unwrap();
        let bytes_2 = structure_2.serialize().unwrap().to_vec();
        assert_eq!(bytes_1, bytes_2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abe::gen_structure;

    #[test]
    fn test_combine() {
        let mut structure = AccessStructure::new();
        gen_structure(&mut structure, false).unwrap();

        // There should be `Prod_dim(|dim| + 1)` rights.
        assert_eq!(
            combine(structure.dimensions.values()).len(),
            structure
                .dimensions
                .values()
                .map(|d| d.attributes().count() + 1)
                .product::<usize>()
        );

        structure.add_anarchy("Country".to_string()).unwrap();
        [
            ("France", HybridizationStatus::Classic),
            ("Germany", HybridizationStatus::Classic),
            ("Spain", HybridizationStatus::Classic),
        ]
        .into_iter()
        .try_for_each(|(attribute, mode)| {
            structure.add_attribute(
                QualifiedAttribute::new("Country", attribute),
                mode,
                None,
            )
        })
        .unwrap();

        // There should be `Prod_dim(|dim| + 1)` rights.
        assert_eq!(
            combine(structure.dimensions.values()).len(),
            structure
                .dimensions
                .values()
                .map(|dim| dim.attributes().count() + 1)
                .product::<usize>()
        );
    }

    #[test]
    fn test_extended_rights() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        gen_structure(&mut structure, false).unwrap();

        {
            let ap = "(DPT::HR || DPT::FIN) && SEC::TOP";
            let comp_points = structure
                .generate_extended_rights(&AccessPolicy::parse(ap)?)?;

            // Check the rights are the same as the ones manually generated, i.e.:
            // - rights()
            // - rights(HR, TOP)
            // - rights(HR, LOW)
            // - rights(FIN, TOP)
            // - rights(FIN, LOW)
            let mut rights = BTreeSet::new();

            rights.insert(Right::from_point(vec![])?);

            rights
                .insert(Right::from_point(vec![structure.get_attribute_id(
                    &QualifiedAttribute::new("DPT", "FIN"),
                )?])?);
            rights
                .insert(Right::from_point(vec![structure.get_attribute_id(
                    &QualifiedAttribute::new("DPT", "HR"),
                )?])?);
            rights
                .insert(Right::from_point(vec![structure.get_attribute_id(
                    &QualifiedAttribute::new("SEC", "LOW"),
                )?])?);
            rights
                .insert(Right::from_point(vec![structure.get_attribute_id(
                    &QualifiedAttribute::new("SEC", "MED"),
                )?])?);
            rights
                .insert(Right::from_point(vec![structure.get_attribute_id(
                    &QualifiedAttribute::new("SEC", "TOP"),
                )?])?);

            rights.insert(Right::from_point(vec![
                structure
                    .get_attribute_id(&QualifiedAttribute::new("DPT", "FIN"))?,
                structure
                    .get_attribute_id(&QualifiedAttribute::new("SEC", "LOW"))?,
            ])?);
            rights.insert(Right::from_point(vec![
                structure
                    .get_attribute_id(&QualifiedAttribute::new("DPT", "HR"))?,
                structure
                    .get_attribute_id(&QualifiedAttribute::new("SEC", "LOW"))?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure
                    .get_attribute_id(&QualifiedAttribute::new("DPT", "HR"))?,
                structure
                    .get_attribute_id(&QualifiedAttribute::new("SEC", "MED"))?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure
                    .get_attribute_id(&QualifiedAttribute::new("DPT", "FIN"))?,
                structure
                    .get_attribute_id(&QualifiedAttribute::new("SEC", "MED"))?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure
                    .get_attribute_id(&QualifiedAttribute::new("DPT", "HR"))?,
                structure
                    .get_attribute_id(&QualifiedAttribute::new("SEC", "TOP"))?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure
                    .get_attribute_id(&QualifiedAttribute::new("DPT", "FIN"))?,
                structure
                    .get_attribute_id(&QualifiedAttribute::new("SEC", "TOP"))?,
            ])?);

            assert_eq!(comp_points, rights);
        }

        // Check the number of rights generated by some other access policies.
        {
            let ap = "DPT::HR";
            assert_eq!(
                structure
                    .generate_extended_rights(&AccessPolicy::parse(ap)?)?
                    .len(),
                // Since the security dimension is hierarchical, the restricted
                // space is the empty space. There is only one projection of
                // DPT::HR, which is the universal broadcast. The complementary
                // space is generated by extending these two points with the
                // restricted space.
                2
            );

            let ap = "DPT::* && SEC::LOW";
            assert_eq!(
                structure
                    .generate_extended_rights(&AccessPolicy::parse(ap)?)?
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
