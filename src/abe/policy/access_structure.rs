use crate::{
    Error,
    abe::policy::{
        AccessPolicy, Attribute, Dimension, EncryptionStatus,
        QualifiedAttribute, Right, Version,
        access_policy::{Name, NameRef},
        attribute::HybridizationStatus,
    },
    data_struct::Dict,
};
use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccessStructure {
    version: Version,
    dimensions: BTreeMap<Name, Dimension>,
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
        match self.dimensions.entry(Name::try_from(dimension)?) {
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
        match self.dimensions.entry(Name::try_from(dimension)?) {
            Entry::Occupied(e) => {
                Err(Error::ExistingDimension(e.key().to_string()))
            }
            Entry::Vacant(e) => {
                e.insert(Dimension::Hierarchy(Dict::new()));
                Ok(())
            }
        }
    }

    /// Removes the dimension with the given name from the access structure.
    ///
    /// Requires USK refresh
    /// ====================
    ///
    /// Refreshed keys loose the ability to decrypt for an access policy
    /// belonging to the semantic space of the removed dimension.
    pub fn del_dimension(&mut self, dimension: &str) -> Result<(), Error> {
        self.dimensions
            .remove(&*NameRef::try_from(dimension)?)
            .map(|_| ())
            .ok_or(Error::DimensionNotFound(dimension.to_string()))
    }

    /// Add the given qualified attribute to the access structure.
    ///
    /// If the dimension if hierarchical, specifying `after` sets the new
    /// attribute as the smallest attribute greater than the attribute of this
    /// name. If it is left unspecified, the new attribute becomes the lowest
    /// attribute of the dimension.
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
            .get_mut(&*attribute.dimension)
            .ok_or_else(|| {
                Error::DimensionNotFound(attribute.dimension.to_string())
            })?
            .add_attribute(attribute.attribute, security_mode, after, cnt)?;

        Ok(())
    }

    /// Remove the given qualified attribute from the access structure.
    ///
    /// Requires USK refresh
    /// ====================
    ///
    /// Only refreshed keys loose the ability to decrypt for an access policy belonging to the
    /// semantic space of this attribute.
    pub fn del_attribute(
        &mut self,
        attr: &QualifiedAttribute,
    ) -> Result<(), Error> {
        if let Some(dim) = self.dimensions.get_mut(&*attr.dimension) {
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
        match self.dimensions.get_mut(&*attribute.dimension) {
            Some(d) => d.rename_attribute(
                NameRef::try_from(&*attribute.attribute)?,
                Name::try_from(new_name)?,
            ),
            None => {
                Err(Error::DimensionNotFound(attribute.dimension.to_string()))
            }
        }
    }

    /// Lists name of the dimensions hold by this access structure.
    pub fn dimensions(&self) -> impl Iterator<Item = &str> {
        self.dimensions.keys().map(Borrow::borrow)
    }

    /// Returns the dimension with the given name from this access structure.
    ///
    /// Fails if there is no such dimension.
    pub fn get_dimension(&self, name: &str) -> Result<&Dimension, Error> {
        self.dimensions
            .get(name)
            .ok_or_else(|| Error::DimensionNotFound(name.to_string()))
    }

    /// Lists the qualified attributes hold by this access structure.
    pub fn attributes(
        &'_ self,
    ) -> impl '_ + Iterator<Item = QualifiedAttribute> {
        self.dimensions.iter().flat_map(|(dimension, d)| {
            d.get_attributes_name().map(move |attribute| {
                QualifiedAttribute::new(
                    dimension.to_string(),
                    attribute.to_string(),
                )
            })
        })
    }

    /// Returns the attribute with the given name from this access structure.
    ///
    /// Fails if there is no such attribute.
    pub fn get_attribute(
        &self,
        attr: &QualifiedAttribute,
    ) -> Result<&Attribute, Error> {
        let dimension = self.get_dimension(&attr.dimension)?;
        dimension.get_attribute(NameRef::try_from(&*attr.attribute)?)
    }

    /// Marks an attribute as read only.
    ///
    /// Public keys generated for this access structure won't hold any key for
    /// this right, but user secret keys will to allow opening encapsulations
    /// previously generated for a policy mentioning this attribute.
    pub fn disable_attribute(
        &mut self,
        attr: &QualifiedAttribute,
    ) -> Result<(), Error> {
        match self.dimensions.get_mut(&*attr.dimension) {
            Some(d) => {
                d.disable_attribute(NameRef::try_from(&*attr.attribute)?)
            }
            None => Err(Error::DimensionNotFound(attr.dimension.to_string())),
        }
    }

    /// Returns all rights defined by this access structure along with their
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

    /// Retrieves the ID of an attribute.
    #[cfg(test)]
    fn get_attribute_id(
        &self,
        attribute: &QualifiedAttribute,
    ) -> Result<usize, Error> {
        self.get_attribute(attribute).map(Attribute::get_id)
    }

    /// Returns the rights associated to the given access policy when extended
    /// each attribute of each clause to its lower attributes or the entire
    /// dimension in the case of the broadcast attribute.
    fn generate_extended_rights(
        &self,
        ap: &AccessPolicy,
    ) -> Result<BTreeSet<Right>, Error> {
        let extend_clause =
            |clause: &[QualifiedAttribute]| -> Result<Vec<Dimension>, Error> {
                clause
                    .iter()
                    .map(|qa| {
                        let dimension = self.get_dimension(&qa.dimension)?;
                        dimension.restrict(qa.attribute.to_string())
                    })
                    .collect()
            };

        ap.to_dnf()
            .iter()
            .map(|clause| {
                extend_clause(clause).map(|extended_attribute| {
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
                    .map(|attr| Ok(self.get_attribute(&attr)?.get_id()))
                    .collect::<Result<_, Error>>()?;
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
                QualifiedAttribute::new(
                    "Country".to_owned(),
                    attribute.to_owned(),
                ),
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
            let ap = "SEC::LOW";
            let comp_points = structure
                .generate_extended_rights(&AccessPolicy::parse(ap)?)?;

            // Check the rights are the same as the ones manually generated, i.e.:
            // - rights(*)
            // - rights(LOW)
            let mut rights = BTreeSet::new();

            // The broadcast.
            rights.insert(Right::from_point(vec![])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "SEC".to_owned(),
                    "LOW".to_owned(),
                ))?,
            ])?);

            assert_eq!(comp_points, rights);
        }

        {
            let ap = "DPT::HR && SEC::*";
            let comp_points = structure
                .generate_extended_rights(&AccessPolicy::parse(ap)?)?;

            // Check the rights are the same as the ones manually generated, i.e.:
            // - rights(*)
            // - rights(DPT::*, SEC::LOW)
            // - rights(DPT::*, SEC::MID)
            // - rights(DPT::*, SEC::TOP)
            // - rights(DPT::HR, SEC::⊥)
            // - rights(DPT::HR, SEC::LOW)
            // - rights(DPT::HR, SEC::MID)
            // - rights(DPT::HR, SEC::TOP)
            let mut rights = BTreeSet::new();

            // The broadcast (`*`).
            rights.insert(Right::from_point(vec![])?);

            // rights(DPT::HR, SEC::⊥)
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "DPT".to_owned(),
                    "HR".to_owned(),
                ))?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "DPT".to_owned(),
                    "HR".to_owned(),
                ))?,
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "SEC".to_owned(),
                    "LOW".to_owned(),
                ))?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "DPT".to_owned(),
                    "HR".to_owned(),
                ))?,
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "SEC".to_owned(),
                    "MED".to_owned(),
                ))?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "DPT".to_owned(),
                    "HR".to_owned(),
                ))?,
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "SEC".to_owned(),
                    "TOP".to_owned(),
                ))?,
            ])?);

            // rights(DPT::*, SEC::LOW)
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "SEC".to_owned(),
                    "LOW".to_owned(),
                ))?,
            ])?);

            // rights(DPT::*, SEC::MID)
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "SEC".to_owned(),
                    "MED".to_owned(),
                ))?,
            ])?);

            // rights(DPT::*, SEC::TOP)
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "SEC".to_owned(),
                    "TOP".to_owned(),
                ))?,
            ])?);

            assert_eq!(comp_points, rights);
        }

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

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "DPT".to_owned(),
                    "FIN".to_owned(),
                ))?,
            ])?);
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "DPT".to_owned(),
                    "HR".to_owned(),
                ))?,
            ])?);
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "SEC".to_owned(),
                    "LOW".to_owned(),
                ))?,
            ])?);
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "SEC".to_owned(),
                    "MED".to_owned(),
                ))?,
            ])?);
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "SEC".to_owned(),
                    "TOP".to_owned(),
                ))?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "DPT".to_owned(),
                    "FIN".to_owned(),
                ))?,
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "SEC".to_owned(),
                    "LOW".to_owned(),
                ))?,
            ])?);
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "DPT".to_owned(),
                    "HR".to_owned(),
                ))?,
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "SEC".to_owned(),
                    "LOW".to_owned(),
                ))?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "DPT".to_owned(),
                    "HR".to_owned(),
                ))?,
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "SEC".to_owned(),
                    "MED".to_owned(),
                ))?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "DPT".to_owned(),
                    "FIN".to_owned(),
                ))?,
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "SEC".to_owned(),
                    "MED".to_owned(),
                ))?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "DPT".to_owned(),
                    "HR".to_owned(),
                ))?,
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "SEC".to_owned(),
                    "TOP".to_owned(),
                ))?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "DPT".to_owned(),
                    "FIN".to_owned(),
                ))?,
                structure.get_attribute_id(&QualifiedAttribute::new(
                    "SEC".to_owned(),
                    "TOP".to_owned(),
                ))?,
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
                // The extension of `DPT::HR` is itself and the dimensional
                // broadcast. No other extensions are required since nothing
                // else is mentioned.
                (1 + 1)
            );

            let ap = "DPT::* && SEC::LOW";
            assert_eq!(
                structure
                    .generate_extended_rights(&AccessPolicy::parse(ap)?)?
                    .len(),
                // The extension of `DPT::*` is the entire department dimension
                // (including the dimensional broadcast), while the extension of
                // `SEC::LOW` is itself and the bottom attribute of the `SEC`
                // dimension.
                (1 + 1) * (5 + 1)
            );

            let ap = "SEC::LOW";
            assert_eq!(
                structure
                    .generate_extended_rights(&AccessPolicy::parse(ap)?)?
                    .len(),
                // The extension of `SEC::LOW` is itself and the bottom
                // attribute of the `SEC` dimension.
                (1 + 1)
            );
        }
        Ok(())
    }
}
