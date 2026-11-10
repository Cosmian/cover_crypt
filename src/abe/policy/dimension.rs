use super::{EncryptionStatus, HybridizationStatus};
use crate::{
    Error,
    abe::policy::{BROADCAST, Name, NameRef},
    data_struct::Dict,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    fmt::Debug,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Attribute {
    pub(crate) id: usize,
    pub(crate) security_mode: HybridizationStatus,
    pub(crate) encryption_status: EncryptionStatus,
}

impl Attribute {
    pub fn new(security_mode: HybridizationStatus, id: usize) -> Self {
        Self {
            id,
            security_mode,
            encryption_status: EncryptionStatus::EncryptDecrypt,
        }
    }

    pub fn get_id(&self) -> usize {
        self.id
    }

    pub fn get_security_mode(&self) -> HybridizationStatus {
        self.security_mode
    }

    pub fn get_encryption_status(&self) -> EncryptionStatus {
        self.encryption_status
    }
}

/// A dimension is an object that contains attributes. It can be ordered or unordered.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub enum Dimension {
    Anarchy(BTreeMap<Name, Attribute>),
    Hierarchy(Dict<Name, Attribute>),
}

impl Default for Dimension {
    fn default() -> Self {
        Self::Anarchy(Default::default())
    }
}

impl Dimension {
    pub fn is_hierarchical(&self) -> bool {
        match self {
            Self::Anarchy(_) => false,
            Self::Hierarchy(_) => true,
        }
    }

    pub fn nb_attributes(&self) -> usize {
        match self {
            Self::Anarchy(attributes) => attributes.len(),
            Self::Hierarchy(attributes) => attributes.len(),
        }
    }

    /// Returns an iterator over the attributes name.
    ///
    /// If the dimension is ordered, the names are returned in this order, otherwise they are
    /// returned in arbitrary order.
    pub fn get_attributes_name(&self) -> Box<dyn '_ + Iterator<Item = &Name>> {
        match self {
            Self::Anarchy(attributes) => Box::new(attributes.keys()),
            Self::Hierarchy(attributes) => Box::new(attributes.keys()),
        }
    }

    /// Returns the attribute with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error in case no attribute with the given name is found.
    pub fn get_attribute<'a>(
        &self,
        name: NameRef<'a>,
    ) -> Result<&Attribute, Error> {
        match self {
            Self::Anarchy(attributes) => attributes.get(&*name),
            Self::Hierarchy(attributes) => attributes.get(&*name),
        }
        .ok_or(Error::AttributeNotFound(name.to_string()))
    }

    /// Restricts the dimension to the attribute that are lower than the given
    /// one or to the entire dimension in case this is the broadcast attribute.
    pub(crate) fn restrict(&self, name: String) -> Result<Self, Error> {
        if name == BROADCAST {
            Ok(self.clone())
        } else {
            let name = Name::try_from(name)?;
            let attribute = self.get_attribute((&name).into())?.clone();
            match self {
                Self::Hierarchy(attributes) => {
                    let mut attributes = attributes
                        .iter()
                        .take_while(|(n, _)| *n != &name)
                        .map(|(name, params)| (name.clone(), params.clone()))
                        .collect::<Dict<_, _>>();
                    attributes.insert(name, attribute);
                    Ok(Self::Hierarchy(attributes))
                }
                Self::Anarchy(_) => Ok(Self::Anarchy(BTreeMap::from_iter([(
                    name,
                    attribute.clone(),
                )]))),
            }
        }
    }

    /// Adds a new attribute to this dimension with the provided name and
    /// properties.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation is not permitted.
    pub fn add_attribute(
        &mut self,
        name: String,
        security_mode: HybridizationStatus,
        after: Option<&str>,
        id: usize,
    ) -> Result<(), Error> {
        match self {
            Self::Anarchy(attributes) => {
                if let Entry::Vacant(entry) =
                    attributes.entry(Name::try_from(name)?)
                {
                    entry.insert(Attribute::new(security_mode, id));
                    Ok(())
                } else {
                    Err(Error::OperationNotPermitted(
                        "Attribute already in dimension".to_string(),
                    ))
                }
            }
            Self::Hierarchy(attributes) => {
                if attributes.contains_key(&*name) {
                    return Err(Error::OperationNotPermitted(
                        "Attribute already in dimension".to_string(),
                    ));
                }

                let new_attributes = {
                    let mut new_attributes = Dict::new();
                    if let Some(after) = after {
                        for (n, a) in attributes.iter().take_while({
                            let mut is_found = false;
                            move |(n, _)| {
                                if &***n == after {
                                    is_found = true;
                                    true
                                } else {
                                    !is_found
                                }
                            }
                        }) {
                            new_attributes.insert(n.clone(), a.clone());
                        }

                        new_attributes.insert(
                            Name::try_from(name)?,
                            Attribute::new(security_mode, id),
                        );

                        for (n, a) in attributes
                            .iter()
                            .skip_while(|(n, _)| &***n != after)
                        {
                            new_attributes.insert(n.clone(), a.clone());
                        }
                    } else {
                        new_attributes.insert(
                            Name::try_from(name)?,
                            Attribute::new(security_mode, id),
                        );
                        for (name, attr) in attributes.iter() {
                            new_attributes.insert(name.clone(), attr.clone());
                        }
                    }
                    new_attributes
                };

                *attributes = new_attributes;

                Ok(())
            }
        }
    }

    /// Removes the attribute with the given name from this dimension.
    ///
    /// # Errors
    ///
    /// Returns an error if no attribute with this name is found.
    pub fn remove_attribute(&mut self, name: &str) -> Result<(), Error> {
        match self {
            Self::Anarchy(attributes) => attributes
                .remove(name)
                .map(|_| ())
                .ok_or(Error::AttributeNotFound(name.to_string())),
            Self::Hierarchy(attributes) => attributes
                .remove(name)
                .map(|_| ())
                .ok_or(Error::AttributeNotFound(name.to_string())),
        }
    }

    /// Disables the attribute with the given name.
    ///
    /// # Errors
    /// Returns an error if no attribute with this name is found.
    pub fn disable_attribute<'a>(
        &mut self,
        name: NameRef<'a>,
    ) -> Result<(), Error> {
        match self {
            Self::Anarchy(attributes) => attributes
                .get_mut(&*name)
                .map(|attr| {
                    attr.encryption_status = EncryptionStatus::DecryptOnly
                })
                .ok_or(Error::AttributeNotFound(name.to_string())),
            Self::Hierarchy(attributes) => attributes
                .get_mut(&*name)
                .map(|attr| {
                    attr.encryption_status = EncryptionStatus::DecryptOnly
                })
                .ok_or(Error::AttributeNotFound(name.to_string())),
        }
    }

    /// Renames the attribute with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the new name is already used in the same dimension
    /// or if no attribute with the given old name is found.
    pub fn rename_attribute(
        &mut self,
        old_name: NameRef,
        new_name: Name,
    ) -> Result<(), Error> {
        match self {
            Self::Anarchy(attributes) => {
                if attributes.contains_key(&*new_name) {
                    return Err(Error::OperationNotPermitted(
                        "New attribute name is already used in the same dimension".to_string(),
                    ));
                }
                match attributes.remove(&*old_name) {
                    Some(attr_params) => {
                        attributes.insert(new_name, attr_params);
                        Ok(())
                    }
                    None => Err(Error::AttributeNotFound(old_name.to_string())),
                }
            }
            Self::Hierarchy(attributes) => attributes
                .update_key(&*old_name, new_name)
                .map_err(|e| Error::OperationNotPermitted(e.to_string())),
        }
    }

    /// Returns an iterator over the `AttributesParameters` and parameters.
    /// If the dimension is ordered, the attributes are returned in order.
    pub fn attributes(&self) -> Box<dyn '_ + Iterator<Item = &Attribute>> {
        match self {
            Self::Anarchy(attributes) => Box::new(attributes.values()),
            Self::Hierarchy(attributes) => Box::new(attributes.values()),
        }
    }
}

mod serialization {
    use cosmian_crypto_core::bytes_ser_de::{
        Deserializer, Serializable, Serializer,
    };

    use super::*;

    impl Serializable for Attribute {
        type Error = Error;

        fn length(&self) -> usize {
            self.id.length()
                + self.security_mode.length()
                + self.encryption_status.length()
        }

        fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
            Ok(self.id.write(ser)?
                + self.security_mode.write(ser)?
                + self.encryption_status.write(ser)?)
        }

        fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
            Ok(Self {
                id: de.read()?,
                security_mode: de.read()?,
                encryption_status: de.read()?,
            })
        }
    }

    #[test]
    fn test_attribute_serialization() {
        use cosmian_crypto_core::bytes_ser_de::test_serialization;

        let attribute = Attribute::new(HybridizationStatus::Classic, 13);
        test_serialization(&attribute).unwrap();

        let attribute =
            Attribute::new(HybridizationStatus::Hybridized, usize::MAX);
        test_serialization(&attribute).unwrap();
    }

    impl Serializable for Dimension {
        type Error = Error;

        fn length(&self) -> usize {
            1 + match self {
                Dimension::Anarchy(inner) => inner.length(),
                Dimension::Hierarchy(inner) => inner.length(),
            }
        }

        fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
            match self {
                Dimension::Anarchy(inner) => {
                    Ok(ser.write(&0usize)? + ser.write(inner)?)
                }
                Dimension::Hierarchy(inner) => Ok(ser.write(&1usize)?
                    + ser
                        .write(inner)
                        .map_err(|e| Error::ConversionFailed(e.to_string()))?),
            }
        }

        fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
            let t = de.read::<usize>()?;
            match t {
                0 => Ok(Self::Anarchy(de.read()?)),
                1 => Ok(Self::Hierarchy(de.read().map_err(
                    |e: crate::data_struct::error::Error| {
                        Error::ConversionFailed(e.to_string())
                    },
                )?)),
                n => Err(Error::ConversionFailed(format!(
                    "invalid dimension type: {n}"
                ))),
            }
        }
    }

    #[test]
    fn test_dimension_serialization() {
        use cosmian_crypto_core::bytes_ser_de::test_serialization;

        let mut d = Dimension::Hierarchy(Dict::new());

        d.add_attribute("A".to_owned(), HybridizationStatus::Classic, None, 0)
            .unwrap();

        d.add_attribute(
            "B".to_owned(),
            HybridizationStatus::Hybridized,
            Some("A"),
            1,
        )
        .unwrap();

        d.add_attribute(
            "C".to_owned(),
            HybridizationStatus::Hybridized,
            Some("B"),
            2,
        )
        .unwrap();

        test_serialization(&d).unwrap();

        let mut d = Dimension::Anarchy(BTreeMap::new());

        d.add_attribute("A".to_owned(), HybridizationStatus::Classic, None, 0)
            .unwrap();

        d.add_attribute(
            "B".to_owned(),
            HybridizationStatus::Hybridized,
            None,
            1,
        )
        .unwrap();

        d.add_attribute(
            "C".to_owned(),
            HybridizationStatus::Hybridized,
            None,
            2,
        )
        .unwrap();

        test_serialization(&d).unwrap();
    }
}
