use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::Debug,
};

use serde::{Deserialize, Serialize};

use super::{EncryptionStatus, SecurityMode};
use crate::{data_struct::Dict, Error};

type Name = String;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Attribute {
    pub(crate) id: usize,
    pub(crate) mode: SecurityMode,
    pub(crate) status: EncryptionStatus,
}

impl Attribute {
    pub fn new(encryption_hint: SecurityMode, id: usize) -> Self {
        Self {
            id,
            mode: encryption_hint,
            status: EncryptionStatus::EncryptDecrypt,
        }
    }

    pub fn get_id(&self) -> usize {
        self.id
    }

    pub fn get_security_mode(&self) -> SecurityMode {
        self.mode
    }

    pub fn get_status(&self) -> EncryptionStatus {
        self.status
    }
}

/// A dimension is an object that contains attributes. It can be ordered or unordered.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub enum Dimension {
    Anarchy(HashMap<Name, Attribute>),
    Hierarchy(Dict<Name, Attribute>),
}

impl Default for Dimension {
    fn default() -> Self {
        Self::Anarchy(Default::default())
    }
}

impl Dimension {
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

    pub fn get_attribute(&self, attr_name: &Name) -> Option<&Attribute> {
        match self {
            Self::Anarchy(attributes) => attributes.get(attr_name),
            Self::Hierarchy(attributes) => attributes.get(attr_name),
        }
    }

    /// Restricts the dimension to the attribute that are lower than the given one.
    pub fn restrict(&self, attr_name: Name) -> Result<Self, Error> {
        let params = self
            .get_attribute(&attr_name)
            .ok_or_else(|| Error::AttributeNotFound(attr_name.to_string()))?
            .clone();

        match self {
            Self::Hierarchy(attributes) => {
                let mut attributes = attributes
                    .iter()
                    .take_while(|(name, _)| *name != &attr_name)
                    .map(|(ref_name, ref_params)| (ref_name.clone(), ref_params.clone()))
                    .collect::<Dict<Name, Attribute>>();
                attributes.insert(attr_name, params);
                Ok(Self::Hierarchy(attributes))
            }
            Self::Anarchy(_) => Ok(Self::Anarchy(HashMap::from_iter([(attr_name, params)]))),
        }
    }

    /// Adds a new attribute to this dimension with the provided properties.
    ///
    /// # Errors
    /// Returns an error if the operation is not permitted.
    pub fn add_attribute(
        &mut self,
        attribute: Name,
        hint: SecurityMode,
        after: Option<&str>,
        id: usize,
    ) -> Result<(), Error> {
        match self {
            Self::Anarchy(attributes) => {
                if let Entry::Vacant(entry) = attributes.entry(attribute) {
                    entry.insert(Attribute::new(hint, id));
                    Ok(())
                } else {
                    Err(Error::OperationNotPermitted(
                        "Attribute already in dimension".to_string(),
                    ))
                }
            }
            Self::Hierarchy(attributes) => {
                if attributes.contains_key(&attribute) {
                    return Err(Error::OperationNotPermitted(
                        "Attribute already in dimension".to_string(),
                    ));
                }
                let after = if let Some(after) = after {
                    if !attributes.contains_key(after) {
                        return Err(Error::AttributeNotFound(
                            "the specified `after` attribute {after} does not exist".to_string(),
                        ));
                    }
                    after
                } else {
                    ""
                };
                let higher_attributes = attributes
                    .clone()
                    .into_iter()
                    .rev()
                    .take_while(|(name, _)| name != after)
                    .collect::<Vec<_>>();

                let mut new_attributes = attributes
                    .clone()
                    .into_iter()
                    .take_while(|a| Some(a) != higher_attributes.last())
                    .collect::<Dict<_, _>>();

                new_attributes.insert(attribute, Attribute::new(hint, id));
                higher_attributes.into_iter().rev().for_each(|(name, dim)| {
                    new_attributes.insert(name, dim);
                });
                *attributes = new_attributes;
                Ok(())
            }
        }
    }

    /// Removes the attribute with the given name from this dimension.
    ///
    /// # Errors
    /// Returns an error if no attribute with this name is found.
    pub fn remove_attribute(&mut self, name: &Name) -> Result<(), Error> {
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
    pub fn disable_attribute(&mut self, name: &Name) -> Result<(), Error> {
        match self {
            Self::Anarchy(attributes) => attributes
                .get_mut(name)
                .map(|attr| attr.status = EncryptionStatus::DecryptOnly)
                .ok_or(Error::AttributeNotFound(name.to_string())),
            Self::Hierarchy(attributes) => attributes
                .get_mut(name)
                .map(|attr| attr.status = EncryptionStatus::DecryptOnly)
                .ok_or(Error::AttributeNotFound(name.to_string())),
        }
    }

    /// Renames the attribute with the given name.
    ///
    /// # Errors
    /// Returns an error if the new name is already used in the same dimension or if no attribute
    /// with the given old name is found.
    pub fn rename_attribute(&mut self, old_name: &Name, new_name: Name) -> Result<(), Error> {
        match self {
            Self::Anarchy(attributes) => {
                if attributes.contains_key(&new_name) {
                    return Err(Error::OperationNotPermitted(
                        "New attribute name is already used in the same dimension".to_string(),
                    ));
                }
                match attributes.remove(old_name) {
                    Some(attr_params) => {
                        attributes.insert(new_name, attr_params);
                        Ok(())
                    }
                    None => Err(Error::AttributeNotFound(old_name.to_string())),
                }
            }
            Self::Hierarchy(attributes) => attributes
                .update_key(old_name, new_name)
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
    use cosmian_crypto_core::bytes_ser_de::Serializable;

    use super::*;

    impl Serializable for Attribute {
        type Error = Error;

        fn length(&self) -> usize {
            self.id.length() + self.mode.length() + self.status.length()
        }

        fn write(
            &self,
            ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
        ) -> Result<usize, Self::Error> {
            Ok(self.id.write(ser)? + self.mode.write(ser)? + self.status.write(ser)?)
        }

        fn read(
            de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer,
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                id: de.read()?,
                mode: de.read()?,
                status: de.read()?,
            })
        }
    }

    #[test]
    fn test_attribute_serialization() {
        use cosmian_crypto_core::bytes_ser_de::test_serialization;

        let attribute = Attribute::new(SecurityMode::Classic, 13);
        test_serialization(&attribute).unwrap();

        let attribute = Attribute::new(SecurityMode::Hybridized, usize::MAX);
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

        fn write(
            &self,
            ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
        ) -> Result<usize, Self::Error> {
            match self {
                Dimension::Anarchy(inner) => Ok(ser.write(&0usize)? + ser.write(inner)?),
                Dimension::Hierarchy(inner) => Ok(ser.write(&1usize)?
                    + ser
                        .write(inner)
                        .map_err(|e| Error::ConversionFailed(e.to_string()))?),
            }
        }

        fn read(
            de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer,
        ) -> Result<Self, Self::Error> {
            let t = de.read::<usize>()?;
            match t {
                0 => Ok(Self::Anarchy(de.read()?)),
                1 => Ok(Self::Hierarchy(de.read().map_err(
                    |e: crate::data_struct::error::Error| Error::ConversionFailed(e.to_string()),
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
        d.add_attribute("A".to_string(), SecurityMode::Classic, None, 0)
            .unwrap();
        d.add_attribute("B".to_string(), SecurityMode::Hybridized, Some("A"), 1)
            .unwrap();
        d.add_attribute("C".to_string(), SecurityMode::Hybridized, Some("B"), 2)
            .unwrap();
        test_serialization(&d).unwrap();

        let mut d = Dimension::Anarchy(HashMap::new());
        d.add_attribute("A".to_string(), SecurityMode::Classic, None, 0)
            .unwrap();
        d.add_attribute("B".to_string(), SecurityMode::Hybridized, None, 1)
            .unwrap();
        d.add_attribute("C".to_string(), SecurityMode::Hybridized, None, 2)
            .unwrap();
        test_serialization(&d).unwrap();
    }
}
