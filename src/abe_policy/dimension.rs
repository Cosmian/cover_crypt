use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::Debug,
};

use cosmian_crypto_core::bytes_ser_de::{to_leb128_len, Serializable};
use serde::{Deserialize, Serialize};

use super::{
    attribute::{AttributeBuilder, EncryptionHint},
    AttributeStatus,
};
use crate::{data_struct::Dict, Error};

/// Creates a dimension by its name and its underlying attribute properties.
/// An attribute property defines its name and a hint about whether hybridized
/// encryption should be used for it (hint set to `true` if this is the case).
///
/// If `hierarchical` is set to `true`, we assume a lexicographical order based
/// on the attribute name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionBuilder {
    /// Dimension name
    pub name: String,
    /// Names of the dimension attributes and hybridized encryption hints
    pub attributes_properties: Vec<AttributeBuilder>,
    /// `true` if the dimension is hierarchical
    pub hierarchical: bool,
}

impl DimensionBuilder {
    /// Generates a new policy dimension with the given name and attribute
    /// names. A hierarchical dimension enforces order between its
    /// attributes.
    ///
    /// - `name`                    : dimension name
    /// - `attribute_properties`    : dimension attribute properties
    /// - `hierarchical`            : set to `true` if the dimension is
    ///   hierarchical
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
                .map(|(dim_name, encryption_hint)| AttributeBuilder {
                    name: dim_name.to_string(),
                    encryption_hint,
                })
                .collect(),
            hierarchical,
        }
    }

    /// Returns the number of attributes belonging to this dimension.
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
/// Represents an `Attribute` inside a `Dimension`.
pub struct AttributeParameters {
    pub(crate) id: usize,
    pub(crate) encryption_hint: EncryptionHint,
    pub(crate) write_status: AttributeStatus,
}

impl Serializable for AttributeParameters {
    type Error = Error;

    fn length(&self) -> usize {
        2 + to_leb128_len(self.id)
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        let mut n = ser.write_leb128_u64(self.id as u64)?;
        n += ser.write_leb128_u64(<bool>::from(self.encryption_hint) as u64)?;
        n += ser.write_leb128_u64(<bool>::from(self.write_status) as u64)?;
        Ok(n)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let id = de.read_leb128_u64()?.try_into()?;
        let hint = de.read_leb128_u64()?;
        let encryption_hint = if 0 == hint {
            EncryptionHint::Classic
        } else if 1 == hint {
            EncryptionHint::Hybridized
        } else {
            return Err(Error::ConversionFailed(format!(
                "erroneous hint value {hint}"
            )));
        };

        let status = de.read_leb128_u64()?;
        let write_status = if 0 == status {
            AttributeStatus::DecryptOnly
        } else if 1 == status {
            AttributeStatus::EncryptDecrypt
        } else {
            return Err(Error::ConversionFailed(format!(
                "erroneous status value {hint}"
            )));
        };

        Ok(Self {
            id,
            encryption_hint,
            write_status,
        })
    }
}

impl AttributeParameters {
    /// Creates a `AttributeParameters` with the provided `encryption_hint`
    /// and increments the `seed_id` to generate unique IDs.
    pub fn new(encryption_hint: EncryptionHint, id: usize) -> Self {
        Self {
            id,
            encryption_hint,
            write_status: AttributeStatus::EncryptDecrypt,
        }
    }

    #[must_use]
    pub fn get_id(&self) -> usize {
        self.id
    }

    #[must_use]
    pub fn get_encryption_hint(&self) -> EncryptionHint {
        self.encryption_hint
    }

    #[must_use]
    pub fn get_status(&self) -> AttributeStatus {
        self.write_status
    }
}

type AttributeName = String;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
/// A dimension is a space that holds attributes. It can be ordered (an
/// dimension) or unordered (a set).
pub enum Dimension {
    Unordered(HashMap<AttributeName, AttributeParameters>),
    Ordered(Dict<AttributeName, AttributeParameters>),
}

impl Default for Dimension {
    fn default() -> Self {
        Self::Unordered(Default::default())
    }
}

impl Serializable for Dimension {
    type Error = Error;

    fn length(&self) -> usize {
        let f = |attributes: Box<dyn Iterator<Item = (&String, &AttributeParameters)>>| {
            attributes
                .map(|(name, attribute)| {
                    let l = name.len();
                    to_leb128_len(l) + l + attribute.length()
                })
                .sum::<usize>()
        };
        1 + match self {
            Dimension::Unordered(attributes) => {
                to_leb128_len(attributes.len()) + f(Box::new(attributes.iter()))
            }
            Dimension::Ordered(attributes) => {
                to_leb128_len(attributes.len()) + f(Box::new(attributes.iter()))
            }
        }
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        let write_attributes =
            |mut attributes: Box<dyn Iterator<Item = (&String, &AttributeParameters)>>,
             ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer|
             -> Result<usize, Error> {
                attributes.try_fold(0, |mut n, (name, attribute)| {
                    n += ser.write_vec(name.as_bytes())?;
                    n += ser.write(attribute)?;
                    Ok(n)
                })
            };

        let mut n = ser.write_leb128_u64(self.is_ordered() as u64)?;
        match self {
            Dimension::Unordered(attributes) => {
                n += ser.write_leb128_u64(attributes.len() as u64)?;
                n += write_attributes(Box::new(attributes.iter()), ser)?;
            }
            Dimension::Ordered(attributes) => {
                n += ser.write_leb128_u64(attributes.len() as u64)?;
                n += write_attributes(Box::new(attributes.iter()), ser)?;
            }
        };

        Ok(n)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let is_ordered = de.read_leb128_u64()?;
        let l = de.read_leb128_u64()?;
        let attributes = (0..l).map(|_| {
            let name = String::from_utf8(de.read_vec()?)
                .map_err(|e| Error::ConversionFailed(e.to_string()))?;
            let attribute = de.read::<AttributeParameters>()?;
            Ok::<_, Error>((name, attribute))
        });

        if 0 == is_ordered {
            attributes.collect::<Result<_, _>>().map(Self::Ordered)
        } else if 1 == is_ordered {
            attributes.collect::<Result<_, _>>().map(Self::Unordered)
        } else {
            Err(Error::ConversionFailed(format!(
                "invalid boolean value {is_ordered}"
            )))
        }
    }
}

impl Dimension {
    #[must_use]
    pub fn nb_attributes(&self) -> usize {
        match self {
            Self::Unordered(attributes) => attributes.len(),
            Self::Ordered(attributes) => attributes.len(),
        }
    }

    #[must_use]
    pub fn is_ordered(&self) -> bool {
        match self {
            Self::Unordered(_) => false,
            Self::Ordered(_) => true,
        }
    }

    pub fn order(&mut self, attributes: &[String]) -> Result<(), Error> {
        let attributes = attributes
            .iter()
            .map(|a| {
                self.get_attribute(a)
                    .ok_or_else(|| Error::AttributeNotFound(a.to_string()))
                    .cloned()
                    .map(|attribute| (a.to_owned(), attribute))
            })
            .collect::<Result<Dict<_, _>, _>>()?;
        *self = Self::Ordered(attributes);
        Ok(())
    }

    /// Returns an iterator over the attributes name.
    /// If the dimension is ordered, the names are returned in this order,
    /// otherwise they are returned in arbitrary order.
    #[must_use]
    pub fn get_attributes_name(&self) -> Box<dyn '_ + Iterator<Item = &AttributeName>> {
        match self {
            Self::Unordered(attributes) => Box::new(attributes.keys()),
            Self::Ordered(attributes) => Box::new(attributes.keys()),
        }
    }

    #[must_use]
    pub fn get_attribute(&self, attr_name: &AttributeName) -> Option<&AttributeParameters> {
        match self {
            Self::Unordered(attributes) => attributes.get(attr_name),
            Self::Ordered(attributes) => attributes.get(attr_name),
        }
    }

    /// Restricts the dimension to the given attribute.
    ///
    /// If the dimension is unordered, the resulting dimension only holds this
    /// attribute. Otherwise it also holds lower attributes.
    pub fn restrict(&self, attr_name: AttributeName) -> Result<Self, Error> {
        let params = self
            .get_attribute(&attr_name)
            .ok_or_else(|| Error::AttributeNotFound(attr_name.to_string()))?
            .clone();

        match self {
            Self::Ordered(attributes) => {
                let mut attributes = attributes
                    .iter()
                    .take_while(|(name, _)| *name != &attr_name)
                    .map(|(ref_name, ref_params)| (ref_name.clone(), ref_params.clone()))
                    .collect::<Dict<AttributeName, AttributeParameters>>();
                attributes.insert(attr_name, params);
                Ok(Self::Ordered(attributes))
            }
            Self::Unordered(_) => Ok(Self::Unordered(HashMap::from_iter([(attr_name, params)]))),
        }
    }

    /// Adds a new attribute to the dimension with the provided properties.
    ///
    /// # Arguments
    ///
    /// * `attr` - The properties of the attribute to add.
    /// * `seed_id` - A seed used for generating unique ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation is not permitted.
    pub fn add_attribute(
        self,
        attribute: AttributeName,
        hint: EncryptionHint,
        after: Option<AttributeName>,
        id: usize,
    ) -> Result<Self, Error> {
        match self {
            Self::Unordered(mut attributes) => {
                if let Entry::Vacant(entry) = attributes.entry(attribute) {
                    entry.insert(AttributeParameters::new(hint, id));
                    Ok(Self::Unordered(attributes))
                } else {
                    Err(Error::OperationNotPermitted(
                        "Attribute already in dimension".to_string(),
                    ))
                }
            }
            Self::Ordered(attributes) => {
                if attributes.contains_key(&attribute) {
                    return Err(Error::OperationNotPermitted(
                        "Attribute already in dimension".to_string(),
                    ));
                }
                let after = if let Some(after) = after {
                    if !attributes.contains_key(&after) {
                        return Err(Error::AttributeNotFound(
                            "the specified `after` attribute {after} does not exist".to_string(),
                        ));
                    }
                    after
                } else {
                    "".to_owned()
                };
                let higher_attributes = attributes
                    .clone()
                    .into_iter()
                    .rev()
                    .take_while(|(name, _)| name != &after)
                    .collect::<Vec<_>>();

                let mut new_attributes = attributes
                    .clone()
                    .into_iter()
                    .take_while(|a| Some(a) != higher_attributes.last())
                    .collect::<Dict<_, _>>();

                new_attributes.insert(attribute, AttributeParameters::new(hint, id));
                higher_attributes.into_iter().rev().for_each(|(name, dim)| {
                    new_attributes.insert(name, dim);
                });
                Ok(Self::Ordered(new_attributes))
            }
        }
    }

    /// Removes an attribute from the dimension.
    ///
    /// # Arguments
    ///
    /// * `attr_name` - The name of the attribute to remove.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation is not permitted or if the attribute
    /// is not found.
    pub fn remove_attribute(&mut self, attr_name: &AttributeName) -> Result<(), Error> {
        match self {
            Self::Unordered(attributes) => attributes
                .remove(attr_name)
                .map(|_| ())
                .ok_or(Error::AttributeNotFound(attr_name.to_string())),
            Self::Ordered(_) => Err(Error::OperationNotPermitted(
                "Hierarchical dimension are immutable".to_string(),
            )),
        }
    }

    /// Deactivates an attribute by marking it as read-only.
    ///
    /// # Arguments
    ///
    /// * `attr_name` - The name of the attribute to deactivate.
    ///
    /// # Errors
    ///
    /// Returns an error if the attribute is not found.
    pub fn disable_attribute(&mut self, attr_name: &AttributeName) -> Result<(), Error> {
        match self {
            Self::Unordered(attributes) => attributes
                .get_mut(attr_name)
                .map(|attr| attr.write_status = AttributeStatus::DecryptOnly)
                .ok_or(Error::AttributeNotFound(attr_name.to_string())),
            Self::Ordered(attributes) => attributes
                .get_mut(attr_name)
                .map(|attr| attr.write_status = AttributeStatus::DecryptOnly)
                .ok_or(Error::AttributeNotFound(attr_name.to_string())),
        }
    }

    /// Renames an attribute with a new name.
    ///
    /// # Arguments
    ///
    /// * `attr_name` - The current name of the attribute to rename.
    /// * `new_name` - The new name for the attribute.
    ///
    /// # Errors
    ///
    /// Returns an error if the new attribute name is already used in the same
    /// dimension or if the attribute is not found.
    pub fn rename_attribute(
        &mut self,
        attr_name: &AttributeName,
        new_name: String,
    ) -> Result<(), Error> {
        match self {
            Self::Unordered(attributes) => {
                if attributes.contains_key(&new_name) {
                    return Err(Error::OperationNotPermitted(
                        "New attribute name is already used in the same dimension".to_string(),
                    ));
                }
                match attributes.remove(attr_name) {
                    Some(attr_params) => {
                        attributes.insert(new_name, attr_params);
                        Ok(())
                    }
                    None => Err(Error::AttributeNotFound(attr_name.to_string())),
                }
            }
            Self::Ordered(attributes) => attributes
                .update_key(attr_name, new_name)
                .map_err(|e| Error::OperationNotPermitted(e.to_string())),
        }
    }

    /// Returns an iterator over the `AttributesParameters` and parameters.
    /// If the dimension is ordered, the attributes are returned in order.
    #[must_use]
    pub fn attributes(&self) -> Box<dyn '_ + Iterator<Item = &AttributeParameters>> {
        match self {
            Self::Unordered(attributes) => Box::new(attributes.values()),
            Self::Ordered(attributes) => Box::new(attributes.values()),
        }
    }
}
