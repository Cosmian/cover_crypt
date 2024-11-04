use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::Debug,
};

use serde::{Deserialize, Serialize};

use super::{
    attribute::{AttributeBuilder, EncryptionHint},
    AttributeStatus,
};
use crate::{data_struct::Dict, Error};

///
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
    pub(crate) id: u32,
    pub(crate) encryption_hint: EncryptionHint,
    pub(crate) write_status: AttributeStatus,
}

impl AttributeParameters {
    /// Creates a `AttributeParameters` with the provided `encryption_hint`
    /// and increments the `seed_id` to generate unique IDs.
    pub fn new(encryption_hint: EncryptionHint, seed_id: &mut u32) -> Self {
        *seed_id += 1;
        Self {
            id: *seed_id,
            encryption_hint,
            write_status: AttributeStatus::EncryptDecrypt,
        }
    }

    #[must_use]
    pub fn get_id(&self) -> u32 {
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

impl Dimension {
    /// Creates a new `Dimension` based on the given `DimensionBuilder`,
    /// initializing attributes and order if applicable.
    ///
    /// # Arguments
    ///
    /// * `dim` - The `DimensionBuilder` to base the dimension on.
    /// * `seed_id` - A mutable reference to a seed ID used for generating
    ///   unique values for attributes.
    pub fn new(dim: DimensionBuilder, seed_id: &mut u32) -> Self {
        let attributes_mapping = dim.attributes_properties.into_iter().map(|attr| {
            (
                attr.name,
                AttributeParameters::new(attr.encryption_hint, seed_id),
            )
        });

        match dim.hierarchical {
            true => Self::Ordered(attributes_mapping.collect()),
            false => Self::Unordered(attributes_mapping.collect()),
        }
    }

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
        &mut self,
        attr_name: AttributeName,
        encryption_hint: EncryptionHint,
        seed_id: &mut u32,
    ) -> Result<(), Error> {
        match self {
            Self::Unordered(attributes) => {
                if let Entry::Vacant(entry) = attributes.entry(attr_name) {
                    entry.insert(AttributeParameters::new(encryption_hint, seed_id));
                    Ok(())
                } else {
                    Err(Error::OperationNotPermitted(
                        "Attribute already in dimension".to_string(),
                    ))
                }
            }
            Self::Ordered(_) => Err(Error::OperationNotPermitted(
                "Hierarchical dimension are immutable".to_string(),
            )),
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
