use std::{collections::HashMap, fmt::Debug};

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
    pub(crate) rotation_values: Vec<u32>,
    pub(crate) encryption_hint: EncryptionHint,
    pub(crate) write_status: AttributeStatus,
}

impl AttributeParameters {
    /// Creates a `AttributeParameters` with the provided `encryption_hint`
    /// and increments the `seed_id` to generate unique IDs.
    pub fn new(encryption_hint: EncryptionHint, seed_id: &mut u32) -> Self {
        *seed_id += 1;
        Self {
            rotation_values: vec![*seed_id],
            encryption_hint,
            write_status: AttributeStatus::EncryptDecrypt,
        }
    }

    /// Gets the current rotation of the Attribute.
    pub fn get_current_rotation(&self) -> u32 {
        self.rotation_values
            .last()
            .copied()
            .expect("Attribute should always have at least one value")
    }

    pub fn rotate_current_value(&mut self, seed_id: &mut u32) {
        *seed_id += 1;
        self.rotation_values.push(*seed_id)
    }

    pub fn clear_old_rotation_values(&mut self) {
        // TODO: use VecDeque ?
        let current_val = self.get_current_rotation();
        self.rotation_values.retain(|val| val == &current_val);
    }

    pub fn all_rotation_values(&self) -> impl '_ + DoubleEndedIterator<Item = u32> {
        self.rotation_values.iter().copied()
    }

    /// Flattens the properties of the `AttributeParameters` into a vector of
    /// tuples where each tuple contains a rotation value, the associated
    /// encryption hint, and the `read_only` flag.
    pub fn flatten_properties(&self) -> Vec<(u32, EncryptionHint, AttributeStatus)> {
        self.rotation_values
            .iter()
            .map(|&value| (value, self.encryption_hint, self.write_status))
            .collect()
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
    pub fn new(dim: &DimensionBuilder, seed_id: &mut u32) -> Self {
        let attributes_mapping = dim.attributes_properties.iter().map(|attr| {
            (
                attr.name.clone(),
                AttributeParameters::new(attr.encryption_hint, seed_id),
            )
        });

        match dim.hierarchical {
            true => Self::Ordered(attributes_mapping.collect()),
            false => Self::Unordered(attributes_mapping.collect()),
        }
    }

    pub fn nb_attributes(&self) -> usize {
        match self {
            Dimension::Unordered(attributes) => attributes.len(),
            Dimension::Ordered(attributes) => attributes.len(),
        }
    }

    pub fn is_ordered(&self) -> bool {
        match self {
            Dimension::Unordered(_) => false,
            Dimension::Ordered(_) => true,
        }
    }

    /// Returns an iterator over the attributes name.
    /// If the dimension is ordered, the names are returned in this order,
    /// otherwise they are returned in arbitrary order.
    pub fn get_attributes_name(&self) -> Box<dyn '_ + Iterator<Item = &AttributeName>> {
        match self {
            Dimension::Unordered(attributes) => Box::new(attributes.keys()),
            Dimension::Ordered(attributes) => Box::new(attributes.keys()),
        }
    }

    pub fn get_attribute(&self, attr_name: &AttributeName) -> Option<&AttributeParameters> {
        match self {
            Dimension::Unordered(attributes) => attributes.get(attr_name),
            Dimension::Ordered(attributes) => attributes.get(attr_name),
        }
    }

    /// Rotates the attribute with the given name by incrementing its rotation
    /// value.
    ///
    /// # Arguments
    ///
    /// * `attr_name` - The name of the attribute to rotate.
    /// * `seed_id` - A seed used for generating the new rotation value.
    ///
    /// # Errors
    ///
    /// Returns an error if the attribute with the specified name is not found.
    pub fn rotate_attribute(
        &mut self,
        attr_name: &AttributeName,
        seed_id: &mut u32,
    ) -> Result<(), Error> {
        match self {
            Dimension::Unordered(attributes) => match attributes.get_mut(attr_name) {
                Some(attr) => {
                    attr.rotate_current_value(seed_id);
                    Ok(())
                }
                None => Err(Error::AttributeNotFound(attr_name.to_string())),
            },
            Dimension::Ordered(attributes) => match attributes.get_mut(attr_name) {
                Some(attr) => {
                    attr.rotate_current_value(seed_id);
                    Ok(())
                }
                None => Err(Error::AttributeNotFound(attr_name.to_string())),
            },
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
        attr_name: &AttributeName,
        encryption_hint: EncryptionHint,
        seed_id: &mut u32,
    ) -> Result<(), Error> {
        match self {
            Dimension::Unordered(attributes) => {
                if attributes.contains_key(attr_name) {
                    Err(Error::OperationNotPermitted(
                        "Attribute already in dimension".to_string(),
                    ))
                } else {
                    attributes.insert(
                        attr_name.clone(),
                        AttributeParameters::new(encryption_hint, seed_id),
                    );
                    Ok(())
                }
            }
            Dimension::Ordered(_) => Err(Error::OperationNotPermitted(
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
            Dimension::Unordered(attributes) => attributes
                .remove(attr_name)
                .map(|_| ())
                .ok_or(Error::AttributeNotFound(attr_name.to_string())),

            Dimension::Ordered(_) => Err(Error::OperationNotPermitted(
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
            Dimension::Unordered(attributes) => attributes
                .get_mut(attr_name)
                .map(|attr| attr.write_status = AttributeStatus::DecryptOnly)
                .ok_or(Error::AttributeNotFound(attr_name.to_string())),

            Dimension::Ordered(attributes) => attributes
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
        new_name: &str,
    ) -> Result<(), Error> {
        match self {
            Dimension::Unordered(attributes) => {
                if attributes.contains_key(new_name) {
                    return Err(Error::OperationNotPermitted(
                        "New attribute name is already used in the same dimension".to_string(),
                    ));
                }
                match attributes.remove(attr_name) {
                    Some(attr_params) => {
                        attributes.insert(new_name.to_string(), attr_params);
                        Ok(())
                    }
                    None => Err(Error::AttributeNotFound(attr_name.to_string())),
                }
            }

            Dimension::Ordered(attributes) => {
                if attributes.contains_key(new_name) {
                    return Err(Error::OperationNotPermitted(
                        "New attribute name is already used in the same dimension".to_string(),
                    ));
                }
                match attributes.remove(attr_name) {
                    Some(attr_params) => {
                        attributes.insert(new_name.to_string(), attr_params);
                        Ok(())
                    }
                    None => Err(Error::AttributeNotFound(attr_name.to_string())),
                }
            }
        }
    }

    /// Clears the old rotations of an attribute, keeping only the current ID.
    ///
    /// # Arguments
    ///
    /// * `attr_name` - The name of the attribute to clear old rotations for.
    ///
    /// # Errors
    ///
    /// Returns an error if the attribute is not found.
    pub fn clear_old_attribute_values(&mut self, attr_name: &AttributeName) -> Result<(), Error> {
        match self {
            Dimension::Unordered(attributes) => attributes
                .get_mut(attr_name)
                .map(|attr| attr.clear_old_rotation_values())
                .ok_or(Error::AttributeNotFound(attr_name.to_string())),

            Dimension::Ordered(attributes) => attributes
                .get_mut(attr_name)
                .map(|attr| attr.clear_old_rotation_values())
                .ok_or(Error::AttributeNotFound(attr_name.to_string())),
        }
    }

    /// Returns an iterator over the AttributesParameters and parameters.
    /// If the dimension is ordered, the attributes are returned in order.
    pub fn attributes_properties(&self) -> Box<dyn '_ + Iterator<Item = &AttributeParameters>> {
        match self {
            Dimension::Unordered(attributes) => Box::new(attributes.values()),
            Dimension::Ordered(attributes) => Box::new(attributes.values()),
        }
    }

    /// Returns an iterator over the Attributes names and parameters.
    /// If the dimension is ordered, the attributes are returned in order.
    pub fn iter_attributes(
        &self,
    ) -> Box<dyn '_ + Iterator<Item = (&AttributeName, &AttributeParameters)>> {
        match self {
            Dimension::Unordered(attributes) => Box::new(attributes.iter()),
            Dimension::Ordered(attributes) => Box::new(attributes.iter()),
        }
    }
}
