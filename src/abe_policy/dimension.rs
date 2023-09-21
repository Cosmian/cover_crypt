use std::{collections::HashMap, fmt::Debug, vec};

use serde::{Deserialize, Serialize};

use super::{
    attribute::{AxisAttributeProperties, EncryptionHint},
    AttributeStatus,
};
use crate::Error;

///
/// Defines a policy axis by its name and its underlying attribute properties.
/// An attribute property defines its name and a hint about whether hybridized
/// encryption should be used for it (hint set to `true` if this is the case).
///
/// If `hierarchical` is set to `true`, we assume a lexicographical order based
/// on the attribute name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAxis {
    /// Axis name
    pub name: String,
    /// Names of the axis attributes and hybridized encryption hints
    pub attributes_properties: Vec<AxisAttributeProperties>,
    /// `true` if the axis is hierarchical
    pub hierarchical: bool,
}

impl PolicyAxis {
    /// Generates a new policy axis with the given name and attribute names.
    /// A hierarchical axis enforces order between its attributes.
    ///
    /// - `name`                    : axis name
    /// - `attribute_properties`    : axis attribute properties
    /// - `hierarchical`            : set to `true` if the axis is hierarchical
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
                .map(|(axis_name, encryption_hint)| AxisAttributeProperties {
                    name: axis_name.to_string(),
                    encryption_hint,
                })
                .collect(),
            hierarchical,
        }
    }

    /// Returns the number of attributes belonging to this axis.
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
pub struct PolicyAttributesParameters {
    pub values: Vec<u32>,
    pub encryption_hint: EncryptionHint,
}

pub type AttributeId = u32;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
/// Represents attribute's data inside a Policy.
pub struct PolicyAttribute {
    pub id: AttributeId,
    pub rotation_values: Vec<u32>,
    pub encryption_hint: EncryptionHint,
    pub write_status: AttributeStatus,
}

impl PolicyAttribute {
    /// Creates a `PolicyAttribute` with the provided `encryption_hint`
    /// and increments the `seed_id` to generate unique IDs.
    pub fn new(encryption_hint: EncryptionHint, seed_id: &mut u32) -> Self {
        *seed_id += 1;
        Self {
            id: *seed_id,
            rotation_values: vec![*seed_id],
            encryption_hint,
            write_status: AttributeStatus::EncryptDecrypt,
        }
    }

    /// Gets the current ID.
    pub fn get_current_rotation(&self) -> u32 {
        self.rotation_values
            .last()
            .copied()
            .expect("Attribute should always have at least one value")
    }

    /// Flattens the properties of the `PolicyAttribute` into a vector of tuples
    /// where each tuple contains an ID, the associated encryption hint, and the
    /// `read_only` flag.
    pub fn flatten_properties(&self) -> Vec<(u32, EncryptionHint, AttributeStatus)> {
        self.rotation_values
            .iter()
            .map(|&value| (value, self.encryption_hint, self.write_status))
            .collect()
    }
}

type AttributeName = String;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
/// A dimension is a space that holds attributes. It can be ordered (an axis) or
/// unordered (a set).
pub struct Dimension {
    pub order: Option<Vec<AttributeName>>,
    pub attributes: HashMap<AttributeName, PolicyAttribute>,
}

impl Dimension {
    /// Creates a new `Dimension` based on the given `PolicyAxis`, initializing
    /// attributes and order if applicable.
    ///
    /// # Arguments
    ///
    /// * `axis` - The `PolicyAxis` to base the dimension on.
    /// * `seed_id` - A mutable reference to a seed ID used for generating
    ///   unique IDs for attributes.
    pub fn new(axis: &PolicyAxis, seed_id: &mut u32) -> Self {
        let attributes_mapping = axis
            .attributes_properties
            .iter()
            .map(|attr| {
                (
                    attr.name.clone(),
                    PolicyAttribute::new(attr.encryption_hint, seed_id),
                )
            })
            .collect();

        match axis.hierarchical {
            true => Self {
                order: Some(
                    axis.attributes_properties
                        .iter()
                        .map(|attr| attr.name.clone())
                        .collect(),
                ),
                attributes: attributes_mapping,
            },
            false => Self {
                order: None,
                attributes: attributes_mapping,
            },
        }
    }

    /// Rotates the attribute with the given name by incrementing its ID.
    ///
    /// # Arguments
    ///
    /// * `attr_name` - The name of the attribute to rotate.
    /// * `seed_id` - A seed used for generating the new rotation ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the attribute with the specified name is not found.
    pub fn rotate_attribute(
        &mut self,
        attr_name: &AttributeName,
        seed_id: &mut u32,
    ) -> Result<(), Error> {
        match self.attributes.get_mut(attr_name) {
            Some(attr) => {
                *seed_id += 1;
                attr.rotation_values.push(*seed_id);
                Ok(())
            }
            None => Err(Error::AttributeNotFound(attr_name.to_string())),
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
        if self.order.is_some() {
            Err(Error::OperationNotPermitted(
                "Hierarchical axis are immutable".to_string(),
            ))
        } else if self.attributes.contains_key(attr_name) {
            Err(Error::OperationNotPermitted(
                "Attribute already in axis".to_string(),
            ))
        } else {
            self.attributes.insert(
                attr_name.clone(),
                PolicyAttribute::new(encryption_hint, seed_id),
            );
            Ok(())
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
        if self.order.is_some() {
            Err(Error::OperationNotPermitted(
                "Hierarchical axis are immutable".to_string(),
            ))
        } else {
            self.attributes
                .remove(attr_name)
                .map(|_| ())
                .ok_or(Error::AttributeNotFound(attr_name.to_string()))
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
        self.attributes
            .get_mut(attr_name)
            .map(|attr| attr.write_status = AttributeStatus::DecryptOnly)
            .ok_or(Error::AttributeNotFound(attr_name.to_string()))
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
    /// axis or if the attribute is not found.
    pub fn rename_attribute(
        &mut self,
        attr_name: &AttributeName,
        new_name: &str,
    ) -> Result<(), Error> {
        if self.attributes.contains_key(new_name) {
            Err(Error::OperationNotPermitted(
                "New attribute name is already used in the same axis".to_string(),
            ))
        } else {
            match self.attributes.remove(attr_name) {
                Some(attr_params) => {
                    self.attributes.insert(new_name.to_string(), attr_params);
                    Ok(())
                }
                None => Err(Error::AttributeNotFound(attr_name.to_string())),
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
    pub fn clear_old_rotations(&mut self, attr_name: &AttributeName) -> Result<(), Error> {
        self.attributes
            .get_mut(attr_name)
            .map(|attr| {
                let current_val = attr.get_current_rotation();
                attr.rotation_values.retain(|val| val == &current_val);
            })
            .ok_or(Error::AttributeNotFound(attr_name.to_string()))
    }
}
