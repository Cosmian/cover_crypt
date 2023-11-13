use std::{collections::HashMap, fmt::Debug};

use serde::{Deserialize, Serialize};

use super::{
    attribute::{AttributeBuilder, EncryptionHint},
    AttributeStatus,
};
use crate::Error;

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
    pub(crate) current_rotation_value: u32,
    pub(crate) oldest_rotation_value: u32,
    pub(crate) encryption_hint: EncryptionHint,
    pub(crate) write_status: AttributeStatus,
}

impl AttributeParameters {
    /// Creates a `AttributeParameters` with the provided `encryption_hint`
    /// and increments the `seed_id` to generate unique IDs.
    pub fn new(encryption_hint: EncryptionHint) -> Self {
        Self {
            current_rotation_value: 1,
            oldest_rotation_value: 1,
            encryption_hint,
            write_status: AttributeStatus::EncryptDecrypt,
        }
    }

    /// Gets the current rotation of the Attribute.
    pub fn get_current_rotation(&self) -> u32 {
        self.current_rotation_value
    }

    pub fn rotate_current_value(&mut self) {
        self.current_rotation_value += 1;
    }

    pub fn clear_old_rotation_values(&mut self) {
        self.oldest_rotation_value = self.current_rotation_value
    }

    pub fn all_rotation_values(&self) -> impl DoubleEndedIterator<Item = u32> {
        self.oldest_rotation_value..=self.current_rotation_value
    }

    /// Flattens the properties of the `AttributeParameters` into a vector of
    /// tuples where each tuple contains a rotation value, the associated
    /// encryption hint, and the `read_only` flag.
    pub fn flatten_properties(&self) -> Vec<(u32, EncryptionHint, AttributeStatus)> {
        (self.oldest_rotation_value..=self.current_rotation_value)
            .map(|value| (value, self.encryption_hint, self.write_status))
            .collect()
    }
}

type AttributeName = String;
type AttributeId = u64;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
/// A dimension is a space that holds attributes. It can be ordered (an
/// dimension) or unordered (a set).
pub struct Dimension {
    pub order: Option<Vec<AttributeName>>,
    pub attributes: HashMap<AttributeName, AttributeParameters>,
}

impl Dimension {
    /// Creates a new `Dimension` based on the given `DimensionBuilder`,
    /// initializing attributes and order if applicable.
    ///
    /// # Arguments
    ///
    /// * `dim` - The `DimensionBuilder` to base the dimension on.
    /// * `seed_id` - A mutable reference to a seed ID used for generating
    ///   unique IDs for attributes.
    pub fn new(dim: &DimensionBuilder, seed_id: &mut u32) -> Self {
        /*let attributes_mapping = dim
            .attributes_properties
            .iter()
            .map(|attr| {
                (
                    attr.name.clone(),
                    AttributeParameters::new(attr.encryption_hint),
                )
            })
            .collect();

        match dim.hierarchical {
            true => Self {
                order: Some(
                    dim.attributes_properties
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
        }*/
        //*seed_id += 1;
        //let attr_id = *seed_id;
        let id_mapping: HashMap<AttributeName, AttributeId> =
            HashMap::with_capacity(dim.attributes_properties.len());

        let attributes_mapping: HashMap<AttributeId, AttributeParameters> =
            HashMap::with_capacity(dim.attributes_properties.len());

        for x in dim.attributes_properties.iter() {
            todo!()
        }
        todo!()
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
        match self.attributes.get_mut(attr_name) {
            Some(attr) => {
                attr.rotate_current_value();
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
                "Hierarchical dimension are immutable".to_string(),
            ))
        } else if self.attributes.contains_key(attr_name) {
            Err(Error::OperationNotPermitted(
                "Attribute already in dimension".to_string(),
            ))
        } else {
            self.attributes
                .insert(attr_name.clone(), AttributeParameters::new(encryption_hint));
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
                "Hierarchical dimension are immutable".to_string(),
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
    /// dimension or if the attribute is not found.
    pub fn rename_attribute(
        &mut self,
        attr_name: &AttributeName,
        new_name: &str,
    ) -> Result<(), Error> {
        if self.attributes.contains_key(new_name) {
            return Err(Error::OperationNotPermitted(
                "New attribute name is already used in the same dimension".to_string(),
            ));
        }
        match self.attributes.remove(attr_name) {
            Some(attr_params) => {
                self.attributes.insert(new_name.to_string(), attr_params);
                if let Some(order) = self.order.as_mut() {
                    order.iter_mut().for_each(|name| {
                        if name == attr_name {
                            *name = new_name.to_string()
                        }
                    })
                }
                Ok(())
            }
            None => Err(Error::AttributeNotFound(attr_name.to_string())),
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
        self.attributes
            .get_mut(attr_name)
            .map(|attr| attr.clear_old_rotation_values())
            .ok_or(Error::AttributeNotFound(attr_name.to_string()))
    }

    /// Returns the list of Attributes of this Policy.
    /// If the dimension is ordered, the attributes are returned in order.
    pub fn attributes_properties(&self) -> Vec<(String, EncryptionHint)> {
        if let Some(ordered_attrs) = &self.order {
            ordered_attrs
                .iter()
                .map(|name| {
                    (
                        name.to_string(),
                        self.attributes.get(name).unwrap().encryption_hint,
                    )
                })
                .collect()
        } else {
            self.attributes
                .iter()
                .map(|(name, attr_params)| (name.to_string(), attr_params.encryption_hint))
                .collect()
        }
    }
}
