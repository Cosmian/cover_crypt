use std::{collections::HashMap, fmt::Debug, vec};

use serde::{Deserialize, Serialize};

use crate::Error;

use super::attribute::{AxisAttributeProperties, EncryptionHint};

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
#[deprecated]
pub struct PolicyAxesParameters {
    pub attribute_names: Vec<String>,
    pub is_hierarchical: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[deprecated]
pub struct PolicyAttributesParameters {
    pub values: Vec<u32>,
    pub encryption_hint: EncryptionHint,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
/// An attribute is used to tag a dimensional element.
pub struct PolicyAttribute {
    pub ids: Vec<u32>,
    pub encryption_hint: EncryptionHint,
    pub read_only: bool,
}

impl PolicyAttribute {
    pub fn new(encryption_hint: EncryptionHint, seed_id: &mut u32) -> Self {
        *seed_id += 1;
        Self {
            encryption_hint,
            ids: vec![*seed_id],
            read_only: false,
        }
    }

    pub fn get_current_id(&self) -> u32 {
        self.ids
            .last()
            .copied()
            .expect("Attribute should always have at least one id")
    }

    pub fn flatten_values_encryption_hint(&self) -> Vec<(u32, EncryptionHint)> {
        self.ids
            .iter()
            .map(|&value| (value, self.encryption_hint))
            .collect()
    }

    pub fn flatten_properties(&self) -> Vec<(u32, EncryptionHint, bool)> {
        self.ids
            .iter()
            .map(|&value| (value, self.encryption_hint, self.read_only))
            .collect()
    }
}

type AttributeName = String;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
/// A dimension is a space that holds attributes. It can be ordered (an axis) or unordered (a set).
pub struct Dimension {
    pub order: Option<Vec<AttributeName>>, // store HashSet PolicyAttribute and Vec AttrName
    pub attributes: HashMap<AttributeName, PolicyAttribute>,
}

// Implement some getter and setters to manipulate this `enum`.
impl Dimension {
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
            true => Dimension {
                order: Some(
                    axis.attributes_properties
                        .iter()
                        .map(|attr| attr.name.clone())
                        .collect(),
                ),
                attributes: attributes_mapping,
            },
            false => Dimension {
                order: None,
                attributes: attributes_mapping,
            },
        }
    }

    pub fn rotate_attribute(
        &mut self,
        attr_name: &AttributeName,
        seed_id: &mut u32,
    ) -> Result<(), Error> {
        match self.attributes.get_mut(attr_name) {
            Some(attr) => {
                *seed_id += 1;
                attr.ids.push(*seed_id);
                Ok(())
            }
            None => Err(Error::AttributeNotFound(attr_name.to_string())),
        }
    }

    pub fn add_attribute(
        &mut self,
        attr: &AxisAttributeProperties,
        seed_id: &mut u32,
    ) -> Result<(), Error> {
        if self.order.is_some() {
            Err(Error::OperationNotPermitted(
                "Hierarchical axis are immutable".to_string(),
            ))
        } else if self.attributes.contains_key(&attr.name) {
            Err(Error::OperationNotPermitted(
                "Attribute already in axis".to_string(),
            ))
        } else {
            self.attributes.insert(
                attr.name.clone(),
                PolicyAttribute::new(attr.encryption_hint, seed_id),
            );
            Ok(())
        }
    }

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

    pub fn deactivate_attribute(&mut self, attr_name: &AttributeName) -> Result<(), Error> {
        self.attributes
            .get_mut(attr_name)
            .map(|attr| attr.read_only = true)
            .ok_or(Error::AttributeNotFound(attr_name.to_string()))
    }

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
}
