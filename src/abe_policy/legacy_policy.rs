use std::{collections::HashMap, fmt::Debug};

use serde::{Deserialize, Serialize};

use super::{
    Attribute, AttributeParameters, AttributeStatus, Dimension, EncryptionHint, Policy,
    PolicyVersion,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
//#[deprecated]
pub struct PolicyAxesParameters {
    pub attribute_names: Vec<String>,
    pub is_hierarchical: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LegacyPolicy {
    /// Last value taken by the attribute.
    pub(crate) last_attribute_value: u32,
    /// Maximum attribute value. Defines a maximum number of attribute
    /// creations (revocations + addition).
    pub max_attribute_creations: u32,
    /// Policy axes: maps axes name to the list of associated attribute names
    /// and a boolean defining whether or not this axis is hierarchical.
    pub axes: HashMap<String, PolicyAxesParameters>,
    /// Maps an attribute to its values and its hybridization hint.
    pub attributes: HashMap<Attribute, Vec<u32>>,
}

impl From<LegacyPolicy> for Policy {
    fn from(val: LegacyPolicy) -> Self {
        let mut dimensions = HashMap::with_capacity(val.axes.len());
        for (axis_name, axis_params) in val.axes {
            dimensions.insert(
                axis_name.clone(),
                Dimension {
                    order: if axis_params.is_hierarchical {
                        Some(axis_params.attribute_names)
                    } else {
                        None
                    },
                    attributes: val
                        .attributes
                        .clone()
                        .iter()
                        .filter(|(attr, _)| attr.dimension == axis_name)
                        .map(|(attr, values)| {
                            (
                                attr.name.clone(),
                                AttributeParameters {
                                    id: values.first().copied().expect(
                                        "Policy should have at least one value per attribute",
                                    ),
                                    rotation_values: values.clone(),
                                    encryption_hint: EncryptionHint::Classic,
                                    write_status: AttributeStatus::EncryptDecrypt,
                                },
                            )
                        })
                        .collect(),
                },
            );
        }
        Policy {
            version: PolicyVersion::V2,
            last_attribute_id: val.last_attribute_value,
            dimensions,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PolicyV1AttributeParameters {
    pub values: Vec<u32>,
    pub encryption_hint: EncryptionHint,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PolicyV1 {
    /// Version number
    pub version: PolicyVersion,
    /// Last value taken by the attribute.
    pub(crate) last_attribute_value: u32,
    /// Maximum attribute value. Defines a maximum number of attribute
    /// creations (revocations + addition).
    pub max_attribute_creations: u32,
    /// Policy axes: maps axes name to the list of associated attribute names
    /// and a boolean defining whether or not this axis is hierarchical.
    pub axes: HashMap<String, PolicyAxesParameters>,
    /// Maps an attribute to its values and its hybridization hint.
    pub attributes: HashMap<Attribute, PolicyV1AttributeParameters>,
}

impl From<PolicyV1> for Policy {
    fn from(val: PolicyV1) -> Self {
        let mut dimensions = HashMap::with_capacity(val.axes.len());
        for (axis_name, axis_params) in val.axes {
            dimensions.insert(
                axis_name.clone(),
                Dimension {
                    order: if axis_params.is_hierarchical {
                        Some(axis_params.attribute_names)
                    } else {
                        None
                    },
                    attributes: val
                        .attributes
                        .clone()
                        .iter()
                        .filter(|(attr, _)| attr.dimension == axis_name)
                        .map(|(attr, attr_params)| {
                            (
                                attr.name.clone(),
                                AttributeParameters {
                                    id: attr_params.values.first().copied().expect(
                                        "Policy should have at least one value per attribute",
                                    ),
                                    rotation_values: attr_params.values.clone(),
                                    encryption_hint: attr_params.encryption_hint,
                                    write_status: AttributeStatus::EncryptDecrypt,
                                },
                            )
                        })
                        .collect(),
                },
            );
        }
        Policy {
            version: PolicyVersion::V2,
            last_attribute_id: val.last_attribute_value,
            dimensions,
        }
    }
}
