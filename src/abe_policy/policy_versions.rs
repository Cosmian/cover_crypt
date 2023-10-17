use std::{collections::HashMap, fmt::Debug};

use serde::{Deserialize, Serialize};

use super::{
    Attribute, AttributeParameters, AttributeStatus, Dimension, EncryptionHint, PolicyVersion,
};

/// Current policy version
///
/// A policy is a set of policy axes. A fixed number of attribute creations
/// (revocations + additions) is allowed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PolicyV2 {
    /// Version number
    pub version: PolicyVersion,
    /// Last value taken by the attribute.
    pub(crate) last_attribute_value: u32,

    /// Policy axes: maps axes name to the list of associated attribute names
    /// and a boolean defining whether or not this dim is hierarchical.
    pub dimensions: HashMap<String, Dimension>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PolicyV1AttributeParameters {
    pub values: Vec<u32>,
    pub encryption_hint: EncryptionHint,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct OldPolicyAxisParameters {
    pub attribute_names: Vec<String>,
    pub is_hierarchical: bool,
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
    pub axes: HashMap<String, OldPolicyAxisParameters>,
    /// Maps an attribute to its values and its hybridization hint.
    pub attributes: HashMap<Attribute, PolicyV1AttributeParameters>,
}

impl From<PolicyV1> for PolicyV2 {
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
        Self {
            version: PolicyVersion::V2,
            last_attribute_value: val.last_attribute_value,
            dimensions,
        }
    }
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
    pub axes: HashMap<String, OldPolicyAxisParameters>,
    /// Maps an attribute to its values and its hybridization hint.
    pub attributes: HashMap<Attribute, Vec<u32>>,
}

impl From<LegacyPolicy> for PolicyV2 {
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
        Self {
            version: PolicyVersion::V2,
            last_attribute_value: val.last_attribute_value,
            dimensions,
        }
    }
}
