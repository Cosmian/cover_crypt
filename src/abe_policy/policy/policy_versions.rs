use std::{collections::HashMap, fmt::Debug};

use serde::{Deserialize, Serialize};

use crate::abe_policy::{
    policy::policy_v2::PolicyV2, AttributeParameters, AttributeStatus, Dimension, EncryptionHint,
    QualifiedAttribute,
};

use super::PolicyVersion;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PolicyV1AttributeParameters {
    values: Vec<u32>,
    encryption_hint: EncryptionHint,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct OldPolicyAxisParameters {
    attribute_names: Vec<String>,
    is_hierarchical: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PolicyV1 {
    /// Version number
    version: PolicyVersion,
    /// Last value taken by the attribute.
    last_attribute_value: u32,
    /// Maximum attribute value. Defines a maximum number of attribute
    /// creations (revocations + addition).
    max_attribute_creations: u32,
    /// Policy axes: maps axes name to the list of associated attribute names
    /// and a boolean defining whether or not this axis is hierarchical.
    axes: HashMap<String, OldPolicyAxisParameters>,
    /// Maps an attribute to its values and its hybridization hint.
    attributes: HashMap<QualifiedAttribute, PolicyV1AttributeParameters>,
}

impl From<PolicyV1> for PolicyV2 {
    fn from(val: PolicyV1) -> Self {
        let mut dimensions = HashMap::with_capacity(val.axes.len());
        for (axis_name, axis_params) in val.axes {
            let attributes = val
                .attributes
                .clone()
                .into_iter()
                .filter(|(attr, _)| attr.dimension == axis_name)
                .map(|(attr, attr_params)| {
                    (
                        attr.name,
                        AttributeParameters {
                            id: *attr_params.values.first().unwrap(),
                            encryption_hint: attr_params.encryption_hint,
                            write_status: AttributeStatus::EncryptDecrypt,
                        },
                    )
                });
            dimensions.insert(
                axis_name.clone(),
                match axis_params.is_hierarchical {
                    true => Dimension::Ordered(attributes.collect()),
                    false => Dimension::Unordered(attributes.collect()),
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
    last_attribute_value: u32,
    /// Maximum attribute value. Defines a maximum number of attribute
    /// creations (revocations + addition).
    max_attribute_creations: u32,
    /// Policy axes: maps axes name to the list of associated attribute names
    /// and a boolean defining whether or not this axis is hierarchical.
    axes: HashMap<String, OldPolicyAxisParameters>,
    /// Maps an attribute to its values and its hybridization hint.
    attributes: HashMap<QualifiedAttribute, Vec<u32>>,
}

impl From<LegacyPolicy> for PolicyV2 {
    fn from(val: LegacyPolicy) -> Self {
        let mut dimensions = HashMap::with_capacity(val.axes.len());
        for (axis_name, axis_params) in val.axes {
            let attributes = val
                .attributes
                .clone()
                .into_iter()
                .filter(|(attr, _)| attr.dimension == axis_name)
                .map(|(attr, values)| {
                    (
                        attr.name,
                        AttributeParameters {
                            id: *values.first().unwrap(),
                            encryption_hint: EncryptionHint::Classic,
                            write_status: AttributeStatus::EncryptDecrypt,
                        },
                    )
                });
            dimensions.insert(
                axis_name.clone(),
                match axis_params.is_hierarchical {
                    true => Dimension::Ordered(attributes.collect()),
                    false => Dimension::Unordered(attributes.collect()),
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
