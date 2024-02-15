use std::collections::HashMap;

use serde_json::Value;

use super::{
    AttributeParameters, Dimension, DimensionBuilder, EncryptionHint, LegacyPolicy, Policy,
    PolicyV1, PolicyVersion,
};
use crate::Error;

impl Policy {
    /// Converts the given bytes into a Policy, supports legacy policy versions.
    pub fn parse_and_convert(bytes: &[u8]) -> Result<Self, Error> {
        let json_policy: Value =
            serde_json::from_slice(bytes).map_err(Error::DeserializationError)?;

        if let Some(policy_version) = json_policy.get("version") {
            match serde_json::from_value::<PolicyVersion>(policy_version.clone()) {
                Ok(PolicyVersion::V1) => Ok(serde_json::from_slice::<PolicyV1>(bytes)
                    .map_err(Error::DeserializationError)?
                    .into()),
                Ok(PolicyVersion::V2) => {
                    serde_json::from_value::<Self>(json_policy).map_err(Error::DeserializationError)
                }
                Err(e) => Err(Error::DeserializationError(e)),
            }
        } else {
            // Legacy Policy
            Ok(serde_json::from_slice::<LegacyPolicy>(bytes)
                .map_err(Error::DeserializationError)?
                .into())
        }
    }
}

impl TryFrom<&[u8]> for Policy {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::parse_and_convert(bytes)
    }
}

impl TryFrom<&Policy> for Vec<u8> {
    type Error = Error;

    fn try_from(policy: &Policy) -> Result<Self, Self::Error> {
        serde_json::to_vec(policy).map_err(Self::Error::DeserializationError)
    }
}

impl TryFrom<HashMap<String, Vec<String>>> for Policy {
    type Error = Error;

    /// Create a policy object from policy specifications
    ///
    /// The policy specifications must be passed as a mapping object:
    /// ```json
    ///     {
    ///        "Security Level::<": [
    ///            "Protected",
    ///            "Confidential",
    ///            "Top Secret::+"
    ///        ],
    ///        "Department": [
    ///            "R&D",
    ///            "HR",
    ///            "MKG",
    ///            "FIN"
    ///        ]
    ///    }
    /// ```
    fn try_from(value: HashMap<String, Vec<String>>) -> Result<Self, Self::Error> {
        let mut policy = Self::new();

        for (axis, attributes) in &value {
            // Split the axis into axis name and hierarchy flag
            let (axis_name, hierarchical) = match axis.split_once("::") {
                Some((name, specs)) => {
                    // If the axis contains the hierarchy flag, parse it
                    let hierarchical = match specs {
                        "<" => true,
                        x => {
                            return Err(Error::ConversionFailed(format!("unknown axis spec {x}")));
                        }
                    };
                    (name, hierarchical)
                }
                // If there is no hierarchy flag, assume the axis is non-hierarchical
                None => (axis.as_str(), false),
            };

            let mut attributes_properties: Vec<(&str, EncryptionHint)> =
                Vec::with_capacity(attributes.len());

            // Parse each attribute and its encryption hint
            for att in attributes {
                let (att_name, encryption_hint) = match att.split_once("::") {
                    Some((name, specs)) => {
                        let encryption_hint = match specs {
                            "+" => EncryptionHint::Hybridized,
                            x => {
                                return Err(Error::ConversionFailed(format!(
                                    "unknown attribute spec {x}"
                                )));
                            }
                        };
                        (name, encryption_hint)
                    }
                    // If there is no encryption hint, assume the attribute is non-hybridized
                    None => (att.as_str(), EncryptionHint::Classic),
                };
                attributes_properties.push((att_name, encryption_hint));
            }

            // Add the axis to the policy
            policy.add_dimension(DimensionBuilder::new(
                axis_name,
                attributes_properties,
                hierarchical,
            ))?;
        }
        Ok(policy)
    }
}

fn convert_attribute(attribute: (String, AttributeParameters)) -> String {
    let (name, params) = attribute;
    match params.get_encryption_hint() {
        EncryptionHint::Hybridized => name + "::+",
        EncryptionHint::Classic => name,
    }
}

impl TryFrom<Policy> for HashMap<String, Vec<String>> {
    type Error = Error;

    fn try_from(policy: Policy) -> Result<Self, Self::Error> {
        let mut result: Self = Self::with_capacity(policy.dimensions.len());

        for (dim_name, dimension) in policy.dimensions {
            let (dim_full_name, attributes_list) = match dimension {
                Dimension::Unordered(attributes) => {
                    let attributes_list: Vec<String> =
                        attributes.into_iter().map(convert_attribute).collect();
                    (dim_name, attributes_list)
                }
                Dimension::Ordered(attributes) => {
                    let dim_name = dim_name + "::<";
                    let attributes_list: Vec<String> =
                        attributes.into_iter().map(convert_attribute).collect();
                    (dim_name, attributes_list)
                }
            };
            result.insert(dim_full_name, attributes_list);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        abe_policy::{Attribute, Dimension, EncryptionHint, Policy},
        Error,
    };
    #[test]
    pub fn test_create_policy_from_spec() -> Result<(), Error> {
        let json = r#"
    {
        "Security Level::<": [
            "Protected",
            "Confidential",
            "Top Secret::+"
        ],
        "Department": [
            "R&D",
            "HR",
            "MKG",
            "FIN"
        ]
    }
    "#;

        let policy_json: HashMap<String, Vec<String>> = serde_json::from_str(json).unwrap();
        let policy: Policy = policy_json.try_into()?;
        assert_eq!(policy.dimensions.len(), 2);
        assert!(matches!(
            policy.dimensions.get("Security Level").unwrap(),
            Dimension::Ordered(_)
        ));
        assert!(matches!(
            policy.dimensions.get("Department").unwrap(),
            Dimension::Unordered(_)
        ));
        assert_eq!(
            policy
                .dimensions
                .get("Security Level")
                .unwrap()
                .attributes()
                .count(),
            3
        );
        assert_eq!(
            policy
                .get_attribute_hybridization_hint(&Attribute::new("Department", "MKG"))
                .unwrap(),
            EncryptionHint::Classic
        );
        assert_eq!(
            policy
                .get_attribute_hybridization_hint(&Attribute::new("Security Level", "Protected"))
                .unwrap(),
            EncryptionHint::Classic
        );
        assert_eq!(
            policy
                .get_attribute_hybridization_hint(&Attribute::new("Security Level", "Top Secret"))
                .unwrap(),
            EncryptionHint::Hybridized
        );

        Ok(())
    }
}
