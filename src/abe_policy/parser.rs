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
    /// The policy specifications format is as follow:
    /// ```text
    /// policy: { dimension_list }
    /// dimension_list: dimension_entry | dimension_entry, dimension_list
    /// dimension_entry: dimension_name: [ attribute_list ]
    /// dimension_name: "NAME::dimension_modifier"
    /// dimension_modifier: "<" | ""        # ordered | unordered dimension
    /// attribute_list: attribute | attribute, attribute_list
    /// attribute: "NAME::attribute_modifier"
    /// attribute_modifier: "+" | ""        # hybridized | classic encryption
    /// ```
    ///
    /// Example:
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

        for (dimension, attributes) in &value {
            // Split the dimension into name and hierarchy flag
            let (dim_name, hierarchical) = match dimension.split_once("::") {
                Some((name, specs)) => {
                    // If the dimension contains the hierarchy flag, parse it
                    let hierarchical = match specs {
                        "<" => true,
                        x => {
                            return Err(Error::ConversionFailed(format!(
                                "invalid specification '{x}' for dimension '{name}'"
                            )));
                        }
                    };
                    (name, hierarchical)
                }
                // If there is no hierarchy flag, assume the dimension is non-hierarchical
                None => (dimension.as_str(), false),
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
                                    "invalid specification '{x}' for attribute \
                                     '{dim_name}::{name}'"
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

            // Add the dimension to the policy
            policy.add_dimension(DimensionBuilder::new(
                dim_name,
                attributes_properties,
                hierarchical,
            ))?;
        }
        Ok(policy)
    }
}

impl TryFrom<Policy> for HashMap<String, Vec<String>> {
    type Error = Error;

    fn try_from(policy: Policy) -> Result<Self, Self::Error> {
        fn convert_attribute(attribute: (String, AttributeParameters)) -> String {
            let (name, params) = attribute;
            match params.get_encryption_hint() {
                EncryptionHint::Hybridized => name + "::+",
                EncryptionHint::Classic => name,
            }
        }
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
        abe_policy::{Attribute, Dimension, DimensionBuilder, EncryptionHint, Policy},
        Error,
    };

    #[test]
    pub fn test_parse_policy_from_bytes() -> Result<(), Error> {
        let mut policy = Policy::new();
        policy.add_dimension(DimensionBuilder::new(
            "Security Level",
            vec![
                ("Protected", EncryptionHint::Classic),
                ("Confidential", EncryptionHint::Classic),
                ("Top Secret", EncryptionHint::Hybridized),
            ],
            true,
        ))?;
        policy.add_dimension(DimensionBuilder::new(
            "Department",
            vec![
                ("R&D", EncryptionHint::Classic),
                ("HR", EncryptionHint::Classic),
                ("MKG", EncryptionHint::Classic),
                ("FIN", EncryptionHint::Classic),
            ],
            false,
        ))?;
        let serialized_policy = <Vec<u8>>::try_from(&policy)?;
        let parsed_policy = Policy::parse_and_convert(&serialized_policy)?;
        // check policy size
        assert_eq!(parsed_policy.attributes().len(), policy.attributes().len());

        // check order
        let orig_ordered_dim = policy.dimensions.get("Security Level").unwrap();
        let parsed_ordered_dim = parsed_policy.dimensions.get("Security Level").unwrap();
        assert_eq!(
            parsed_ordered_dim.get_attributes_name().collect::<Vec<_>>(),
            orig_ordered_dim.get_attributes_name().collect::<Vec<_>>(),
        );

        Ok(())
    }

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
