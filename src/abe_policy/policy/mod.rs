use serde::{Deserialize, Serialize};

//mod parser;
//mod policy_v2;
mod access_structure;
//mod policy_versions;

pub use access_structure::AccessStructure;

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
    V1,
    V2,
    V3,
}

impl Default for Version {
    fn default() -> Self {
        Self::V3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abe_policy::{gen_structure, EncryptionHint, QualifiedAttribute};

    #[test]
    fn test_edit_anarchic_attributes() {
        let mut structure = AccessStructure::default();
        gen_structure(&mut structure).unwrap();

        assert_eq!(structure.attributes().count(), 9);

        // Try renaming Research to already used name MKG
        assert!(structure
            .rename_attribute(
                &QualifiedAttribute::new("Department", "R&D"),
                "MKG".to_string(),
            )
            .is_err());

        // Rename R&D to Research
        assert!(structure
            .rename_attribute(
                &QualifiedAttribute::new("Department", "R&D"),
                "Research".to_string(),
            )
            .is_ok());

        let order: Vec<_> = structure
            .attributes()
            .filter(|a| a.dimension.as_str() == "Security Level")
            .map(|a| a.name)
            .collect();

        assert!(order.len() == 5);

        // Add new attribute Sales
        let new_attr = QualifiedAttribute::new("Department", "Sales");
        assert!(structure
            .add_attribute(new_attr.clone(), EncryptionHint::Classic, None)
            .is_ok());
        assert_eq!(structure.attributes().count(), 10);

        // Try adding already existing attribute HR
        let duplicate_attr = QualifiedAttribute::new("Department", "HR");
        assert!(structure
            .add_attribute(duplicate_attr, EncryptionHint::Classic, None)
            .is_err());

        // Try adding attribute to non existing dimension
        let missing_dimension = QualifiedAttribute::new("Missing", "dimension");
        assert!(structure
            .add_attribute(missing_dimension.clone(), EncryptionHint::Classic, None)
            .is_err());

        // Remove research attribute
        let delete_attr = QualifiedAttribute::new("Department", "Research");
        structure.del_attribute(&delete_attr).unwrap();
        assert_eq!(structure.attributes().count(), 9);

        // Duplicate remove
        assert!(structure.del_attribute(&delete_attr).is_err());

        // Missing dimension remove
        assert!(structure.del_attribute(&missing_dimension).is_err());

        // Remove all attributes from a dimension
        structure.del_attribute(&new_attr).unwrap();
        structure
            .del_attribute(&QualifiedAttribute::new("Department", "HR"))
            .unwrap();
        structure
            .del_attribute(&QualifiedAttribute::new("Department", "MKG"))
            .unwrap();

        structure.del_dimension("Department").unwrap();

        assert_eq!(structure.dimensions().count(), 1);

        // Add new dimension
        structure.add_anarchy("DimensionTest".to_string()).unwrap();
        structure
            .add_attribute(
                QualifiedAttribute::new("DimensionTest", "Attr1"),
                EncryptionHint::Classic,
                None,
            )
            .unwrap();
        structure
            .add_attribute(
                QualifiedAttribute::new("DimensionTest", "Attr2"),
                EncryptionHint::Classic,
                None,
            )
            .unwrap();
        assert_eq!(structure.dimensions().count(), 2);

        //// Remove the new dimension
        structure.del_dimension("DimensionTest").unwrap();
        assert_eq!(structure.dimensions().count(), 1);

        //// Try removing non existing dimension
        assert!(structure.del_dimension("MissingDim").is_err());
    }

    #[test]
    fn test_edit_hierarchic_attributes() {
        let mut structure = AccessStructure::default();
        gen_structure(&mut structure).unwrap();

        assert_eq!(
            structure
                .attributes()
                .filter(|a| a.dimension == "Security Level")
                .collect::<Vec<_>>(),
            vec![
                QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "Protected".to_string(),
                },
                QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "Low Secret".to_string(),
                },
                QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "Medium Secret".to_string(),
                },
                QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "High Secret".to_string(),
                },
                QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "Top Secret".to_string(),
                },
            ]
        );

        // Rename ordered dimension
        assert!(structure
            .rename_attribute(
                &QualifiedAttribute::new("Security Level", "Protected"),
                "Detcetorp".to_string(),
            )
            .is_ok());

        let order = structure.attributes().map(|q| q.name).collect::<Vec<_>>();
        assert!(order.contains(&"Detcetorp".to_string()));
        assert!(!order.contains(&"Protected".to_string()));

        //// Try modifying hierarchical dimension
        structure
            .del_attribute(&QualifiedAttribute::new("Security Level", "Detcetorp"))
            .unwrap();

        structure
            .add_attribute(
                QualifiedAttribute::new("Security Level", "After Medium"),
                EncryptionHint::Classic,
                Some("Medium Secret"),
            )
            .unwrap();

        assert_eq!(
            structure
                .attributes()
                .filter(|a| a.dimension == "Security Level")
                .collect::<Vec<_>>(),
            vec![
                QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "Low Secret".to_string(),
                },
                QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "Medium Secret".to_string(),
                },
                QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "After Medium".to_string(),
                },
                QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "High Secret".to_string(),
                },
                QualifiedAttribute {
                    dimension: "Security Level".to_string(),
                    name: "Top Secret".to_string(),
                },
            ]
        );
        //// Removing a hierarchical dimension is permitted
        structure.del_dimension("Security Level").unwrap();
    }
}
