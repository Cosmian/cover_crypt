use crate::{Error, abe_policy::AccessStructure};

use super::EncryptionHint;

pub fn gen_structure(policy: &mut AccessStructure, complete: bool) -> Result<(), Error> {
    policy.add_hierarchy("SEC".to_string())?;

    policy.add_attribute(
        crate::abe_policy::QualifiedAttribute {
            dimension: "SEC".to_string(),
            name: "LOW".to_string(),
        },
        EncryptionHint::Classic,
        None,
    )?;
    policy.add_attribute(
        crate::abe_policy::QualifiedAttribute {
            dimension: "SEC".to_string(),
            name: "TOP".to_string(),
        },
        EncryptionHint::Hybridized,
        Some("LOW"),
    )?;

    policy.add_anarchy("DPT".to_string())?;
    [
        ("RD", EncryptionHint::Classic),
        ("HR", EncryptionHint::Classic),
        ("MKG", EncryptionHint::Classic),
        ("FIN", EncryptionHint::Classic),
        ("DEV", EncryptionHint::Classic),
    ]
    .into_iter()
    .try_for_each(|(attribute, hint)| {
        policy.add_attribute(
            crate::abe_policy::QualifiedAttribute {
                dimension: "DPT".to_string(),
                name: attribute.to_string(),
            },
            hint,
            None,
        )
    })?;

    if complete {
        policy.add_anarchy("CTR".to_string())?;
        [
            ("EN", EncryptionHint::Classic),
            ("DE", EncryptionHint::Classic),
            ("IT", EncryptionHint::Classic),
            ("FR", EncryptionHint::Classic),
            ("SP", EncryptionHint::Classic),
        ]
        .into_iter()
        .try_for_each(|(attribute, hint)| {
            policy.add_attribute(
                crate::abe_policy::QualifiedAttribute {
                    dimension: "CTR".to_string(),
                    name: attribute.to_string(),
                },
                hint,
                None,
            )
        })?;
    }

    Ok(())
}

#[test]
fn test_edit_anarchic_attributes() {
    use super::QualifiedAttribute;

    let mut structure = AccessStructure::new();
    gen_structure(&mut structure, false).unwrap();

    assert_eq!(structure.attributes().count(), 7);

    // Try renaming Research to already used name MKG
    assert!(
        structure
            .rename_attribute(&QualifiedAttribute::new("DPT", "RD"), "MKG".to_string(),)
            .is_err()
    );

    // Rename RD to Research
    assert!(
        structure
            .rename_attribute(
                &QualifiedAttribute::new("DPT", "RD"),
                "Research".to_string(),
            )
            .is_ok()
    );

    let order: Vec<_> = structure
        .attributes()
        .filter(|a| a.dimension.as_str() == "SEC")
        .map(|a| a.name)
        .collect();

    assert!(order.len() == 2);

    // Add new attribute Sales
    let new_attr = QualifiedAttribute::new("DPT", "Sales");
    assert!(
        structure
            .add_attribute(new_attr.clone(), EncryptionHint::Classic, None)
            .is_ok()
    );
    assert_eq!(structure.attributes().count(), 8);

    // Try adding already existing attribute HR
    let duplicate_attr = QualifiedAttribute::new("DPT", "HR");
    assert!(
        structure
            .add_attribute(duplicate_attr, EncryptionHint::Classic, None)
            .is_err()
    );

    // Try adding attribute to non existing dimension
    let missing_dimension = QualifiedAttribute::new("Missing", "dimension");
    assert!(
        structure
            .add_attribute(missing_dimension.clone(), EncryptionHint::Classic, None)
            .is_err()
    );

    // Remove research attribute
    let delete_attr = QualifiedAttribute::new("DPT", "Research");
    structure.del_attribute(&delete_attr).unwrap();
    assert_eq!(structure.attributes().count(), 7);

    // Duplicate remove
    assert!(structure.del_attribute(&delete_attr).is_err());

    // Missing dimension remove
    assert!(structure.del_attribute(&missing_dimension).is_err());

    // Remove all attributes from a dimension
    structure.del_attribute(&new_attr).unwrap();
    structure
        .del_attribute(&QualifiedAttribute::new("DPT", "HR"))
        .unwrap();
    structure
        .del_attribute(&QualifiedAttribute::new("DPT", "MKG"))
        .unwrap();

    structure.del_dimension("DPT").unwrap();

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
    use super::QualifiedAttribute;

    let mut structure = AccessStructure::new();
    gen_structure(&mut structure, false).unwrap();

    assert_eq!(
        structure
            .attributes()
            .filter(|a| a.dimension == "SEC")
            .collect::<Vec<_>>(),
        vec![
            QualifiedAttribute {
                dimension: "SEC".to_string(),
                name: "LOW".to_string(),
            },
            QualifiedAttribute {
                dimension: "SEC".to_string(),
                name: "TOP".to_string(),
            },
        ]
    );

    // Rename ordered dimension
    assert!(
        structure
            .rename_attribute(&QualifiedAttribute::new("SEC", "LOW"), "WOL".to_string(),)
            .is_ok()
    );

    let order = structure.attributes().map(|q| q.name).collect::<Vec<_>>();
    assert!(order.contains(&"WOL".to_string()));
    assert!(!order.contains(&"LOW".to_string()));

    //// Try modifying hierarchical dimension
    structure
        .del_attribute(&QualifiedAttribute::new("SEC", "WOL"))
        .unwrap();

    structure
        .add_attribute(
            QualifiedAttribute::new("SEC", "MID"),
            EncryptionHint::Classic,
            None,
        )
        .unwrap();

    assert_eq!(
        structure
            .attributes()
            .filter(|a| a.dimension == "SEC")
            .collect::<Vec<_>>(),
        vec![
            QualifiedAttribute {
                dimension: "SEC".to_string(),
                name: "MID".to_string(),
            },
            QualifiedAttribute {
                dimension: "SEC".to_string(),
                name: "TOP".to_string(),
            },
        ]
    );

    structure
        .add_attribute(
            QualifiedAttribute::new("SEC", "LOW"),
            EncryptionHint::Classic,
            None,
        )
        .unwrap();

    assert_eq!(
        structure
            .attributes()
            .filter(|a| a.dimension == "SEC")
            .collect::<Vec<_>>(),
        vec![
            QualifiedAttribute {
                dimension: "SEC".to_string(),
                name: "LOW".to_string(),
            },
            QualifiedAttribute {
                dimension: "SEC".to_string(),
                name: "MID".to_string(),
            },
            QualifiedAttribute {
                dimension: "SEC".to_string(),
                name: "TOP".to_string(),
            },
        ]
    );

    structure
        .del_attribute(&QualifiedAttribute::new("SEC", "MID"))
        .unwrap();

    structure
        .add_attribute(
            QualifiedAttribute::new("SEC", "MID"),
            EncryptionHint::Classic,
            Some("LOW"),
        )
        .unwrap();

    assert_eq!(
        structure
            .attributes()
            .filter(|a| a.dimension == "SEC")
            .collect::<Vec<_>>(),
        vec![
            QualifiedAttribute {
                dimension: "SEC".to_string(),
                name: "LOW".to_string(),
            },
            QualifiedAttribute {
                dimension: "SEC".to_string(),
                name: "MID".to_string(),
            },
            QualifiedAttribute {
                dimension: "SEC".to_string(),
                name: "TOP".to_string(),
            },
        ]
    );

    //// Removing a hierarchical dimension is permitted
    structure.del_dimension("SEC").unwrap();
}
