use crate::{
    Error, QualifiedAttribute,
    abe::policy::{AccessStructure, HybridizationStatus},
};

pub fn gen_structure(
    policy: &mut AccessStructure,
    complete: bool,
) -> Result<(), Error> {
    policy.add_hierarchy("SEC".to_string())?;

    policy.add_attribute(
        QualifiedAttribute::new("SEC".to_owned(), "LOW".to_owned()),
        HybridizationStatus::Classic,
        None,
    )?;
    policy.add_attribute(
        QualifiedAttribute::new("SEC".to_owned(), "MED".to_owned()),
        HybridizationStatus::PostQuantum,
        Some("LOW"),
    )?;
    policy.add_attribute(
        QualifiedAttribute::new("SEC".to_owned(), "TOP".to_owned()),
        HybridizationStatus::Hybridized,
        Some("MED"),
    )?;

    policy.add_anarchy("DPT".to_string())?;
    [
        ("RD", HybridizationStatus::Classic),
        ("HR", HybridizationStatus::Classic),
        ("MKG", HybridizationStatus::Classic),
        ("FIN", HybridizationStatus::Classic),
        ("DEV", HybridizationStatus::Classic),
    ]
    .into_iter()
    .try_for_each(|(attribute, mode)| {
        policy.add_attribute(
            QualifiedAttribute::new("DPT".to_owned(), attribute.to_owned()),
            mode,
            None,
        )
    })?;

    if complete {
        policy.add_anarchy("CTR".to_string())?;
        [
            ("EN", HybridizationStatus::Classic),
            ("DE", HybridizationStatus::Classic),
            ("IT", HybridizationStatus::Classic),
            ("FR", HybridizationStatus::Classic),
            ("SP", HybridizationStatus::Classic),
        ]
        .into_iter()
        .try_for_each(|(attribute, mode)| {
            policy.add_attribute(
                QualifiedAttribute::new("CTR".to_owned(), attribute.to_owned()),
                mode,
                None,
            )
        })?;
    }

    Ok(())
}

#[test]
fn test_edit_anarchic_attributes() {
    let mut structure = AccessStructure::new();
    gen_structure(&mut structure, false).unwrap();

    assert_eq!(structure.attributes().count(), 8);

    // Try renaming Research to already used name MKG
    assert!(
        structure
            .rename_attribute(
                &QualifiedAttribute::new("DPT".to_owned(), "RD".to_owned()),
                "MKG".to_string(),
            )
            .is_err()
    );

    // Rename RD to Research
    assert!(
        structure
            .rename_attribute(
                &QualifiedAttribute::new("DPT".to_owned(), "RD".to_owned()),
                "Research".to_string(),
            )
            .is_ok()
    );

    let order: Vec<_> = structure
        .attributes()
        .filter(|a| a.dimension.as_str() == "SEC")
        .map(|a| a.attribute)
        .collect();

    assert!(order.len() == 3);

    // Add new attribute Sales
    let new_attr =
        QualifiedAttribute::new("DPT".to_owned(), "Sales".to_owned());
    assert!(
        structure
            .add_attribute(new_attr.clone(), HybridizationStatus::Classic, None)
            .is_ok()
    );
    assert_eq!(structure.attributes().count(), 9);

    // Try adding already existing attribute HR
    let duplicate_attr =
        QualifiedAttribute::new("DPT".to_owned(), "HR".to_owned());
    assert!(
        structure
            .add_attribute(duplicate_attr, HybridizationStatus::Classic, None)
            .is_err()
    );

    // Try adding attribute to non existing dimension
    let missing_dimension =
        QualifiedAttribute::new("Missing".to_owned(), "dimension".to_owned());
    assert!(
        structure
            .add_attribute(
                missing_dimension.clone(),
                HybridizationStatus::Classic,
                None
            )
            .is_err()
    );

    // Remove research attribute
    let delete_attr =
        QualifiedAttribute::new("DPT".to_owned(), "Research".to_owned());
    structure.del_attribute(&delete_attr).unwrap();
    assert_eq!(structure.attributes().count(), 8);

    // Duplicate remove
    assert!(structure.del_attribute(&delete_attr).is_err());

    // Missing dimension remove
    assert!(structure.del_attribute(&missing_dimension).is_err());

    // Remove all attributes from a dimension
    structure.del_attribute(&new_attr).unwrap();
    structure
        .del_attribute(&QualifiedAttribute::new(
            "DPT".to_owned(),
            "HR".to_owned(),
        ))
        .unwrap();
    structure
        .del_attribute(&QualifiedAttribute::new(
            "DPT".to_owned(),
            "MKG".to_owned(),
        ))
        .unwrap();

    structure.del_dimension("DPT").unwrap();

    assert_eq!(structure.dimensions().count(), 1);

    // Add new dimension
    structure.add_anarchy("DimensionTest".to_string()).unwrap();
    structure
        .add_attribute(
            QualifiedAttribute::new(
                "DimensionTest".to_owned(),
                "Attr1".to_owned(),
            ),
            HybridizationStatus::Classic,
            None,
        )
        .unwrap();
    structure
        .add_attribute(
            QualifiedAttribute::new(
                "DimensionTest".to_owned(),
                "Attr2".to_owned(),
            ),
            HybridizationStatus::Classic,
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
            QualifiedAttribute::new("SEC".to_owned(), "LOW".to_owned(),),
            QualifiedAttribute::new("SEC".to_owned(), "MED".to_owned(),),
            QualifiedAttribute::new("SEC".to_owned(), "TOP".to_owned(),),
        ]
    );

    // Rename ordered dimension
    assert!(
        structure
            .rename_attribute(
                &QualifiedAttribute::new("SEC".to_owned(), "LOW".to_owned()),
                "WOL".to_string(),
            )
            .is_ok()
    );

    let order = structure
        .attributes()
        .map(|q| q.attribute)
        .collect::<Vec<_>>();
    assert!(order.contains(&"WOL".to_string()));
    assert!(!order.contains(&"LOW".to_string()));

    //// Try modifying hierarchical dimension
    structure
        .del_attribute(&QualifiedAttribute::new(
            "SEC".to_owned(),
            "WOL".to_owned(),
        ))
        .unwrap();

    structure
        .add_attribute(
            QualifiedAttribute::new("SEC".to_owned(), "OTHER".to_owned()),
            HybridizationStatus::Classic,
            None,
        )
        .unwrap();

    assert_eq!(
        structure
            .attributes()
            .filter(|a| a.dimension == "SEC")
            .collect::<Vec<_>>(),
        vec![
            QualifiedAttribute::new("SEC".to_owned(), "OTHER".to_owned(),),
            QualifiedAttribute::new("SEC".to_owned(), "MED".to_owned(),),
            QualifiedAttribute::new("SEC".to_owned(), "TOP".to_owned(),),
        ]
    );

    structure
        .add_attribute(
            QualifiedAttribute::new("SEC".to_owned(), "LOW".to_owned()),
            HybridizationStatus::Classic,
            None,
        )
        .unwrap();

    assert_eq!(
        structure
            .attributes()
            .filter(|a| a.dimension == "SEC")
            .collect::<Vec<_>>(),
        vec![
            QualifiedAttribute::new("SEC".to_owned(), "LOW".to_owned(),),
            QualifiedAttribute::new("SEC".to_owned(), "OTHER".to_owned(),),
            QualifiedAttribute::new("SEC".to_owned(), "MED".to_owned(),),
            QualifiedAttribute::new("SEC".to_owned(), "TOP".to_owned(),),
        ]
    );

    structure
        .del_attribute(&QualifiedAttribute::new(
            "SEC".to_owned(),
            "OTHER".to_owned(),
        ))
        .unwrap();

    structure
        .add_attribute(
            QualifiedAttribute::new("SEC".to_owned(), "MID".to_owned()),
            HybridizationStatus::Classic,
            Some("LOW"),
        )
        .unwrap();

    assert_eq!(
        structure
            .attributes()
            .filter(|a| a.dimension == "SEC")
            .collect::<Vec<_>>(),
        vec![
            QualifiedAttribute::new("SEC".to_owned(), "LOW".to_owned(),),
            QualifiedAttribute::new("SEC".to_owned(), "MID".to_owned(),),
            QualifiedAttribute::new("SEC".to_owned(), "MED".to_owned(),),
            QualifiedAttribute::new("SEC".to_owned(), "TOP".to_owned(),),
        ]
    );

    //// Removing a hierarchical dimension is permitted
    structure.del_dimension("SEC").unwrap();
}
