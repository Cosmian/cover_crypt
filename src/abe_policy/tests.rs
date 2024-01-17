use crate::{
    abe_policy::{Attribute, DimensionBuilder, EncryptionHint, Policy},
    error::Error,
};

/// Creates the policy object used in tests.
pub fn policy() -> Result<Policy, Error> {
    let sec_level = DimensionBuilder::new(
        "Security Level",
        vec![
            ("Protected", EncryptionHint::Classic),
            ("Confidential", EncryptionHint::Classic),
            ("Top Secret", EncryptionHint::Hybridized),
        ],
        true,
    );
    let department = DimensionBuilder::new(
        "Department",
        vec![
            ("R&D", EncryptionHint::Classic),
            ("HR", EncryptionHint::Classic),
            ("MKG", EncryptionHint::Classic),
            ("FIN", EncryptionHint::Classic),
        ],
        false,
    );
    let mut policy = Policy::new();
    policy.add_dimension(sec_level)?;
    policy.add_dimension(department)?;
    Ok(policy)
}

#[test]
fn check_policy() {
    let security_level = DimensionBuilder::new(
        "Security Level",
        vec![
            ("Protected", EncryptionHint::Classic),
            ("Confidential", EncryptionHint::Classic),
            ("Top Secret", EncryptionHint::Hybridized),
        ],
        true,
    );
    let department = DimensionBuilder::new(
        "Department",
        vec![
            ("R&D", EncryptionHint::Classic),
            ("HR", EncryptionHint::Classic),
            ("MKG", EncryptionHint::Classic),
            ("FIN", EncryptionHint::Classic),
        ],
        false,
    );
    let mut policy = Policy::new();
    policy.add_dimension(security_level.clone()).unwrap();
    policy.add_dimension(department.clone()).unwrap();

    // check that policy
    let attributes = policy.attributes();
    assert_eq!(security_level.len() + department.len(), attributes.len());
    for properties in &security_level.attributes_properties {
        assert!(attributes.contains(&Attribute::new("Security Level", &properties.name)));
    }
    for properties in &department.attributes_properties {
        assert!(attributes.contains(&Attribute::new("Department", &properties.name)));
    }
}

#[test]
fn test_edit_policy_attributes() -> Result<(), Error> {
    let mut policy = policy()?;
    assert_eq!(policy.attributes().len(), 7);

    // Try renaming Research to already used name MKG
    assert!(policy
        .rename_attribute(&Attribute::new("Department", "R&D"), "MKG".to_string(),)
        .is_err());

    // Rename R&D to Research
    assert!(policy
        .rename_attribute(&Attribute::new("Department", "R&D"), "Research".to_string(),)
        .is_ok());

    // Rename ordered dimension
    assert!(policy
        .rename_attribute(
            &Attribute::new("Security Level", "Protected"),
            "Open".to_string(),
        )
        .is_ok());
    let order: Vec<_> = policy
        .dimensions
        .get("Security Level")
        .unwrap()
        .get_attributes_name()
        .cloned()
        .collect();
    assert!(order.len() == 3);
    assert!(order.contains(&"Open".to_string()));
    assert!(!order.contains(&"Protected".to_string()));

    assert_eq!(policy.attributes().len(), 7);
    // Add new attribute Sales
    let new_attr = Attribute::new("Department", "Sales");
    assert!(policy
        .add_attribute(new_attr.clone(), EncryptionHint::Classic)
        .is_ok());
    assert_eq!(policy.attributes().len(), 8);

    // Try adding already existing attribute HR
    let duplicate_attr = Attribute::new("Department", "HR");
    assert!(policy
        .add_attribute(duplicate_attr, EncryptionHint::Classic)
        .is_err());

    // Try adding attribute to non existing dimension
    let missing_dimension = Attribute::new("Missing", "dimension");
    assert!(policy
        .add_attribute(missing_dimension.clone(), EncryptionHint::Classic)
        .is_err());

    // Remove research attribute
    let delete_attr = Attribute::new("Department", "Research");
    assert!(policy.remove_attribute(&delete_attr).is_ok());
    assert_eq!(policy.attributes().len(), 7);

    // Duplicate remove
    assert!(policy.remove_attribute(&delete_attr).is_err());

    // Missing dimension remove
    assert!(policy.remove_attribute(&missing_dimension).is_err());

    // Remove all attributes from an dimension
    policy.remove_attribute(&new_attr)?;
    policy.remove_attribute(&Attribute::new("Department", "HR"))?;
    policy.remove_attribute(&Attribute::new("Department", "MKG"))?;
    policy.remove_attribute(&Attribute::new("Department", "FIN"))?;
    assert_eq!(policy.dimensions.len(), 1);

    // Add new dimension
    let new_dimension = DimensionBuilder::new(
        "DimensionTest",
        vec![
            ("Attr1", EncryptionHint::Classic),
            ("Attr2", EncryptionHint::Classic),
        ],
        false,
    );
    policy.add_dimension(new_dimension)?;
    assert_eq!(policy.dimensions.len(), 2);

    // Remove the new dimension
    policy.remove_dimension("DimensionTest")?;
    assert_eq!(policy.dimensions.len(), 1);

    // Try removing non existing dimension
    assert!(policy.remove_dimension("MissingDim").is_err());

    // Try modifying hierarchical dimension
    assert!(policy
        .remove_attribute(&Attribute::new("Security Level", "Top Secret"))
        .is_err());

    // Removing a hierarchical dimension is permitted
    assert!(policy.remove_dimension("Security Level").is_ok());

    Ok(())
}
