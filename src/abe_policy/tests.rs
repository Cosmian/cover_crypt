use crate::{
    abe_policy::{AccessPolicy, Attribute, EncryptionHint, Policy, PolicyAxis},
    error::Error,
};

/// Creates the policy object used in tests.
pub fn policy() -> Result<Policy, Error> {
    let sec_level = PolicyAxis::new(
        "Security Level",
        vec![
            ("Protected", EncryptionHint::Classic),
            ("Confidential", EncryptionHint::Classic),
            ("Top Secret", EncryptionHint::Hybridized),
        ],
        true,
    );
    let department = PolicyAxis::new(
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
    policy.add_axis(sec_level)?;
    policy.add_axis(department)?;
    Ok(policy)
}

#[test]
fn check_policy() {
    let security_level = PolicyAxis::new(
        "Security Level",
        vec![
            ("Protected", EncryptionHint::Classic),
            ("Confidential", EncryptionHint::Classic),
            ("Top Secret", EncryptionHint::Hybridized),
        ],
        true,
    );
    let department = PolicyAxis::new(
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
    policy.add_axis(security_level.clone()).unwrap();
    policy.add_axis(department.clone()).unwrap();

    // check that policy
    let attributes = policy.attributes();
    assert_eq!(security_level.len() + department.len(), attributes.len());
    for properties in &security_level.attributes_properties {
        assert!(attributes.contains(&Attribute::new("Security Level", &properties.name)))
    }
    for properties in &department.attributes_properties {
        assert!(attributes.contains(&Attribute::new("Department", &properties.name)))
    }
    for attribute in &attributes {
        assert_eq!(
            policy.attribute_values(attribute).unwrap()[0],
            policy.attribute_current_value(attribute).unwrap()
        )
    }
}

#[test]
fn test_rotate_policy_attributes() -> Result<(), Error> {
    let mut policy = policy()?;
    let attributes = policy.attributes();
    // rotate few attributes
    policy.rotate(&attributes[0])?;
    assert_eq!(2, policy.attribute_values(&attributes[0])?.len());
    policy.rotate(&attributes[2])?;
    assert_eq!(2, policy.attribute_values(&attributes[2])?.len());
    for attribute in &attributes {
        assert_eq!(
            policy.attribute_values(attribute)?[0],
            policy.attribute_current_value(attribute)?
        )
    }

    policy.clear_old_rotations(&attributes[0])?;
    assert_eq!(1, policy.attribute_values(&attributes[0])?.len());

    assert!(policy
        .clear_old_rotations(&Attribute::new("Department", "Missing"))
        .is_err());

    Ok(())
}

#[test]
fn test_edit_policy_attributes() -> Result<(), Error> {
    let mut policy = policy()?;
    assert_eq!(policy.attributes().len(), 7);

    // Rename R&D to Research
    assert!(policy
        .rename_attribute(Attribute::new("Department", "R&D"), "Research",)
        .is_ok());

    // Try renaming Research to already used name MKG
    assert!(policy
        .rename_attribute(Attribute::new("Department", "R&D"), "MKG",)
        .is_err());
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

    // Try adding attribute to non existing Axis
    let missing_axis = Attribute::new("Missing", "Axis");
    assert!(policy
        .add_attribute(missing_axis.clone(), EncryptionHint::Classic)
        .is_err());

    // Remove research attribute
    let delete_attr = Attribute::new("Department", "Research");
    assert!(policy.remove_attribute(delete_attr.clone()).is_ok());
    assert_eq!(policy.attributes().len(), 7);

    // Duplicate remove
    assert!(policy.remove_attribute(delete_attr).is_err());

    // Missing axis remove
    assert!(policy.remove_attribute(missing_axis).is_err());

    // Remove all attributes from an axis
    policy.remove_attribute(new_attr)?;
    policy.remove_attribute(Attribute::new("Department", "HR"))?;
    policy.remove_attribute(Attribute::new("Department", "MKG"))?;
    policy.remove_attribute(Attribute::new("Department", "FIN"))?;
    assert_eq!(policy.axes.len(), 1);

    // Add new axis
    let new_axis = PolicyAxis::new(
        "AxisTest",
        vec![
            ("Attr1", EncryptionHint::Classic),
            ("Attr2", EncryptionHint::Classic),
        ],
        false,
    );
    policy.add_axis(new_axis)?;
    assert_eq!(policy.axes.len(), 2);

    // Remove the new axis
    policy.remove_axis("AxisTest".to_string())?;
    assert_eq!(policy.axes.len(), 1);

    // Try removing non existing axis
    assert!(policy.remove_axis("MissingAxis".to_string()).is_err());

    // Try modifying hierarchical axis
    assert!(policy
        .remove_attribute(Attribute::new("Security Level", "Top Secret"))
        .is_err());

    // Removing a hierarchical axis is permitted
    assert!(policy.remove_axis("Security Level".to_string()).is_ok());

    Ok(())
}

#[test]
fn test_access_policy_equality() {
    let ap1 = "(Department::FIN || Department::MKG) && Security Level::Top Secret";
    let ap2 = "Security Level::Top Secret && (Department::FIN || Department::MKG)";
    let ap3 = "Security Level::Top Secret && (Department::FIN || Department::HR)";
    let ap1 = AccessPolicy::from_boolean_expression(ap1).unwrap();
    let ap2 = AccessPolicy::from_boolean_expression(ap2).unwrap();
    let ap3 = AccessPolicy::from_boolean_expression(ap3).unwrap();
    assert_eq!(ap1, ap2);
    assert_eq!(ap2, ap2);
    assert_ne!(ap2, ap3);
}
