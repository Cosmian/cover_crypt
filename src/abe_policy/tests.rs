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
    Ok(())
}

#[test]
fn test_edit_policy_attributes() -> Result<(), Error> {
    let mut policy = policy()?;

    let new_attr = Attribute {
        axis: "Department".to_string(),
        name: "Sales".to_string(),
    };
    let res = policy.add_attribute(new_attr.clone(), EncryptionHint::Classic);
    assert!(res.is_ok());

    let duplicate_attr = Attribute {
        axis: "Department".to_string(),
        name: "HR".to_string(),
    };
    let res = policy.add_attribute(duplicate_attr, EncryptionHint::Classic);
    assert!(res.is_err());

    let missing_axis = Attribute {
        axis: "Missing".to_string(),
        name: "Axis".to_string(),
    };
    let res = policy.add_attribute(missing_axis.clone(), EncryptionHint::Classic);
    assert!(res.is_err());

    let delete_attr = Attribute {
        axis: "Department".to_string(),
        name: "R&D".to_string(),
    };
    let res = policy.delete_attribute(delete_attr.clone());
    assert!(res.is_ok());

    // Duplicate remove
    let res = policy.delete_attribute(delete_attr);
    assert!(res.is_err());

    // Missing axis remove
    let res = policy.delete_attribute(missing_axis);
    assert!(res.is_err());

    // Remove all attributes from an axis
    policy.delete_attribute(new_attr)?;
    policy.delete_attribute(Attribute {
        axis: "Department".to_string(),
        name: "HR".to_string(),
    })?;
    policy.delete_attribute(Attribute {
        axis: "Department".to_string(),
        name: "MKG".to_string(),
    })?;
    policy.delete_attribute(Attribute {
        axis: "Department".to_string(),
        name: "FIN".to_string(),
    })?;
    assert_eq!(policy.axes.len(), 1);

    // Remove axis test
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

    policy.remove_axis("AxisTest".to_string())?;
    assert_eq!(policy.axes.len(), 1);

    let res = policy.remove_axis("MissingAxis".to_string());
    assert!(res.is_err());

    // Removing last axis should result in an error
    let res = policy.remove_axis("Security Level".to_string());
    assert!(res.is_err());

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
