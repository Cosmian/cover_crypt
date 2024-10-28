use crate::{abe_policy::Policy, Error};

use super::EncryptionHint;

pub fn gen_policy(policy: &mut Policy) -> Result<(), Error> {
    policy.add_hierarchy("Security Level".to_string())?;

    policy.add_attribute(
        crate::abe_policy::QualifiedAttribute {
            dimension: "Security Level".to_string(),
            name: "Protected".to_string(),
        },
        EncryptionHint::Classic,
        None,
    )?;
    policy.add_attribute(
        crate::abe_policy::QualifiedAttribute {
            dimension: "Security Level".to_string(),
            name: "Low Secret".to_string(),
        },
        EncryptionHint::Classic,
        Some("Protected".to_string()),
    )?;
    policy.add_attribute(
        crate::abe_policy::QualifiedAttribute {
            dimension: "Security Level".to_string(),
            name: "Medium Secret".to_string(),
        },
        EncryptionHint::Classic,
        Some("Low Secret".to_string()),
    )?;
    policy.add_attribute(
        crate::abe_policy::QualifiedAttribute {
            dimension: "Security Level".to_string(),
            name: "High Secret".to_string(),
        },
        EncryptionHint::Classic,
        Some("Medium Secret".to_string()),
    )?;
    policy.add_attribute(
        crate::abe_policy::QualifiedAttribute {
            dimension: "Security Level".to_string(),
            name: "Top Secret".to_string(),
        },
        EncryptionHint::Hybridized,
        Some("High Secret".to_string()),
    )?;

    policy.add_anarchy("Department".to_string())?;
    [
        ("R&D", EncryptionHint::Classic),
        ("HR", EncryptionHint::Classic),
        ("MKG", EncryptionHint::Classic),
        ("FIN", EncryptionHint::Classic),
    ]
    .into_iter()
    .try_for_each(|(attribute, hint)| {
        policy.add_attribute(
            crate::abe_policy::QualifiedAttribute {
                dimension: "Department".to_string(),
                name: attribute.to_string(),
            },
            hint,
            None,
        )
    })?;

    Ok(())
}

//#[test]
//fn check_policy() {
//let mut policy = policy().unwrap();
//policy.add_dimension(security_level.clone()).unwrap();
//policy.add_dimension(department.clone()).unwrap();

//// check that policy
//let attributes = policy.attributes();
//assert_eq!(security_level.len() + department.len(), attributes.len());
//for properties in &security_level.attributes_properties {
//assert!(attributes.contains(&QualifiedAttribute::new("Security Level", &properties.name)));
//}
//for properties in &department.attributes_properties {
//assert!(attributes.contains(&QualifiedAttribute::new("Department", &properties.name)));
//}
//Ok(())
//}

//#[test]
//fn test_edit_policy_attributes() -> Result<(), Error> {
//let (msk, _mpk, _cover_crypt) = setup_cc_and_gen_master_keys()?;

//let mut policy = msk.policy;

//assert_eq!(policy.attributes().len(), 8);

//// Try renaming Research to already used name MKG
//assert!(policy
//.rename_attribute(
//&QualifiedAttribute::new("Department", "R&D"),
//"MKG".to_string(),
//)
//.is_err());

//// Rename R&D to Research
//assert!(policy
//.rename_attribute(
//&QualifiedAttribute::new("Department", "R&D"),
//"Research".to_string(),
//)
//.is_ok());

//// Rename ordered dimension
//assert!(policy
//.rename_attribute(
//&QualifiedAttribute::new("Security Level", "Protected"),
//"Open".to_string(),
//)
//.is_ok());
//let order: Vec<_> = policy
//.dimensions
//.get("Security Level")
//.unwrap()
//.get_attributes_name()
//.cloned()
//.collect();
//assert!(order.len() == 4);
//assert!(order.contains(&"Open".to_string()));
//assert!(!order.contains(&"Protected".to_string()));

//assert_eq!(policy.attributes().len(), 8);
//// Add new attribute Sales
//let new_attr = QualifiedAttribute::new("Department", "Sales");
//assert!(policy
//.add_attribute(new_attr.clone(), EncryptionHint::Classic)
//.is_ok());
//assert_eq!(policy.attributes().len(), 9);

//// Try adding already existing attribute HR
//let duplicate_attr = QualifiedAttribute::new("Department", "HR");
//assert!(policy
//.add_attribute(duplicate_attr, EncryptionHint::Classic)
//.is_err());

//// Try adding attribute to non existing dimension
//let missing_dimension = QualifiedAttribute::new("Missing", "dimension");
//assert!(policy
//.add_attribute(missing_dimension.clone(), EncryptionHint::Classic)
//.is_err());

//// Remove research attribute
//let delete_attr = QualifiedAttribute::new("Department", "Research");
//assert!(policy.remove_attribute(&delete_attr).is_ok());
//assert_eq!(policy.attributes().len(), 7);

//// Duplicate remove
//assert!(policy.remove_attribute(&delete_attr).is_err());

//// Missing dimension remove
//assert!(policy.remove_attribute(&missing_dimension).is_err());

//// Remove all attributes from a dimension
//policy.remove_attribute(&new_attr)?;
//policy.remove_attribute(&QualifiedAttribute::new("Department", "HR"))?;
//policy.remove_attribute(&QualifiedAttribute::new("Department", "MKG"))?;

//// TODO: temporary fix before we allow removing an entire dimension
//// policy.remove_attribute(&Attribute::new("Department", "FIN"))?;
//policy.remove_dimension("Department")?;

//assert_eq!(policy.dimensions.len(), 1);

//// Add new dimension
//let new_dimension = DimensionBuilder::new(
//"DimensionTest",
//vec![
//("Attr1", EncryptionHint::Classic),
//("Attr2", EncryptionHint::Classic),
//],
//false,
//);
//policy.add_dimension(new_dimension)?;
//assert_eq!(policy.dimensions.len(), 2);

//// Remove the new dimension
//policy.remove_dimension("DimensionTest")?;
//assert_eq!(policy.dimensions.len(), 1);

//// Try removing non existing dimension
//assert!(policy.remove_dimension("MissingDim").is_err());

//// Try modifying hierarchical dimension
//assert!(policy
//.remove_attribute(&QualifiedAttribute::new("Security Level", "Top Secret"))
//.is_err());

//// Removing a hierarchical dimension is permitted
//assert!(policy.remove_dimension("Security Level").is_ok());

//Ok(())
//}

//#[test]
//fn specification_conversion_round_trip() -> Result<(), Error> {
//let (msk, _mpk, _cover_crypt) = setup_cc_and_gen_master_keys()?;

//let spec: HashMap<String, Vec<String>> = msk.policy.try_into()?;

//let policy_from_spec: Policy = spec.try_into()?;

//assert_eq!(policy_from_spec.dimensions.len(), 2);

//assert!(matches!(
//policy_from_spec.dimensions.get("Security Level").unwrap(),
//Dimension::Ordered(_)
//));
//assert!(matches!(
//policy_from_spec.dimensions.get("Department").unwrap(),
//Dimension::Unordered(_)
//));
//assert_eq!(
//policy_from_spec
//.dimensions
//.get("Security Level")
//.unwrap()
//.attributes()
//.count(),
//4
//);
//assert_eq!(
//policy_from_spec
//.get_attribute_hybridization_hint(&QualifiedAttribute::new("Department", "MKG"))
//.unwrap(),
//EncryptionHint::Classic
//);
//assert_eq!(
//policy_from_spec
//.get_attribute_hybridization_hint(&QualifiedAttribute::new(
//"Security Level",
//"Protected"
//))
//.unwrap(),
//EncryptionHint::Classic
//);
//assert_eq!(
//policy_from_spec
//.get_attribute_hybridization_hint(&QualifiedAttribute::new(
//"Security Level",
//"Top Secret"
//))
//.unwrap(),
//EncryptionHint::Hybridized
//);

//Ok(())
//}
