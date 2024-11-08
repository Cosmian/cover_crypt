use crate::{abe_policy::AccessStructure, Error};

use super::EncryptionHint;

pub fn gen_structure(policy: &mut AccessStructure) -> Result<(), Error> {
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
        Some("Protected"),
    )?;
    policy.add_attribute(
        crate::abe_policy::QualifiedAttribute {
            dimension: "Security Level".to_string(),
            name: "Medium Secret".to_string(),
        },
        EncryptionHint::Classic,
        Some("Low Secret"),
    )?;
    policy.add_attribute(
        crate::abe_policy::QualifiedAttribute {
            dimension: "Security Level".to_string(),
            name: "High Secret".to_string(),
        },
        EncryptionHint::Classic,
        Some("Medium Secret"),
    )?;
    policy.add_attribute(
        crate::abe_policy::QualifiedAttribute {
            dimension: "Security Level".to_string(),
            name: "Top Secret".to_string(),
        },
        EncryptionHint::Hybridized,
        Some("High Secret"),
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
//let mut policy = Policy::default();
//gen_policy(&mut policy).unwrap();

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
