use serde::{Deserialize, Serialize};

//mod parser;
//mod policy_v2;
mod policy_v3;
//mod policy_versions;

pub use policy_v3::PolicyV3 as Policy;

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyVersion {
    V1,
    V2,
    V3,
}

impl Default for PolicyVersion {
    fn default() -> Self {
        Self::V3
    }
}

//#[cfg(test)]
//mod tests {
//use super::{policy_versions::LegacyPolicy, *};
//use crate::test_utils::policy;

//#[test]
//fn write_policy() {
//let _policy = policy().unwrap();
//std::fs::write("target/policy.json", serde_json::to_vec(&_policy).unwrap()).unwrap();
//}

///// Read policy from a file. Assert `LegacyPolicy` is convertible into a
///// `Policy`.
//#[test]
//fn read_policy() {
//// Can read a `Policy` V2
//let policy_v2_str = include_bytes!("../../test_utils/tests_data/policy_v2.json");
//Policy::try_from(policy_v2_str.as_slice()).unwrap();

//// Can read a `Policy` V1
//let policy_v1_str = include_bytes!("../../test_utils/tests_data/policy_v1.json");
//Policy::try_from(policy_v1_str.as_slice()).unwrap();

//// Can read a `LegacyPolicy`
//let legacy_policy_str = include_bytes!("../../test_utils/tests_data/legacy_policy.json");
//serde_json::from_slice::<LegacyPolicy>(legacy_policy_str).unwrap();

//// Can read `LegacyPolicy` as `Policy`
//Policy::try_from(legacy_policy_str.as_slice()).unwrap();
//}
//}
