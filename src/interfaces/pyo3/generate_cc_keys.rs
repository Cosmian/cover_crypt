use crate::{
    api::CoverCrypt,
    interfaces::statics::{CoverCryptX25519Aes256, MasterSecretKey},
};
use abe_policy::{AccessPolicy, Attribute, Policy, PolicyAxis};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use pyo3::{exceptions::PyTypeError, prelude::*};

/// Generate the master authority keys for supplied Policy
///
///  - `policy_bytes` : Policy to use to generate the keys (JSON serialized)
#[pyfunction]
pub fn generate_master_keys(policy_bytes: Vec<u8>) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let policy: Policy = serde_json::from_slice(policy_bytes.as_slice())
        .map_err(|e| PyTypeError::new_err(format!("Policy deserialization failed: {e}")))?;

    let (msk, mpk) = CoverCryptX25519Aes256::default().generate_master_keys(&policy)?;

    Ok((msk.try_to_bytes()?, mpk.try_to_bytes()?))
}

/// Generate a user secret key.
///
/// - `msk_bytes`           : master secret key
/// - `access_policy_str`   : user access policy
/// - `policy_bytes`        : global policy
#[pyfunction]
pub fn generate_user_secret_key(
    msk_bytes: Vec<u8>,
    access_policy_str: String,
    policy_bytes: Vec<u8>,
) -> PyResult<Vec<u8>> {
    let msk = MasterSecretKey::try_from_bytes(&msk_bytes)?;
    let policy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Policy deserialization failed: {e}")))?;
    let access_policy = AccessPolicy::from_boolean_expression(&access_policy_str)
        .map_err(|e| PyTypeError::new_err(format!("Access policy creation failed: {e}")))?;

    let usk = CoverCryptX25519Aes256::default().generate_user_secret_key(
        &msk,
        &access_policy,
        &policy,
    )?;

    Ok(usk.try_to_bytes()?)
}

/// Generate ABE policy from axis given in serialized JSON
///
/// - `policy_axis_bytes`: as many axis as needed
/// - `max_attribute_value`: maximum number of attributes that can be used in
///   policy
#[pyfunction]
pub fn generate_policy(policy_axis_bytes: Vec<u8>, max_attribute_value: u32) -> PyResult<Vec<u8>> {
    let policy_axis: Vec<PolicyAxis> = serde_json::from_slice(&policy_axis_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Policy Axis deserialization failed: {e}")))?;
    let mut policy = Policy::new(max_attribute_value);
    for axis in &policy_axis {
        let attrs = axis
            .attributes
            .iter()
            .map(std::ops::Deref::deref)
            .collect::<Vec<_>>();
        policy
            .add_axis(&PolicyAxis::new(&axis.name, &attrs, axis.hierarchical))
            .map_err(|e| PyTypeError::new_err(format!("Error adding axes: {e}")))?;
    }

    let policy_bytes = serde_json::to_vec(&policy)
        .map_err(|e| PyTypeError::new_err(format!("Error serializing policy: {e}")))?;

    Ok(policy_bytes)
}

/// Rotate attributes: changing its underlying value with that of an unused slot
///
/// Returns the new policy with refreshed attributes
#[pyfunction]
pub fn rotate_attributes(attributes_bytes: Vec<u8>, policy_bytes: Vec<u8>) -> PyResult<Vec<u8>> {
    let attributes: Vec<Attribute> = serde_json::from_slice(&attributes_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing attributes: {e}")))?;
    let mut policy: Policy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing policy: {e}")))?;

    for attr in &attributes {
        policy
            .rotate(attr)
            .map_err(|e| PyTypeError::new_err(format!("Rotation failed: {e}")))?;
    }
    serde_json::to_vec(&policy)
        .map_err(|e| PyTypeError::new_err(format!("Error serializing policy: {e}")))
}
