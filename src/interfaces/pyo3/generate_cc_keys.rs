use cosmian_crypto_base::asymmetric::ristretto::X25519Crypto;
use pyo3::{exceptions::PyTypeError, prelude::*};

use crate::{
    api::{CoverCrypt, PrivateKey},
    error::Error,
    policies::{AccessPolicy, Policy},
};

impl From<Error> for pyo3::PyErr {
    fn from(e: Error) -> Self {
        pyo3::exceptions::PyTypeError::new_err(format!("{e}"))
    }
}

#[pyfunction]
pub fn generate_master_keys(policy_bytes: Vec<u8>) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let policy: Policy = serde_json::from_slice(policy_bytes.as_slice())
        .map_err(|e| PyTypeError::new_err(format!("Policy deserialization failed: {e}")))?;

    //
    // Setup CoverCrypt
    let (master_private_key, master_public_key) =
        CoverCrypt::<X25519Crypto>::default().generate_master_keys(&policy)?;

    Ok((
        master_private_key.to_bytes()?,
        master_public_key.to_bytes()?,
    ))
}

#[pyfunction]
pub fn generate_user_private_key(
    master_private_key_bytes: Vec<u8>,
    access_policy_str: String,
    policy_bytes: Vec<u8>,
) -> PyResult<Vec<u8>> {
    let master_private_key: PrivateKey<X25519Crypto> =
        PrivateKey::try_from_bytes(master_private_key_bytes.to_vec().as_slice())?;
    let policy = serde_json::from_slice(policy_bytes.to_vec().as_slice())
        .map_err(|e| PyTypeError::new_err(format!("Policy deserialization failed: {e}")))?;
    let access_policy = AccessPolicy::from_boolean_expression(&access_policy_str)?;

    let user_key = CoverCrypt::<X25519Crypto>::default().generate_user_private_key(
        &master_private_key,
        &access_policy,
        &policy,
    )?;

    Ok(user_key.to_bytes()?)
}
