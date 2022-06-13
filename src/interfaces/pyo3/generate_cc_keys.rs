use cosmian_crypto_base::asymmetric::ristretto::X25519Crypto;
use pyo3::{exceptions::PyTypeError, prelude::*};

use crate::{api::CoverCrypt, error::Error, policies::Policy};

impl From<Error> for pyo3::PyErr {
    fn from(e: Error) -> Self {
        pyo3::exceptions::PyTypeError::new_err(format!("{e}"))
    }
}

#[pyfunction]
pub fn generate_master_keys(policy_bytes: Vec<u8>) -> PyResult<Vec<u8>> {
    let policy: Policy = serde_json::from_slice(policy_bytes.as_slice())
        .map_err(|e| PyTypeError::new_err(format!("{e}")))?;

    //
    // Setup CoverCrypt
    let (private_key, public_key) =
        CoverCrypt::<X25519Crypto>::default().generate_master_keys(&policy)?;

    // Serialize master keys
    let private_keys_bytes = private_key.to_bytes()?;
    let public_keys_bytes = public_key.to_bytes()?;

    let mut master_keys_bytes =
        Vec::<u8>::with_capacity(4 + private_keys_bytes.len() + public_keys_bytes.len());
    master_keys_bytes.extend_from_slice(&u32::to_be_bytes(private_keys_bytes.len() as u32));
    master_keys_bytes.extend_from_slice(&private_keys_bytes);
    master_keys_bytes.extend_from_slice(&public_keys_bytes);
    Ok(master_keys_bytes)
}

/// A Python module implemented in Rust.
#[pymodule]
fn cover_crypt(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_master_keys, m)?)?;
    Ok(())
}
