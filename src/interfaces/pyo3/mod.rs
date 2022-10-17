use pyo3::{pymodule, types::PyModule, wrap_pyfunction, PyResult, Python};

use self::{
    generate_cc_keys::{
        generate_master_keys, generate_policy, generate_user_secret_key, rotate_attributes,
    },
    hybrid_cc_aes::{
        decrypt, decrypt_hybrid_header, decrypt_symmetric_block, encrypt, encrypt_hybrid_header,
        encrypt_symmetric_block,
    },
};
use crate::error::Error;

impl From<Error> for pyo3::PyErr {
    fn from(e: Error) -> Self {
        pyo3::exceptions::PyTypeError::new_err(format!("{e}"))
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn cosmian_cover_crypt(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_master_keys, m)?)?;
    m.add_function(wrap_pyfunction!(generate_user_secret_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_policy, m)?)?;
    m.add_function(wrap_pyfunction!(rotate_attributes, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_hybrid_header, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_hybrid_header, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_symmetric_block, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_symmetric_block, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    Ok(())
}

pub mod generate_cc_keys;
pub mod hybrid_cc_aes;
