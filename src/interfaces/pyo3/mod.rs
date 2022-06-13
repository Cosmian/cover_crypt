use pyo3::{pymodule, types::PyModule, wrap_pyfunction, PyResult, Python};

use self::{
    generate_cc_keys::{generate_master_keys, generate_user_private_key},
    hybrid_cc_aes::{
        decrypt, decrypt_hybrid_block, decrypt_hybrid_header, encrypt, encrypt_hybrid_block,
        encrypt_hybrid_header, get_encrypted_header_size,
    },
};

/// A Python module implemented in Rust.
#[pymodule]
fn cover_crypt(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_master_keys, m)?)?;
    m.add_function(wrap_pyfunction!(generate_user_private_key, m)?)?;
    m.add_function(wrap_pyfunction!(get_encrypted_header_size, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_hybrid_header, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_hybrid_header, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_hybrid_block, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_hybrid_block, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    Ok(())
}

pub mod generate_cc_keys;
pub mod hybrid_cc_aes;
