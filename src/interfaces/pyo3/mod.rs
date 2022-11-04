use pyo3::{pymodule, types::PyModule, PyResult, Python};

use self::cover_crypt_lib::{Attribute, CoverCrypt, Policy, PolicyAxis, SymmetricKey};
use crate::error::Error;

impl From<Error> for pyo3::PyErr {
    fn from(e: Error) -> Self {
        pyo3::exceptions::PyTypeError::new_err(format!("{e}"))
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn cosmian_cover_crypt(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Attribute>()?;
    m.add_class::<PolicyAxis>()?;
    m.add_class::<Policy>()?;
    m.add_class::<CoverCrypt>()?;
    m.add_class::<SymmetricKey>()?;
    Ok(())
}

pub mod cover_crypt_lib;
