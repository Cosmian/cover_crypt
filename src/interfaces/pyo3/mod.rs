use crate::error::Error;
use pyo3::{pymodule, types::PyModule, PyResult, Python};

pub mod py_abe_policy;
pub mod py_cover_crypt;

use py_abe_policy::{Attribute, Policy, PolicyAxis};
use py_cover_crypt::{CoverCrypt, MasterSecretKey, PublicKey, SymmetricKey, UserSecretKey};

impl From<Error> for pyo3::PyErr {
    fn from(e: Error) -> Self {
        pyo3::exceptions::PyException::new_err(format!("{e}"))
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
    m.add_class::<MasterSecretKey>()?;
    m.add_class::<PublicKey>()?;
    m.add_class::<UserSecretKey>()?;
    Ok(())
}
