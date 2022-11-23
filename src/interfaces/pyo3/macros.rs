/// Implements the basic functionalities of a key in python.
///
/// - implements `deep_copy`
/// - converts to and from `PyBytes`
///
/// # Parameters
///
/// - `type_name`   : name of the key type
macro_rules! impl_key_byte {
    ($py_type:ty, $rust_type:ty) => {
        #[pymethods]
        impl $py_type {
            /// Clones the key
            pub fn deep_copy(&self) -> Self {
                Self(self.0.clone())
            }

            /// Converts key to bytes
            pub fn to_bytes(&self, py: Python) -> PyResult<PyObject> {
                Ok(convert_to_pybytes(&self.0.try_to_bytes()?, py))
            }

            /// Reads key from bytes
            #[classmethod]
            pub fn from_bytes(_cls: &PyType, key_bytes: Vec<u8>) -> PyResult<Self> {
                match <$rust_type>::try_from_bytes(&key_bytes) {
                    Ok(key) => Ok(Self(key)),
                    Err(e) => Err(PyErr::from(e)),
                }
            }
        }
    };
}
