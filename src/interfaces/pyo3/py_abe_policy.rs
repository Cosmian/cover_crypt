use abe_policy::{Attribute as AttributeRust, Policy as PolicyRust, PolicyAxis as PolicyAxisRust};
use pyo3::{exceptions::PyException, exceptions::PyTypeError, prelude::*, types::PyType};

// Pyo3 doc on classes
// https://pyo3.rs/v0.16.2/class.html

/// An attribute in a policy group is characterized by the axis policy name
/// and its unique name within this axis.
#[pyclass]
pub struct Attribute {
    inner: AttributeRust,
}

#[pymethods]
impl Attribute {
    /// Create a Policy Attribute.
    ///
    /// - `axis`    : policy axis the attributes belongs to
    /// - `name`    : unique attribute name within this axis
    #[new]
    pub fn new(axis: &str, name: &str) -> Self {
        Attribute {
            inner: AttributeRust::new(axis, name),
        }
    }

    /// Return a string representation of the Attribute
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        format!("{}", &self.inner)
    }

    #[classmethod]
    pub fn from_string(_cls: &PyType, string: &str) -> PyResult<Self> {
        let attribute = match AttributeRust::try_from(string) {
            Ok(att) => att,
            Err(e) => return Err(PyException::new_err(e.to_string())),
        };
        Ok(Attribute { inner: attribute })
    }
}

/// Defines a policy axis by its name and its underlying attribute names.
///
/// If `hierarchical` is set to `true`, we assume a lexicographical order based
/// on the attribute name.
#[pyclass]
pub struct PolicyAxis {
    inner: PolicyAxisRust,
}

#[pymethods]
impl PolicyAxis {
    /// Generates a new policy axis with the given name and attribute names.
    /// A hierarchical axis enforces order between its attributes.
    ///
    /// - `name`        : axis name
    /// - `attributes`  : name of the attributes on this axis
    /// - `hierarchical`: set the axis to be hierarchical
    #[new]
    fn new(name: &str, attributes: Vec<&str>, hierarchical: bool) -> Self {
        PolicyAxis {
            inner: PolicyAxisRust::new(name, attributes.as_slice(), hierarchical),
        }
    }

    /// Returns the number of attributes belonging to this axis.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Return `true` if the attribute list is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Return a string representation of the Policy Axis
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        format!(
            "{}: {:?}, hierarchical: {}",
            &self.inner.name, &self.inner.attributes, &self.inner.hierarchical
        )
    }
}

#[pyclass]
pub struct Policy {
    pub(super) inner: PolicyRust,
}

#[pymethods]
impl Policy {
    #[new]
    fn new() -> Self {
        Policy {
            inner: PolicyRust::new(u32::MAX),
        }
    }

    /// Adds the given policy axis to the policy.
    pub fn add_axis(&mut self, axis: &PolicyAxis) -> PyResult<()> {
        self.inner
            .add_axis(&axis.inner)
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Rotates an attribute, changing its underlying value with an unused
    /// value.
    pub fn rotate(&mut self, attr: &Attribute) -> PyResult<()> {
        self.inner
            .rotate(&attr.inner)
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Returns the list of Attributes of this Policy.
    pub fn attributes(&self) -> Vec<Attribute> {
        self.inner
            .attributes()
            .into_iter()
            .map(|a| Attribute { inner: a })
            .collect()
    }

    /// Returns the list of all attributes values given to this Attribute
    /// over the time after rotations. The current value is returned first
    pub fn attribute_values(&self, attribute: &Attribute) -> PyResult<Vec<u32>> {
        self.inner
            .attribute_values(&attribute.inner)
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Retrieves the current value of an attribute.
    pub fn attribute_current_value(&self, attribute: &Attribute) -> PyResult<u32> {
        self.inner
            .attribute_current_value(&attribute.inner)
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Return a string representation of the Policy
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        format!("{}", &self.inner)
    }

    /// Perform deep copy of the Policy
    pub fn clone(&self) -> Self {
        Policy {
            inner: self.inner.clone(),
        }
    }

    /// JSON serialization
    pub fn to_json(&self) -> PyResult<String> {
        match serde_json::to_string(&self.inner) {
            Ok(res) => Ok(res),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    /// JSON deserialization
    #[classmethod]
    pub fn from_json(_cls: &PyType, policy_json: String) -> PyResult<Self> {
        let policy: PolicyRust = serde_json::from_str(&policy_json)
            .map_err(|e| PyTypeError::new_err(format!("Error deserializing attributes: {e}")))?;
        Ok(Policy { inner: policy })
    }
}
