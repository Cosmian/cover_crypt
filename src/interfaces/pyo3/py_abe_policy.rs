use abe_policy::{Attribute as AttributeRust, Policy as PolicyRust, PolicyAxis as PolicyAxisRust};
use pyo3::{exceptions::PyException, exceptions::PyTypeError, prelude::*, types::PyType};

// Pyo3 doc on classes
// https://pyo3.rs/v0.16.2/class.html

/// An attribute in a policy group is characterized by the axis policy name
/// and its unique name within this axis.
#[pyclass]
pub struct Attribute(AttributeRust);

#[pymethods]
impl Attribute {
    /// Creates a Policy Attribute.
    ///
    /// - `axis`    : policy axis the attributes belongs to
    /// - `name`    : unique attribute name within this axis
    #[new]
    pub fn new(axis: &str, name: &str) -> Self {
        Self(AttributeRust::new(axis, name))
    }

    /// Returns a string representation of the Attribute
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }

    /// Creates a Policy Attribute from a string representation
    #[classmethod]
    pub fn from_string(_cls: &PyType, string: &str) -> PyResult<Self> {
        match AttributeRust::try_from(string) {
            Ok(inner) => Ok(Self(inner)),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }
}

/// Defines an unique policy axis by its name and its underlying attribute names.
///
/// If the axis is defined as hierarchical, we assume a lexicographical order
/// on the attribute name.
#[pyclass]
pub struct PolicyAxis(PolicyAxisRust);

#[pymethods]
impl PolicyAxis {
    /// Generates a new policy axis with the given name and attribute names.
    /// If `hierarchical` is set to `true`, the axis is defined as hierarchical.
    ///
    /// - `name`        : axis name
    /// - `attributes`  : name of the attributes on this axis
    /// - `hierarchical`: set the axis to be hierarchical
    #[new]
    fn new(name: &str, attributes: Vec<&str>, hierarchical: bool) -> Self {
        Self(PolicyAxisRust::new(
            name,
            attributes.as_slice(),
            hierarchical,
        ))
    }

    /// Returns the number of attributes belonging to this axis.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return `true` if the attribute list is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return a string representation of the Policy Axis
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        format!(
            "{}: {:?}, hierarchical: {}",
            &self.0.name, &self.0.attributes, &self.0.hierarchical
        )
    }
}

#[pyclass]
pub struct Policy(pub(super) PolicyRust);

#[pymethods]
impl Policy {
    /// Generates a new policy object with the given number of attribute
    /// creations (revocation + addition) allowed.
    /// Default maximum of attribute creations is u32::MAX
    #[new]
    #[args(max_attribute_creations = "4294967295")]
    fn new(max_attribute_creations: u32) -> Self {
        Self(PolicyRust::new(max_attribute_creations))
    }

    /// Adds the given policy axis to the policy.
    pub fn add_axis(&mut self, axis: &PolicyAxis) -> PyResult<()> {
        self.0
            .add_axis(&axis.0)
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Rotates an attribute, changing its underlying value with an unused
    /// value.
    pub fn rotate(&mut self, attr: &Attribute) -> PyResult<()> {
        self.0
            .rotate(&attr.0)
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Returns the list of Attributes of this Policy.
    pub fn attributes(&self) -> Vec<Attribute> {
        self.0
            .attributes()
            .into_iter()
            .map(|a| Attribute(a))
            .collect()
    }

    /// Returns the list of all attributes values given to this Attribute
    /// over the time after rotations. The current value is returned first
    pub fn attribute_values(&self, attribute: &Attribute) -> PyResult<Vec<u32>> {
        self.0
            .attribute_values(&attribute.0)
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Retrieves the current value of an attribute.
    pub fn attribute_current_value(&self, attribute: &Attribute) -> PyResult<u32> {
        self.0
            .attribute_current_value(&attribute.0)
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Returns a string representation of the Policy
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        format!("{}", &self.0)
    }

    /// Performs deep copy of the Policy
    pub fn deep_copy(&self) -> Self {
        Self(self.0.clone())
    }

    /// JSON serialization
    pub fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.0).map_err(|e| PyException::new_err(e.to_string()))
    }

    /// JSON deserialization
    #[classmethod]
    pub fn from_json(_cls: &PyType, policy_json: &str) -> PyResult<Self> {
        let policy: PolicyRust = serde_json::from_str(policy_json)
            .map_err(|e| PyTypeError::new_err(format!("Error deserializing attributes: {e}")))?;
        Ok(Self(policy))
    }
}
