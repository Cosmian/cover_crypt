use crate::{
    api::CoverCrypt as CoverCryptRust,
    interfaces::statics::{
        CoverCryptX25519Aes256,
        MasterSecretKey as MasterSecretKeyRust,
        PublicKey as PublicKeyRust, UserSecretKey as UserSecretKeyRust}
};
use abe_policy::{AccessPolicy, Attribute as AttributeRust, Policy as PolicyRust, PolicyAxis as PolicyAxisRust};
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
    inner: PolicyRust,
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
}

#[pyclass]
pub struct MasterSecretKey {
    inner: MasterSecretKeyRust,
}

#[pyclass]
pub struct PublicKey {
    inner: PublicKeyRust,
}

#[pyclass]
pub struct UserSecretKey {
    inner: UserSecretKeyRust,
}

#[pyclass]
pub struct CoverCrypt {
    inner: CoverCryptX25519Aes256,
}

#[pymethods]
impl CoverCrypt {
    #[new]
    fn new() -> Self {
        CoverCrypt {
            inner: CoverCryptX25519Aes256::default(),
        }
    }

    /// Generate the master authority keys for supplied Policy
    ///
    ///  - `policy` : Policy to use to generate the keys
    pub fn generate_master_keys(&self, policy: &Policy) -> PyResult<(MasterSecretKey, PublicKey)> {
        match self.inner.generate_master_keys(&policy.inner) {
            Ok((msk, pk)) => Ok((MasterSecretKey { inner: msk }, PublicKey { inner: pk })),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    /// Update the master keys according to this new policy.
    ///
    /// When a partition exists in the new policy but not in the master keys,
    /// a new key pair is added to the master keys for that partition.
    /// When a partition exists on the master keys, but not in the new policy,
    /// it is removed from the master keys.
    ///
    ///  - `policy` : Policy to use to generate the keys
    ///  - `msk`    : master secret key
    ///  - `mpk`    : master public key
    pub fn update_master_keys(
        &self,
        policy: &Policy,
        mpk: &mut MasterSecretKey,
        pk: &mut PublicKey
    ) -> PyResult<()> {
        match self.inner.update_master_keys(&policy.inner, &mut mpk.inner, &mut pk.inner) {
            Ok(()) => Ok(()),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    /// Generate a user secret key.
    ///
    /// A new user secret key does NOT include to old (i.e. rotated) partitions
    ///
    /// - `msk`                 : master secret key
    /// - `access_policy_str`   : user access policy
    /// - `policy`              : global policy
    pub fn generate_user_secret_key(
        &self,
        msk: &mut MasterSecretKey,
        access_policy_str: String,
        policy: &Policy) -> PyResult<UserSecretKey> {
        
        let access_policy = AccessPolicy::from_boolean_expression(&access_policy_str)
            .map_err(|e| PyTypeError::new_err(format!("Access policy creation failed: {e}")))?;

        match self.inner.generate_user_secret_key(&msk.inner, &access_policy, &policy.inner) {
            Ok(usk) => Ok(UserSecretKey { inner: usk }),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }
}
