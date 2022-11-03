use crate::{
    api::CoverCrypt as CoverCryptRust,
    interfaces::statics::{
        CoverCryptX25519Aes256,
        EncryptedHeader as EncryptedHeaderRust,
        MasterSecretKey as MasterSecretKeyRust,
        PublicKey as PublicKeyRust, UserSecretKey as UserSecretKeyRust,
        SymmetricKey as SymmetricKeyRust
    }
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


#[pyclass]
struct SymmetricKey {
    inner: SymmetricKeyRust
}

#[pyclass]
pub struct EncryptedHeader {
    inner: EncryptedHeaderRust
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
        msk: &MasterSecretKey,
        access_policy_str: String,
        policy: &Policy) -> PyResult<UserSecretKey> {
        
        let access_policy = AccessPolicy::from_boolean_expression(&access_policy_str)
            .map_err(|e| PyTypeError::new_err(format!("Access policy creation failed: {e}")))?;

        match self.inner.generate_user_secret_key(&msk.inner, &access_policy, &policy.inner) {
            Ok(usk) => Ok(UserSecretKey { inner: usk }),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    /// Refresh the user key according to the given master key and access policy.
    ///
    /// The user key will be granted access to the current partitions, as determined by its access policy.
    /// If preserve_old_partitions_access is set, the user access to rotated partitions will be preserved
    ///
    /// - `usk`                 : the user key to refresh
    /// - `access_policy`       : the access policy of the user key
    /// - `msk`                 : master secret key
    /// - `policy`              : global policy of the master secret key
    /// - `keep_old_accesses`   : whether access to old partitions (i.e. before rotation) should be kept
    pub fn refresh_user_secret_key(
        &self,
        usk: &mut UserSecretKey,
        access_policy_str: String,
        msk: &MasterSecretKey,
        policy: &Policy,
        keep_old_accesses: bool) -> PyResult<()> {
        
        let access_policy = AccessPolicy::from_boolean_expression(&access_policy_str)
            .map_err(|e| PyTypeError::new_err(format!("Access policy creation failed: {e}")))?;

        match self.inner.refresh_user_secret_key(&mut usk.inner, &access_policy, &msk.inner, &policy.inner, keep_old_accesses) {
            Ok(()) => Ok(()),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    /// Hybrid encryption. Concatenates the encrypted header and the symmetric
    /// ciphertext.
    ///
    /// - `policy`              : policy
    /// - `access_policy_str`   : the access policy
    /// - `pk`                  : CoverCrypt public key
    /// - `plaintext`           : plaintext to encrypt using the DEM
    /// - `additional_data`     : additional data to symmetrically encrypt in the header
    /// - `authenticated_data`  : authenticated data to use in symmetric encryptions
    pub fn encrypt(
        &self,
        policy: &Policy,
        access_policy_str: String,
        pk: &PublicKey,
        plaintext: Vec<u8>,
        additional_data: Option<Vec<u8>>,
        authenticated_data: Option<Vec<u8>>,
    ) -> PyResult<(EncryptedHeader, Vec<u8>)> {
        
        let access_policy = AccessPolicy::from_boolean_expression(&access_policy_str)
        .map_err(|e| PyTypeError::new_err(format!("Access policy creation failed: {e}")))?;

        // generate encrypted header
        let (symmetric_key, encrypted_header) = EncryptedHeaderRust::generate(
            &self.inner,
            &policy.inner,
            &pk.inner,
            &access_policy,
            additional_data.as_deref(),
            authenticated_data.as_deref(),
        )?;

        // encrypt the plaintext
        let ciphertext = self.inner.encrypt(&symmetric_key, &plaintext, authenticated_data.as_deref())?;

        Ok((EncryptedHeader {inner: encrypted_header}, ciphertext))
    }

    /// Hybrid decryption.
    ///
    /// - `usk`                 : user secret key
    /// - `encrypted_header`    : encrypted header
    /// - `cyphertext_bytes`    : symmetric ciphertext
    /// - `authenticated_data`  : authenticated data to use in symmetric decryptions
    pub fn decrypt(
        &self,
        usk: &UserSecretKey,
        encrypted_header: &EncryptedHeader,
        cyphertext_bytes: Vec<u8>,
        authenticated_data: Option<Vec<u8>>,
    ) -> PyResult<Vec<u8>> {
        // Decrypt header
        let cleartext_header = encrypted_header.inner.decrypt(
            &self.inner,
            &usk.inner,
            authenticated_data.as_deref(),
        )?;

        // Decrypt plaintext
        self.inner.decrypt(
                &cleartext_header.symmetric_key,
                cyphertext_bytes.as_slice(),
                authenticated_data.as_deref(),
            )
            .map_err(|e| PyTypeError::new_err(e.to_string()))
    }
}
