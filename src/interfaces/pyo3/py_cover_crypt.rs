use abe_policy::AccessPolicy;
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    symmetric_crypto::Dem,
    symmetric_crypto::SymKey,
};
use pyo3::{exceptions::PyTypeError, prelude::*, types::PyType, PyErr};

use crate::{
    api::CoverCrypt as CoverCryptRust,
    interfaces::{
        pyo3::py_abe_policy::Policy,
        statics::{
            CoverCryptDem, CoverCryptX25519Aes256, EncryptedHeader,
            MasterSecretKey as MasterSecretKeyRust, PublicKey as PublicKeyRust,
            SymmetricKey as SymmetricKeyRust, UserSecretKey as UserSecretKeyRust,
        },
    },
};

// Vec[u8] return type is converted to a list of bytes instead of
// the type bytes in Python so we need an explicit conversion
fn convert_to_pybytes(bytes: &[u8], py: Python) -> PyObject {
    bytes.into_py(py)
}

// Pyo3 doc on classes
// https://pyo3.rs/v0.16.2/class.html

#[pyclass]
pub struct MasterSecretKey(MasterSecretKeyRust);

impl_key_byte!(MasterSecretKey, MasterSecretKeyRust);

#[pyclass]
pub struct PublicKey(PublicKeyRust);

impl_key_byte!(PublicKey, PublicKeyRust);

#[pyclass]
pub struct UserSecretKey(UserSecretKeyRust);

impl_key_byte!(UserSecretKey, UserSecretKeyRust);

#[pyclass]
pub struct SymmetricKey(SymmetricKeyRust);

#[pymethods]
impl SymmetricKey {
    /// Converts key to bytes
    pub fn to_bytes(&self, py: Python) -> PyResult<PyObject> {
        Ok(convert_to_pybytes(self.0.as_bytes(), py))
    }

    /// Reads key from bytes
    #[classmethod]
    pub fn from_bytes(_cls: &PyType, key_bytes: [u8; CoverCryptDem::KEY_LENGTH]) -> PyResult<Self> {
        Ok(Self(SymmetricKeyRust::from_bytes(key_bytes)))
    }
}

#[pyclass]
pub struct CoverCrypt(CoverCryptX25519Aes256);

#[pymethods]
impl CoverCrypt {
    #[new]
    fn new() -> Self {
        Self(CoverCryptX25519Aes256::default())
    }

    /// Generate the master authority keys for supplied Policy
    ///
    ///  - `policy` : Policy to use to generate the keys
    pub fn generate_master_keys(&self, policy: &Policy) -> PyResult<(MasterSecretKey, PublicKey)> {
        match self.0.generate_master_keys(&policy.0) {
            Ok((msk, pk)) => Ok((MasterSecretKey(msk), PublicKey(pk))),
            Err(e) => Err(PyErr::from(e)),
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
        msk: &mut MasterSecretKey,
        pk: &mut PublicKey,
    ) -> PyResult<()> {
        self.0
            .update_master_keys(&policy.0, &mut msk.0, &mut pk.0)
            .map_err(PyErr::from)
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
        access_policy_str: &str,
        policy: &Policy,
    ) -> PyResult<UserSecretKey> {
        let access_policy = AccessPolicy::from_boolean_expression(access_policy_str)
            .map_err(|e| PyTypeError::new_err(format!("Access policy creation failed: {e}")))?;

        match self
            .0
            .generate_user_secret_key(&msk.0, &access_policy, &policy.0)
        {
            Ok(usk) => Ok(UserSecretKey(usk)),
            Err(e) => Err(PyErr::from(e)),
        }
    }

    /// Refreshes the user key according to the given master key and access policy.
    ///
    /// The user key will be granted access to the current partitions, as determined by its access policy.
    /// If `preserve_old_partitions_access` is set, the user access to rotated partitions will be preserved
    ///
    /// - `usk`                 : the user key to refresh
    /// - `access_policy`       : the access policy of the user key
    /// - `msk`                 : master secret key
    /// - `policy`              : global policy of the master secret key
    /// - `keep_old_accesses`   : whether access to old partitions (i.e. before rotation) should be kept
    pub fn refresh_user_secret_key(
        &self,
        usk: &mut UserSecretKey,
        access_policy_str: &str,
        msk: &MasterSecretKey,
        policy: &Policy,
        keep_old_accesses: bool,
    ) -> PyResult<()> {
        let access_policy = AccessPolicy::from_boolean_expression(access_policy_str)
            .map_err(|e| PyTypeError::new_err(format!("Access policy creation failed: {e}")))?;

        self.0
            .refresh_user_secret_key(
                &mut usk.0,
                &access_policy,
                &msk.0,
                &policy.0,
                keep_old_accesses,
            )
            .map_err(PyErr::from)
    }

    /// Encrypts data symmetrically in a block.
    ///
    /// - `symmetric_key`       : symmetric key
    /// - `plaintext`     : plaintext to encrypt
    /// - `authenticated_data`  : associated data to be passed to the DEM scheme
    pub fn encrypt_symmetric_block(
        &self,
        symmetric_key: &SymmetricKey,
        plaintext: Vec<u8>,
        authenticated_data: Option<Vec<u8>>,
        py: Python,
    ) -> PyResult<PyObject> {
        Ok(convert_to_pybytes(
            &self
                .0
                .encrypt(&symmetric_key.0, &plaintext, authenticated_data.as_deref())?,
            py,
        ))
    }

    /// Symmetrically Decrypts encrypted data in a block.
    ///
    /// - `symmetric_key`       : symmetric key
    /// - `ciphertext`          : ciphertext
    /// - `authenticated_data`  : associated data to be passed to the DEM scheme
    pub fn decrypt_symmetric_block(
        &self,
        symmetric_key: &SymmetricKey,
        ciphertext: Vec<u8>,
        authenticated_data: Option<Vec<u8>>,
        py: Python,
    ) -> PyResult<PyObject> {
        Ok(convert_to_pybytes(
            &self
                .0
                .decrypt(&symmetric_key.0, &ciphertext, authenticated_data.as_deref())?,
            py,
        ))
    }

    /// Generates an encrypted header. A header contains the following elements:
    ///
    /// - `encapsulation_size`  : the size of the symmetric key encapsulation (u32)
    /// - `encapsulation`       : symmetric key encapsulation using CoverCrypt
    /// - `encrypted_metadata`  : Optional metadata encrypted using the DEM
    ///
    /// Parameters:
    ///
    /// - `policy`              : global policy
    /// - `access_policy_str`   : access policy
    /// - `public_key`          : CoverCrypt public key
    /// - `additional_data`     : additional data to encrypt with the header
    /// - `authenticated_data`  : authenticated data to use in symmetric encryption
    pub fn encrypt_header(
        &self,
        policy: &Policy,
        access_policy_str: &str,
        public_key: &PublicKey,
        additional_data: Option<Vec<u8>>,
        authenticated_data: Option<Vec<u8>>,
        py: Python,
    ) -> PyResult<(SymmetricKey, PyObject)> {
        // Deserialize inputs
        let access_policy = AccessPolicy::from_boolean_expression(access_policy_str)
            .map_err(|e| PyTypeError::new_err(format!("Access policy creation failed: {e}")))?;

        // Encrypt
        let (symmetric_key, encrypted_header) = EncryptedHeader::generate(
            &self.0,
            &policy.0,
            &public_key.0,
            &access_policy,
            additional_data.as_deref(),
            authenticated_data.as_deref(),
        )?;

        Ok((
            SymmetricKey(symmetric_key),
            convert_to_pybytes(&encrypted_header.try_to_bytes()?, py),
        ))
    }

    /// Decrypts the given header bytes using a user decryption key.
    ///
    /// - `usk`                     : user secret key
    /// - `encrypted_header_bytes`  : encrypted header bytes
    /// - `authenticated_data`      : authenticated data to use in symmetric decryption
    pub fn decrypt_header(
        &self,
        usk: &UserSecretKey,
        encrypted_header_bytes: Vec<u8>,
        authenticated_data: Option<Vec<u8>>,
        py: Python,
    ) -> PyResult<(SymmetricKey, PyObject)> {
        // Finally decrypt symmetric key using given user decryption key
        let cleartext_header = EncryptedHeader::try_from_bytes(&encrypted_header_bytes)?.decrypt(
            &self.0,
            &usk.0,
            authenticated_data.as_deref(),
        )?;

        Ok((
            SymmetricKey(cleartext_header.symmetric_key),
            convert_to_pybytes(&cleartext_header.additional_data, py),
        ))
    }

    /// Hybrid encryption. Concatenates the encrypted header and the symmetric
    /// ciphertext.
    ///
    /// - `policy`              : global policy
    /// - `access_policy_str`   : access policy
    /// - `pk`                  : CoverCrypt public key
    /// - `plaintext`           : plaintext to encrypt using the DEM
    /// - `additional_data`     : additional data to symmetrically encrypt in the header
    /// - `authenticated_data`  : authenticated data to use in symmetric encryptions
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt(
        &self,
        policy: &Policy,
        access_policy_str: &str,
        pk: &PublicKey,
        plaintext: Vec<u8>,
        additional_data: Option<Vec<u8>>,
        authenticated_data: Option<Vec<u8>>,
        py: Python,
    ) -> PyResult<PyObject> {
        let access_policy = AccessPolicy::from_boolean_expression(access_policy_str)
            .map_err(|e| PyTypeError::new_err(format!("Access policy creation failed: {e}")))?;

        // generates encrypted header
        let (symmetric_key, encrypted_header) = EncryptedHeader::generate(
            &self.0,
            &policy.0,
            &pk.0,
            &access_policy,
            additional_data.as_deref(),
            authenticated_data.as_deref(),
        )?;

        // encrypts the plaintext
        let ciphertext =
            self.0
                .encrypt(&symmetric_key, &plaintext, authenticated_data.as_deref())?;

        // concatenates the encrypted header and the ciphertext
        let mut ser = Serializer::with_capacity(encrypted_header.length() + ciphertext.len());
        encrypted_header.write(&mut ser)?;
        ser.write_array(&ciphertext)
            .map_err(|e| PyTypeError::new_err(format!("Error serializing ciphertext: {e}")))?;
        Ok(convert_to_pybytes(&ser.finalize(), py))
    }

    /// Hybrid decryption.
    ///
    /// - `usk`                 : user secret key
    /// - `encrypted_bytes`     : encrypted header || symmetric ciphertext
    /// - `authenticated_data`  : authenticated data to use in symmetric decryptions
    pub fn decrypt(
        &self,
        usk: &UserSecretKey,
        encrypted_bytes: Vec<u8>,
        authenticated_data: Option<Vec<u8>>,
        py: Python,
    ) -> PyResult<PyObject> {
        let mut de = Deserializer::new(encrypted_bytes.as_slice());
        // this will read the exact header size
        let header = EncryptedHeader::read(&mut de)?;
        // the rest is the symmetric ciphertext
        let ciphertext = de.finalize();

        // decrypts the header
        let cleartext_header = header.decrypt(&self.0, &usk.0, authenticated_data.as_deref())?;

        Ok(convert_to_pybytes(
            &self.0.decrypt(
                &cleartext_header.symmetric_key,
                ciphertext.as_slice(),
                authenticated_data.as_deref(),
            )?,
            py,
        ))
    }
}
