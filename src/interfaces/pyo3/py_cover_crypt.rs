use abe_policy::AccessPolicy;
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    KeyTrait,
};
use pyo3::{exceptions::PyException, exceptions::PyTypeError, prelude::*, types::PyType};

use crate::{
    api::CoverCrypt as CoverCryptRust,
    interfaces::pyo3::py_abe_policy::Policy,
    interfaces::statics::{
        CoverCryptX25519Aes256, EncryptedHeader, MasterSecretKey as MasterSecretKeyRust,
        PublicKey as PublicKeyRust, SymmetricKey as SymmetricKeyRust,
        UserSecretKey as UserSecretKeyRust,
    },
};

// Pyo3 doc on classes
// https://pyo3.rs/v0.16.2/class.html

#[pyclass]
pub struct MasterSecretKey {
    inner: MasterSecretKeyRust,
}

#[pymethods]
impl MasterSecretKey {
    /// Convert to bytes for sending/saving the key
    pub fn to_bytes(&self) -> PyResult<Vec<u8>> {
        match self.inner.try_to_bytes() {
            Ok(res) => Ok(res),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    /// Read key from bytes
    #[classmethod]
    pub fn from_bytes(_cls: &PyType, key_bytes: Vec<u8>) -> PyResult<Self> {
        match MasterSecretKeyRust::try_from_bytes(&key_bytes) {
            Ok(key) => Ok(MasterSecretKey { inner: key }),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }
}

#[pyclass]
pub struct PublicKey {
    inner: PublicKeyRust,
}

#[pymethods]
impl PublicKey {
    /// Convert to bytes for sending/saving the key
    pub fn to_bytes(&self) -> PyResult<Vec<u8>> {
        match self.inner.try_to_bytes() {
            Ok(res) => Ok(res),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    /// Read key from bytes
    #[classmethod]
    pub fn from_bytes(_cls: &PyType, key_bytes: Vec<u8>) -> PyResult<Self> {
        match PublicKeyRust::try_from_bytes(&key_bytes) {
            Ok(key) => Ok(PublicKey { inner: key }),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }
}

#[pyclass]
pub struct UserSecretKey {
    inner: UserSecretKeyRust,
}

#[pymethods]
impl UserSecretKey {
    /// Convert to bytes for sending/saving the key
    pub fn to_bytes(&self) -> PyResult<Vec<u8>> {
        match self.inner.try_to_bytes() {
            Ok(res) => Ok(res),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    /// Read key from bytes
    #[classmethod]
    pub fn from_bytes(_cls: &PyType, key_bytes: Vec<u8>) -> PyResult<Self> {
        match UserSecretKeyRust::try_from_bytes(&key_bytes) {
            Ok(key) => Ok(UserSecretKey { inner: key }),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }
}

#[pyclass]
pub struct SymmetricKey {
    inner: SymmetricKeyRust,
}

#[pymethods]
impl SymmetricKey {
    /// Convert to bytes for sending/saving the key
    pub fn to_bytes(&self) -> PyResult<Vec<u8>> {
        Ok(self.inner.to_bytes().to_vec())
    }

    /// Read key from bytes
    #[classmethod]
    pub fn from_bytes(_cls: &PyType, key_bytes: Vec<u8>) -> PyResult<Self> {
        match SymmetricKeyRust::try_from_bytes(&key_bytes) {
            Ok(key) => Ok(SymmetricKey { inner: key }),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }
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
        msk: &mut MasterSecretKey,
        pk: &mut PublicKey,
    ) -> PyResult<()> {
        match self
            .inner
            .update_master_keys(&policy.inner, &mut msk.inner, &mut pk.inner)
        {
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
        policy: &Policy,
    ) -> PyResult<UserSecretKey> {
        let access_policy = AccessPolicy::from_boolean_expression(&access_policy_str)
            .map_err(|e| PyTypeError::new_err(format!("Access policy creation failed: {e}")))?;

        match self
            .inner
            .generate_user_secret_key(&msk.inner, &access_policy, &policy.inner)
        {
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
        keep_old_accesses: bool,
    ) -> PyResult<()> {
        let access_policy = AccessPolicy::from_boolean_expression(&access_policy_str)
            .map_err(|e| PyTypeError::new_err(format!("Access policy creation failed: {e}")))?;

        match self.inner.refresh_user_secret_key(
            &mut usk.inner,
            &access_policy,
            &msk.inner,
            &policy.inner,
            keep_old_accesses,
        ) {
            Ok(()) => Ok(()),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    /// Encrypt data symmetrically in a block.
    ///
    /// - `symmetric_key`       : symmetric key
    /// - `plaintext_bytes`     : plaintext to encrypt
    /// - `authenticated_data`  : associated data to be passed to the DEM scheme
    pub fn encrypt_symmetric_block(
        &self,
        symmetric_key: &SymmetricKey,
        plaintext: Vec<u8>,
        authenticated_data: Option<Vec<u8>>,
    ) -> PyResult<Vec<u8>> {
        Ok(self.inner.encrypt(
            &symmetric_key.inner,
            &plaintext,
            authenticated_data.as_deref(),
        )?)
    }

    /// Symmetrically Decrypt encrypted data in a block.
    ///
    /// - `symmetric_key`       : symmetric key
    /// - `ciphertext`          : ciphertext
    /// - `authenticated_data`  : associated data to be passed to the DEM scheme
    pub fn decrypt_symmetric_block(
        &self,
        symmetric_key: &SymmetricKey,
        ciphertext: Vec<u8>,
        authenticated_data: Option<Vec<u8>>,
    ) -> PyResult<Vec<u8>> {
        Ok(self.inner.decrypt(
            &symmetric_key.inner,
            &ciphertext,
            authenticated_data.as_deref(),
        )?)
    }

    /// Generate an encrypted header. A header contains the following elements:
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
        access_policy_str: String,
        public_key: &PublicKey,
        additional_data: Option<Vec<u8>>,
        authenticated_data: Option<Vec<u8>>,
    ) -> PyResult<(SymmetricKey, Vec<u8>)> {
        // Deserialize inputs
        let access_policy = AccessPolicy::from_boolean_expression(&access_policy_str)
            .map_err(|e| PyTypeError::new_err(format!("Access policy creation failed: {e}")))?;

        // Encrypt
        let (symmetric_key, encrypted_header) = EncryptedHeader::generate(
            &self.inner,
            &policy.inner,
            &public_key.inner,
            &access_policy,
            additional_data.as_deref(),
            authenticated_data.as_deref(),
        )?;

        Ok((
            SymmetricKey {
                inner: symmetric_key,
            },
            encrypted_header.try_to_bytes()?,
        ))
    }

    /// Decrypt the given header bytes using a user decryption key.
    ///
    /// - `usk`                     : user secret key
    /// - `encrypted_header_bytes`  : encrypted header bytes
    /// - `authenticated_data`      : authenticated data to use in symmetric decryption
    pub fn decrypt_header(
        &self,
        usk: &UserSecretKey,
        encrypted_header_bytes: Vec<u8>,
        authenticated_data: Option<Vec<u8>>,
    ) -> PyResult<(SymmetricKey, Vec<u8>)> {
        // Finally decrypt symmetric key using given user decryption key
        let cleartext_header = EncryptedHeader::try_from_bytes(&encrypted_header_bytes)?.decrypt(
            &self.inner,
            &usk.inner,
            authenticated_data.as_deref(),
        )?;

        Ok((
            SymmetricKey {
                inner: cleartext_header.symmetric_key,
            },
            cleartext_header.additional_data,
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
    pub fn encrypt(
        &self,
        policy: &Policy,
        access_policy_str: String,
        pk: &PublicKey,
        plaintext: Vec<u8>,
        additional_data: Option<Vec<u8>>,
        authenticated_data: Option<Vec<u8>>,
    ) -> PyResult<Vec<u8>> {
        let access_policy = AccessPolicy::from_boolean_expression(&access_policy_str)
            .map_err(|e| PyTypeError::new_err(format!("Access policy creation failed: {e}")))?;

        // generate encrypted header
        let (symmetric_key, encrypted_header) = EncryptedHeader::generate(
            &self.inner,
            &policy.inner,
            &pk.inner,
            &access_policy,
            additional_data.as_deref(),
            authenticated_data.as_deref(),
        )?;

        // encrypt the plaintext
        let ciphertext =
            self.inner
                .encrypt(&symmetric_key, &plaintext, authenticated_data.as_deref())?;

        // concatenate the encrypted header and the ciphertext
        let mut ser = Serializer::with_capacity(encrypted_header.length() + ciphertext.len());
        encrypted_header.write(&mut ser)?;
        ser.write_array(&ciphertext)
            .map_err(|e| PyTypeError::new_err(format!("Error serializing ciphertext: {e}")))?;
        Ok(ser.finalize())
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
    ) -> PyResult<Vec<u8>> {
        let mut de = Deserializer::new(encrypted_bytes.as_slice());
        // this will read the exact header size
        let header = EncryptedHeader::read(&mut de)?;
        // the rest is the symmetric ciphertext
        let ciphertext = de.finalize();

        // Decrypt header
        let cleartext_header =
            header.decrypt(&self.inner, &usk.inner, authenticated_data.as_deref())?;

        // Decrypt plaintext
        self.inner
            .decrypt(
                &cleartext_header.symmetric_key,
                ciphertext.as_slice(),
                authenticated_data.as_deref(),
            )
            .map_err(|e| PyTypeError::new_err(e.to_string()))
    }
}
