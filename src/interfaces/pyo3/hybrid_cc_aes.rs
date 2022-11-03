// needed to remove wasm_bindgen warnings
#![allow(non_upper_case_globals)]
// Wait for `wasm-bindgen` issue 2774: https://github.com/rustwasm/wasm-bindgen/issues/2774

use crate::{
    api::CoverCrypt,
    interfaces::statics::{
        CoverCryptX25519Aes256, EncryptedHeader, PublicKey, SymmetricKey, UserSecretKey,
    },
};
use abe_policy::AccessPolicy;
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    KeyTrait,
};
use pyo3::{exceptions::PyTypeError, pyfunction, PyResult};

/// Generate an encrypted header. A header contains the following elements:
///
/// - `encapsulation_size`  : the size of the symmetric key encapsulation (u32)
/// - `encapsulation`       : symmetric key encapsulation using CoverCrypt
/// - `encrypted_metadata`  : Optional metadata encrypted using the DEM
///
/// Parameters:
///
/// - `policy_bytes`        : serialized global policy
/// - `attributes_bytes`    : serialized access policy
/// - `public_key_bytes`    : CoverCrypt public key
/// - `additional_data`     : additional data to encrypt with the header
/// - `authenticated_data`  : authenticated data to use in symmetric encryption
#[pyfunction]
pub fn encrypt_hybrid_header(
    policy_bytes: Vec<u8>,
    access_policy: String,
    public_key_bytes: Vec<u8>,
    additional_data: Vec<u8>,
    authenticated_data: Vec<u8>,
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    //
    // Deserialize inputs
    let policy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing policy: {e}")))?;
    let access_policy = AccessPolicy::from_boolean_expression(&access_policy)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing attributes: {e}")))?;
    let public_key = PublicKey::try_from_bytes(&public_key_bytes)?;

    let additional_data = if additional_data.is_empty() {
        None
    } else {
        Some(additional_data)
    };

    let authenticated_data = if authenticated_data.is_empty() {
        None
    } else {
        Some(authenticated_data)
    };

    //
    // Encrypt
    let (symmetric_key, encrypted_header) = EncryptedHeader::generate(
        &CoverCryptX25519Aes256::default(),
        &policy,
        &public_key,
        &access_policy,
        additional_data.as_deref(),
        authenticated_data.as_deref(),
    )?;

    Ok((
        symmetric_key.to_bytes().to_vec(),
        encrypted_header.try_to_bytes()?,
    ))
}

/// Decrypt the given header bytes using a user decryption key.
///
/// - `usk_bytes`               : serialized user secret key
/// - `encrypted_header_bytes`  : encrypted header bytes
/// - `authenticated_data`      : authenticated data to use in symmetric
///   decryption
#[pyfunction]
pub fn decrypt_hybrid_header(
    usk_bytes: Vec<u8>,
    encrypted_header_bytes: Vec<u8>,
    authenticated_data: Vec<u8>,
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let authenticated_data = if authenticated_data.is_empty() {
        None
    } else {
        Some(authenticated_data)
    };

    //
    // Finally decrypt symmetric key using given user decryption key
    let cleartext_header = EncryptedHeader::try_from_bytes(&encrypted_header_bytes)?.decrypt(
        &CoverCryptX25519Aes256::default(),
        &UserSecretKey::try_from_bytes(&usk_bytes)?,
        authenticated_data.as_deref(),
    )?;

    Ok((
        cleartext_header.symmetric_key.to_bytes().to_vec(),
        cleartext_header.additional_data,
    ))
}

/// Encrypt data symmetrically in a block.
///
/// - `symmetric_key`       : symmetric key
/// - `plaintext_bytes`     : plaintext to encrypt
/// - `authenticated_data`  : associated data to be passed to the DEM scheme
#[pyfunction]
pub fn encrypt_symmetric_block(
    symmetric_key: Vec<u8>,
    plaintext: Vec<u8>,
    authenticated_data: Vec<u8>,
) -> PyResult<Vec<u8>> {
    let authenticated_data = if authenticated_data.is_empty() {
        None
    } else {
        Some(authenticated_data)
    };

    //
    // Parse symmetric key
    let symmetric_key = SymmetricKey::try_from_bytes(&symmetric_key)
        .map_err(|e| PyTypeError::new_err(format!("Deserialize symmetric key failed: {e}")))?;

    //
    // Encrypt block
    Ok(CoverCryptX25519Aes256::default().encrypt(
        &symmetric_key,
        &plaintext,
        authenticated_data.as_deref(),
    )?)
}

/// Symmetrically Decrypt encrypted data in a block.
///
/// - `symmetric_key`       : symmetric key
/// - `ciphertext`          : ciphertext
/// - `authenticated_data`  : associated data to be passed to the DEM scheme
#[pyfunction]
pub fn decrypt_symmetric_block(
    symmetric_key: Vec<u8>,
    ciphertext: Vec<u8>,
    authenticated_data: Vec<u8>,
) -> PyResult<Vec<u8>> {
    let authenticated_data = if authenticated_data.is_empty() {
        None
    } else {
        Some(authenticated_data)
    };

    //
    // Parse symmetric key
    let symmetric_key = SymmetricKey::try_from_bytes(&symmetric_key)
        .map_err(|e| PyTypeError::new_err(format!("Deserialize symmetric key failed: {e}")))?;

    //
    // Decrypt block
    Ok(CoverCryptX25519Aes256::default().decrypt(
        &symmetric_key,
        &ciphertext,
        authenticated_data.as_deref(),
    )?)
}

/// Hybrid encryption. Concatenates the encrypted header and the symmetric
/// ciphertext.
///
/// - `policy_bytes`        : policy
/// - `attributes_bytes`    : attributes
/// - `pk_bytes`            : CoverCrypt public key
/// - `plaintext`           : plaintext to encrypt using the DEM
/// - `additional_data`     : additional data to symmetrically encrypt in the
///   header
/// - `authenticated_data`  : authenticated data to use in symmetric encryptions
#[pyfunction]
pub fn encrypt(
    policy_bytes: Vec<u8>,
    access_policy: String,
    pk: Vec<u8>,
    plaintext: Vec<u8>,
    additional_data: Vec<u8>,
    authenticated_data: Vec<u8>,
) -> PyResult<Vec<u8>> {
    let additional_data = if additional_data.is_empty() {
        None
    } else {
        Some(additional_data)
    };

    let authenticated_data = if authenticated_data.is_empty() {
        None
    } else {
        Some(authenticated_data)
    };

    let policy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing policy: {e}")))?;
    let access_policy = AccessPolicy::from_boolean_expression(&access_policy)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing attributes: {e}")))?;
    let pk = PublicKey::try_from_bytes(&pk)?;

    // instantiate CoverCrypt
    let cover_crypt = CoverCryptX25519Aes256::default();

    // generate encrypted header
    let (symmetric_key, encrypted_header) = EncryptedHeader::generate(
        &cover_crypt,
        &policy,
        &pk,
        &access_policy,
        additional_data.as_deref(),
        authenticated_data.as_deref(),
    )?;

    // encrypt the plaintext
    let ciphertext =
        cover_crypt.encrypt(&symmetric_key, &plaintext, authenticated_data.as_deref())?;

    // concatenate the encrypted header and the ciphertext
    let mut ser = Serializer::with_capacity(encrypted_header.length() + ciphertext.len());
    encrypted_header.write(&mut ser)?;
    ser.write_array(&ciphertext)
        .map_err(|e| PyTypeError::new_err(format!("Error serializing ciphertext: {e}")))?;
    Ok(ser.finalize())
}

/// Hybrid decryption.
///
/// - `usk_bytes`           : serialized user secret key
/// - `encrypted_bytes`     : encrypted header || symmetric ciphertext
/// - `authenticated_data`  : authenticated data to use in symmetric decryptions
#[pyfunction]
pub fn decrypt(
    usk_bytes: Vec<u8>,
    encrypted_bytes: Vec<u8>,
    authenticated_data: Vec<u8>,
) -> PyResult<Vec<u8>> {
    let mut de = Deserializer::new(encrypted_bytes.as_slice());
    // this will read the exact header size
    let header = EncryptedHeader::read(&mut de)?;
    // the rest is the symmetric ciphertext
    let ciphertext = de.finalize();

    let authenticated_data = if authenticated_data.is_empty() {
        None
    } else {
        Some(authenticated_data)
    };

    // Instantiate CoverCrypt
    let cover_crypt = CoverCryptX25519Aes256::default();

    // Decrypt header
    let cleartext_header = header.decrypt(
        &cover_crypt,
        &UserSecretKey::try_from_bytes(&usk_bytes)?,
        authenticated_data.as_deref(),
    )?;

    // Decrypt plaintext
    cover_crypt
        .decrypt(
            &cleartext_header.symmetric_key,
            ciphertext.as_slice(),
            authenticated_data.as_deref(),
        )
        .map_err(|e| PyTypeError::new_err(e.to_string()))
}
