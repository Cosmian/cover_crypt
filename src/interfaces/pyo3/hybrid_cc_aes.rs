// needed to remove wasm_bindgen warnings
#![allow(non_upper_case_globals)]
#![allow(clippy::unused_unit)]
// Wait for `wasm-bindgen` issue 2774: https://github.com/rustwasm/wasm-bindgen/issues/2774

use cosmian_crypto_base::{
    asymmetric::ristretto::X25519Crypto,
    hybrid_crypto::Metadata,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, SymmetricCrypto},
    KeyTrait,
};
use pyo3::{exceptions::PyTypeError, pyfunction, PyResult};

use crate::{
    api::{PrivateKey, PublicKey},
    interfaces::statics::{
        decrypt_hybrid_block as core_decrypt_hybrid_block,
        decrypt_hybrid_header as core_decrypt_hybrid_header,
        encrypt_hybrid_block as core_encrypt_hybrid_block,
        encrypt_hybrid_header as core_encrypt_hybrid_header, ClearTextHeader,
    },
    policies::Attribute,
};

pub const MAX_CLEAR_TEXT_SIZE: usize = 1_usize << 30;

/// Extract header from encrypted bytes
#[pyfunction]
pub fn get_encrypted_header_size(encrypted_bytes: Vec<u8>) -> PyResult<u32> {
    //
    // Check `encrypted_bytes` input param and store it locally
    if encrypted_bytes.len() < 4 {
        return Err(PyTypeError::new_err(
            "Encrypted value must be at least 4-bytes long",
        ));
    }

    //
    // Recover header from `encrypted_bytes`
    let mut header_size_bytes = [0; 4];
    header_size_bytes.copy_from_slice(&encrypted_bytes.to_vec()[0..4]);
    let header_size = u32::from_be_bytes(header_size_bytes);

    Ok(header_size)
}

#[pyfunction]
pub fn encrypt_hybrid_header(
    metadata_bytes: Vec<u8>,
    policy_bytes: Vec<u8>,
    attributes_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    //
    // Deserialize inputs
    let metadata = serde_json::from_slice(&metadata_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing metadata: {e}")))?;
    let policy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing policy: {e}")))?;
    let attributes: Vec<Attribute> = serde_json::from_slice(&attributes_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing attributes: {e}")))?;
    let public_key = PublicKey::try_from_bytes(&public_key_bytes.to_vec())?;

    //
    // Encrypt
    let encrypted_header = core_encrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
        &policy,
        &public_key,
        &attributes,
        Some(&metadata),
    )?;

    Ok((
        encrypted_header.symmetric_key.to_bytes(),
        encrypted_header.header_bytes,
    ))
}

/// Decrypt with a user decryption key an encrypted header
/// of a resource encrypted using an hybrid crypto scheme.
#[pyfunction]
pub fn decrypt_hybrid_header(
    user_decryption_key_bytes: Vec<u8>,
    encrypted_header_bytes: Vec<u8>,
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    //
    // Check `user_decryption_key_bytes` input param and store it locally
    if user_decryption_key_bytes.is_empty() {
        return Err(PyTypeError::new_err("User decryption key is empty"));
    }

    //
    // Check `encrypted_bytes` input param and store it locally
    if encrypted_header_bytes.len() < 4 {
        return Err(PyTypeError::new_err(
            "Size of encrypted value cannot be less than 4!",
        ));
    }

    //
    // Parse user decryption key
    let user_decryption_key = PrivateKey::try_from_bytes(&user_decryption_key_bytes)?;

    //
    // Finally decrypt symmetric key using given user decryption key
    let cleartext_header: ClearTextHeader<Aes256GcmCrypto> =
        core_decrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
            &user_decryption_key,
            &encrypted_header_bytes,
        )?;

    let metadata = cleartext_header
        .meta_data
        .to_bytes()
        .map_err(|e| PyTypeError::new_err(format!("Serialize metadata failed: {e}")))?;

    Ok((cleartext_header.symmetric_key.to_bytes(), metadata))
}

/// Symmetrically Encrypt plaintext data in a block.
#[pyfunction]
pub fn encrypt_hybrid_block(
    symmetric_key_bytes: Vec<u8>,
    uid_bytes: Option<Vec<u8>>,
    block_number: Option<usize>,
    plaintext_bytes: Vec<u8>,
) -> PyResult<Vec<u8>> {
    //
    // Check `plaintext_bytes` input param
    if plaintext_bytes.is_empty() {
        return Err(PyTypeError::new_err("Plaintext value is empty"));
    }

    //
    // Parse symmetric key
    let symmetric_key =
        <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from_bytes(symmetric_key_bytes.to_vec())
            .map_err(|e| PyTypeError::new_err(format!("Deserialize symmetric key failed: {e}")))?;

    //
    // Parse other input params
    let uid = uid_bytes.map_or_else(Vec::new, |v| v.to_vec());
    let block_number_value = block_number.unwrap_or(0);

    //
    // Encrypt block
    let ciphertext = core_encrypt_hybrid_block::<X25519Crypto, Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(
        &symmetric_key,
        &uid,
        block_number_value,
        &plaintext_bytes.to_vec(),
    )?;

    Ok(ciphertext)
}

/// Symmetrically Decrypt encrypted data in a block.
#[pyfunction]
pub fn decrypt_hybrid_block(
    symmetric_key_bytes: Vec<u8>,
    uid_bytes: Option<Vec<u8>>,
    block_number: Option<usize>,
    encrypted_bytes: Vec<u8>,
) -> PyResult<Vec<u8>> {
    //
    // Check `user_decryption_key_bytes` input param and store it locally
    if symmetric_key_bytes.len() != 32 {
        return Err(PyTypeError::new_err("Symmetric key must be 32-bytes long"));
    }

    //
    // Check `encrypted_bytes` input param and store it locally
    if encrypted_bytes.is_empty() {
        return Err(PyTypeError::new_err("Encrypted value is empty"));
    }

    //
    // Parse symmetric key
    let symmetric_key =
        <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from_bytes(symmetric_key_bytes.to_vec())
            .map_err(|e| PyTypeError::new_err(format!("Deserialize symmetric key failed: {e}")))?;

    //
    // Parse other input params
    let uid = uid_bytes.map_or(vec![], |v| v.to_vec());
    let block_number_value = block_number.unwrap_or(0);

    //
    // Decrypt block
    let cleartext = core_decrypt_hybrid_block::<X25519Crypto, Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(
        &symmetric_key,
        &uid,
        block_number_value as usize,
        &encrypted_bytes.to_vec(),
    )?;

    Ok(cleartext)
}

#[pyfunction]
pub fn encrypt(
    metadata_bytes: Vec<u8>,
    policy_bytes: Vec<u8>,
    attributes_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
    plaintext: Vec<u8>,
) -> PyResult<Vec<u8>> {
    let metadata: Metadata = serde_json::from_slice(&metadata_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing metadata: {e}")))?;

    let header = encrypt_hybrid_header(
        metadata_bytes,
        policy_bytes,
        attributes_bytes,
        public_key_bytes,
    )?;

    let ciphertext = encrypt_hybrid_block(header.0, Some(metadata.uid), None, plaintext)?;

    // Encrypted value is composed of: HEADER_LEN (4 bytes) | HEADER | AES_DATA
    let mut encrypted = Vec::<u8>::with_capacity(4 + header.1.len() + ciphertext.len());
    encrypted.extend_from_slice(&u32::to_be_bytes(header.1.len() as u32));
    encrypted.extend_from_slice(&header.1);
    encrypted.extend_from_slice(&ciphertext);
    Ok(encrypted)
}

#[pyfunction]
pub fn decrypt(user_decryption_key_bytes: Vec<u8>, encrypted_bytes: Vec<u8>) -> PyResult<Vec<u8>> {
    let header_size = get_encrypted_header_size(encrypted_bytes.clone())?;
    let header = encrypted_bytes[4..4 + header_size as usize].to_vec();
    let ciphertext = encrypted_bytes[4 + header_size as usize..].to_vec();

    let cleartext_header = decrypt_hybrid_header(user_decryption_key_bytes, header)?;

    let metadata = Metadata::from_bytes(&cleartext_header.1)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing metadata: {e}")))?;

    let cleartext = decrypt_hybrid_block(cleartext_header.0, Some(metadata.uid), None, ciphertext)?;
    Ok(cleartext)
}
