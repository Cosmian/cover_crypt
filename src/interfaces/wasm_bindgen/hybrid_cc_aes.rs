// needed to remove wasm_bindgen warnings
#![allow(non_upper_case_globals)]
#![allow(clippy::unused_unit)]
// Wait for `wasm-bindgen` issue 2774: https://github.com/rustwasm/wasm-bindgen/issues/2774

use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    symmetric_crypto::{Dem, SymKey},
    KeyTrait,
};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use crate::{
    abe_policy::AccessPolicy,
    statics::{CoverCryptX25519Aes256, EncryptedHeader, PublicKey, UserSecretKey, DEM},
    CoverCrypt,
};

pub const MAX_CLEAR_TEXT_SIZE: usize = 1 << 30;

#[wasm_bindgen]
pub fn webassembly_encrypt_hybrid_header(
    policy_bytes: Vec<u8>,
    access_policy: String,
    public_key_bytes: Uint8Array,
    header_metadata: Uint8Array,
    authentication_data: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let policy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| JsValue::from_str(&format!("Error deserializing policy: {e}")))?;
    let access_policy = AccessPolicy::from_boolean_expression(&access_policy)
        .map_err(|e| JsValue::from_str(&format!("Error reading access policy: {e}")))?;
    let public_key = PublicKey::try_from_bytes(&public_key_bytes.to_vec())
        .map_err(|e| JsValue::from_str(&format!("Error deserializing public key: {e}")))?;
    let header_metadata = if header_metadata.is_null() {
        None
    } else {
        Some(header_metadata.to_vec())
    };
    let authentication_data = if authentication_data.is_null() {
        None
    } else {
        Some(authentication_data.to_vec())
    };

    let (symmetric_key, encrypted_header) = EncryptedHeader::generate(
        &CoverCryptX25519Aes256::default(),
        &policy,
        &public_key,
        &access_policy,
        header_metadata.as_deref(),
        authentication_data.as_deref(),
    )
    .map_err(|e| JsValue::from_str(&format!("Error encrypting header: {e}")))?;
    let symmetric_key_bytes = symmetric_key.into_bytes();
    let encrypted_header_bytes = encrypted_header
        .try_to_bytes()
        .map_err(|e| JsValue::from_str(&format!("Error serializing encrypted header: {e}")))?;
    let mut res = Vec::with_capacity(symmetric_key_bytes.len() + encrypted_header_bytes.len());
    res.extend_from_slice(&symmetric_key_bytes);
    res.extend_from_slice(&encrypted_header_bytes);
    Ok(Uint8Array::from(res.as_slice()))
}

// -------------------------------
//         Decryption
// -------------------------------

/// Decrypt with a user decryption key an encrypted header
/// of a resource encrypted using an hybrid crypto scheme.
#[wasm_bindgen]
pub fn webassembly_decrypt_hybrid_header(
    usk_bytes: Uint8Array,
    encrypted_header_bytes: Uint8Array,
    authentication_data: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    //
    // Parse user decryption key
    let usk = UserSecretKey::try_from_bytes(usk_bytes.to_vec().as_slice())
        .map_err(|e| JsValue::from_str(&format!("Error deserializing user decryption key: {e}")))?;
    let authentication_data = if authentication_data.is_null() {
        None
    } else {
        Some(authentication_data.to_vec())
    };

    //
    // Parse encrypted header
    let encrypted_header = EncryptedHeader::try_from_bytes(
        encrypted_header_bytes.to_vec().as_slice(),
    )
    .map_err(|e| JsValue::from_str(&format!("Error deserializing encrypted header: {e}")))?;

    //
    // Finally decrypt symmetric key using given user decryption key
    let cleartext_header = encrypted_header
        .decrypt(
            &CoverCryptX25519Aes256::default(),
            &usk,
            authentication_data.as_deref(),
        )
        .map_err(|e| JsValue::from_str(&format!("Error decrypting hybrid header: {e}")))?;

    Ok(Uint8Array::from(
        cleartext_header
            .try_to_bytes()
            .map_err(|e| JsValue::from_str(&format!("Error serializing decrypted header: {e}")))?
            .as_slice(),
    ))
}

/// Symmetrically Encrypt plaintext data in a block.
#[wasm_bindgen]
pub fn webassembly_encrypt_symmetric_block(
    symmetric_key_bytes: Uint8Array,
    plaintext_bytes: Uint8Array,
    authentication_data: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    //
    // Check `plaintext_bytes` input parameter
    if plaintext_bytes.length() == 0 {
        return Err(JsValue::from_str("Plaintext value is empty"));
    }

    //
    // Parse symmetric key
    let symmetric_key =
        <DEM as Dem<{ DEM::KEY_LENGTH }>>::Key::try_from_bytes(&symmetric_key_bytes.to_vec())
            .map_err(|e| JsValue::from_str(&format!("Error parsing symmetric key: {e}")))?;

    //
    // Encrypt block
    let authentication_data = if authentication_data.is_null() {
        None
    } else {
        Some(authentication_data.to_vec())
    };
    let ciphertext = CoverCryptX25519Aes256::default()
        .encrypt(
            &symmetric_key,
            &plaintext_bytes.to_vec(),
            authentication_data.as_deref(),
        )
        .map_err(|e| JsValue::from_str(&format!("Error encrypting block: {e}")))?;

    Ok(Uint8Array::from(&ciphertext[..]))
}

/// Symmetrically Decrypt encrypted data in a block.
#[wasm_bindgen]
pub fn webassembly_decrypt_symmetric_block(
    symmetric_key_bytes: Uint8Array,
    encrypted_bytes: Uint8Array,
    authentication_data: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    //
    // Parse symmetric key
    let symmetric_key =
        <DEM as Dem<{ DEM::KEY_LENGTH }>>::Key::try_from_bytes(&symmetric_key_bytes.to_vec())
            .map_err(|e| JsValue::from_str(&format!("Error parsing symmetric key: {e}")))?;

    //
    // Decrypt `blockKey<KeyLength>`
    let authentication_data = if authentication_data.is_null() {
        None
    } else {
        Some(authentication_data.to_vec())
    };

    let cleartext = CoverCryptX25519Aes256::default()
        .decrypt(
            &symmetric_key,
            &encrypted_bytes.to_vec(),
            authentication_data.as_deref(),
        )
        .map_err(|e| JsValue::from_str(&format!("Error decrypting block: {e}")))?;

    Ok(Uint8Array::from(&cleartext[..]))
}

/// Generates both a encrypted header and a DEM encryption of the `plaintext`,
/// with the header metadata as associated data.
///
/// - `metadata_bytes`      : serialized metadata
/// - `policy_bytes`        : serialized policy
/// - `attribute_bytes`     : serialized attributes to use in the encapsulation
/// - `pk`                  : CoverCrypt public key
/// - `plaintext`           : message to encrypt with the DEM
/// - `header_metadata`     : additional data to symmetrically encrypt in the
///   header
/// - `authentication_data` : optional data used for authentication
#[wasm_bindgen]
pub fn webassembly_hybrid_encrypt(
    policy_bytes: Vec<u8>,
    access_policy: String,
    pk: Uint8Array,
    plaintext: Uint8Array,
    header_metadata: Uint8Array,
    authentication_data: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let policy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| JsValue::from_str(&format!("Error parsing policy: {e}")))?;
    let access_policy = AccessPolicy::from_boolean_expression(&access_policy)
        .map_err(|e| JsValue::from_str(&format!("Error reading access policy: {e}")))?;
    let pk = PublicKey::try_from_bytes(&pk.to_vec())
        .map_err(|e| JsValue::from_str(&format!("Error parsing public key: {e}")))?;
    let header_metadata = if header_metadata.is_null() {
        None
    } else {
        Some(header_metadata.to_vec())
    };

    let authentication_data = if authentication_data.is_null() {
        None
    } else {
        Some(authentication_data.to_vec())
    };

    // instantiate CoverCrypt
    let cover_crypt = CoverCryptX25519Aes256::default();
    let (symmetric_key, encrypted_header) = EncryptedHeader::generate(
        &cover_crypt,
        &policy,
        &pk,
        &access_policy,
        header_metadata.as_deref(),
        authentication_data.as_deref(),
    )
    .map_err(|e| JsValue::from_str(&format!("Error encrypting header: {e}")))?;

    // encrypt the plaintext
    let ciphertext = cover_crypt
        .encrypt(
            &symmetric_key,
            &plaintext.to_vec(),
            authentication_data.as_deref(),
        )
        .map_err(|e| JsValue::from_str(&format!("Error encrypting symmetric plaintext: {e}")))?;

    // concatenate the encrypted header and the ciphertext
    let mut ser = Serializer::with_capacity(encrypted_header.length() + ciphertext.len());
    ser.write(&encrypted_header)
        .map_err(|e| JsValue::from_str(&format!("Error serializing encrypted header: {e}")))?;
    ser.write_array(&ciphertext)
        .map_err(|e| JsValue::from_str(&format!("Error writing ciphertext: {e}")))?;
    Ok(Uint8Array::from(ser.finalize().as_slice()))
}

/// Decrypt the DEM ciphertext with the header encapsulated symmetric key,
/// with the header metadata as associated data.
///
/// - `usk_bytes`           : serialized user secret key
/// - `encrypted_bytes`     : concatenation of the encrypted header and the DEM
///   ciphertext
/// - `authentication_data` : optional data used for authentication
///
/// Return the decrypted data (additional data in header and cleartext) as a
/// binary format: 1. LEB128 length of the additional data bytes
/// 2. additional data bytes
/// 3. cleartext bytes
#[wasm_bindgen]
pub fn webassembly_hybrid_decrypt(
    usk_bytes: Uint8Array,
    encrypted_bytes: Uint8Array,
    authentication_data: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    // read encrypted bytes as the concatenation of an encrypted header
    // and a DEM ciphertext
    let encrypted_bytes = encrypted_bytes.to_vec();
    let mut de = Deserializer::new(&encrypted_bytes);
    // this will read the exact header size
    let header = de
        .read::<EncryptedHeader>()
        .map_err(|e| JsValue::from_str(&format!("Error parsing encrypted header: {e}")))?;
    // the rest is the symmetric ciphertext
    let ciphertext = de.finalize();

    // deserialize user secret key
    let usk = UserSecretKey::try_from_bytes(usk_bytes.to_vec().as_slice())
        .map_err(|e| JsValue::from_str(&format!("Error parsing user secret key: {e}")))?;

    let authentication_data = if authentication_data.is_null() {
        None
    } else {
        Some(authentication_data.to_vec())
    };

    // Instantiate CoverCrypt
    let cover_crypt = CoverCryptX25519Aes256::default();

    // Decrypt header
    let cleartext_header = header
        .decrypt(&cover_crypt, &usk, authentication_data.as_deref())
        .map_err(|e| JsValue::from_str(&format!("Error decrypting header: {e}")))?;

    let cleartext = cover_crypt
        .decrypt(
            &cleartext_header.symmetric_key,
            ciphertext.as_slice(),
            authentication_data.as_deref(),
        )
        .map_err(|e| JsValue::from_str(&format!("Error decrypting ciphertext: {e}")))?;

    let mut ser = Serializer::new();
    ser.write_vec(cleartext_header.metadata.as_slice())
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Cannot serialize the decrypted header metadata into response : {e}"
            ))
        })?;
    ser.write_array(cleartext.as_slice()).map_err(|e| {
        JsValue::from_str(&format!(
            "Cannot serialize the decrypted plaintext into response : {e}"
        ))
    })?;
    Ok(Uint8Array::from(ser.finalize().as_slice()))
}
