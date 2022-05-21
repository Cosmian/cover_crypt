// needed to remove wasm_bindgen warnings
#![allow(non_upper_case_globals)]
#![allow(clippy::unused_unit)]
// Wait for `wasm-bindgen` issue 2774: https://github.com/rustwasm/wasm-bindgen/issues/2774

use crate::{
    interfaces::statics::{
        decrypt_hybrid_block, decrypt_hybrid_header, encrypt_hybrid_header, ClearTextHeader,
    },
    policies::Attribute,
};
use cosmian_crypto_base::{
    asymmetric::ristretto::X25519Crypto,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, SymmetricCrypto},
    KeyTrait,
};
use wasm_bindgen::prelude::*;

pub const MAX_CLEAR_TEXT_SIZE: usize = 1_usize << 30;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    fn alert(s: &str);
}

/// Extract header from encrypted bytes
#[wasm_bindgen]
pub fn webassembly_get_encrypted_header_size(
    encrypted_bytes: js_sys::Uint8Array,
) -> Result<u32, JsValue> {
    //
    // Check `encrypted_bytes` input param and store it locally
    if encrypted_bytes.length() < 4 {
        return Err(JsValue::from_str(
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

#[wasm_bindgen]
pub fn webassembly_encrypt_hybrid_header(
    metadata_bytes: js_sys::Uint8Array,
    policy_bytes: js_sys::Uint8Array,
    attributes_bytes: js_sys::Uint8Array,
    public_key_bytes: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let metadata = serde_json::from_slice(metadata_bytes.to_vec().as_slice())
        .map_err(|e| JsValue::from_str(&format!("Error deserializing metadata: {e}")))?;
    let policy = serde_json::from_slice(policy_bytes.to_vec().as_slice())
        .map_err(|e| JsValue::from_str(&format!("Error deserializing policy: {e}")))?;
    let attributes: Vec<Attribute> =
        serde_json::from_slice(attributes_bytes.to_vec().as_slice())
            .map_err(|e| JsValue::from_str(&format!("Error deserializing attributes: {e}")))?;
    let public_key = serde_json::from_slice(public_key_bytes.to_vec().as_slice())
        .map_err(|e| JsValue::from_str(&format!("Error deserializing public key: {e}")))?;
    let encrypted_header = encrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
        &policy,
        &public_key,
        &attributes,
        Some(&metadata),
    )
    .map_err(|e| JsValue::from_str(&format!("Error encrypting header: {e}")))?;
    Ok(js_sys::Uint8Array::from(
        serde_json::to_vec(&encrypted_header)
            .map_err(|e| JsValue::from_str(&format!("Error serializing encrypted header: {e}")))?
            .as_slice(),
    ))
}

// -------------------------------
//         Decryption
// -------------------------------

/// Decrypt with a user decryption key an encrypted header
/// of a resource encrypted using an hybrid crypto scheme.
#[wasm_bindgen]
pub fn webassembly_decrypt_hybrid_header(
    user_decryption_key_bytes: js_sys::Uint8Array,
    encrypted_header_bytes: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    //
    // Check `user_decryption_key_bytes` input param and store it locally
    if user_decryption_key_bytes.length() == 0 {
        return Err(JsValue::from_str("User decryption key is empty"));
    }

    //
    // Check `encrypted_bytes` input param and store it locally
    if encrypted_header_bytes.length() < 4 {
        return Err(JsValue::from_str("Encrypted value is empty"));
    }

    //
    // Parse user decryption key
    let user_decryption_key = serde_json::from_slice(user_decryption_key_bytes.to_vec().as_slice())
        .map_err(|e| {
            return JsValue::from_str(&format!("Error deserializing user decryption key: {e}"));
        })?;

    //
    // Finally decrypt symmetric key using given user decryption key
    let cleartext_header: ClearTextHeader<Aes256GcmCrypto> =
        decrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
            &user_decryption_key,
            encrypted_header_bytes.to_vec().as_slice(),
        )
        .map_err(|e| return JsValue::from_str(&format!("Error decrypting hybrid header: {e}")))?;

    Ok(js_sys::Uint8Array::from(
        &cleartext_header.symmetric_key.to_bytes()[..],
    ))
}

/// Symmetrically Decrypt encrypted data in a block.
#[wasm_bindgen]
pub fn webassembly_decrypt_hybrid_block(
    symmetric_key_bytes: js_sys::Uint8Array,
    uid_bytes: Option<js_sys::Uint8Array>,
    block_number: Option<usize>,
    encrypted_bytes: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    //
    // Check `user_decryption_key_bytes` input param and store it locally
    if symmetric_key_bytes.length() != 32 {
        return Err(JsValue::from_str("Symmetric key must be 32-bytes long"));
    }

    //
    // Check `encrypted_bytes` input param and store it locally
    if encrypted_bytes.length() == 0 {
        return Err(JsValue::from_str("Encrypted value is empty"));
    }

    //
    // Parse symmetric key
    let symmetric_key = <Aes256GcmCrypto as SymmetricCrypto>::Key::parse(
        symmetric_key_bytes.to_vec(),
    )
    .map_err(|e| {
        return JsValue::from_str(&format!(
            "Error parsing
    symmetric key: {e}"
        ));
    })?;

    let uid = uid_bytes.map_or(vec![], |v| v.to_vec());
    let block_number_value = block_number.unwrap_or(0);
    //
    // Decrypt block
    let cleartext = decrypt_hybrid_block::<X25519Crypto, Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(
        &symmetric_key,
        &uid,
        block_number_value as usize,
        &encrypted_bytes.to_vec(),
    )
    .map_err(|e| {
        return JsValue::from_str(&format!(
            "Error decrypting block:
    {e}"
        ));
    })?;

    Ok(js_sys::Uint8Array::from(&cleartext[..]))
}
