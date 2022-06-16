// needed to remove wasm_bindgen warnings
#![allow(non_upper_case_globals)]
#![allow(clippy::unused_unit)]
// Wait for `wasm-bindgen` issue 2774: https://github.com/rustwasm/wasm-bindgen/issues/2774

use cosmian_crypto_base::asymmetric::ristretto::X25519Crypto;
use wasm_bindgen::prelude::*;

use crate::{
    api::{CoverCrypt, PrivateKey},
    policies::{AccessPolicy, Policy},
};

/// Generate the master authority keys for supplied Policy
///
///  - `policy_bytes` : Policy to use to generate the keys (serialized from
///    JSON)
#[wasm_bindgen]
pub fn webassembly_generate_master_keys(
    policy_bytes: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let policy: Policy = serde_json::from_slice(policy_bytes.to_vec().as_slice())
        .map_err(|e| JsValue::from_str(&format!("Error deserializing policy:{e}")))?;

    //
    // Setup CoverCrypt
    let (master_private_key, master_public_key) = CoverCrypt::<X25519Crypto>::default()
        .generate_master_keys(&policy)
        .map_err(|e| JsValue::from_str(&format!("Error generating master keys: {e}")))?;

    // Serialize master keys
    let master_private_key_bytes = master_private_key
        .try_to_bytes()
        .map_err(|e| JsValue::from_str(&format!("Error serializing master private key: {e}")))?;
    let master_public_key_bytes = master_public_key
        .try_to_bytes()
        .map_err(|e| JsValue::from_str(&format!("Error serializing master public key: {e}")))?;

    let mut master_keys_bytes = Vec::<u8>::with_capacity(
        4 + master_private_key_bytes.len() + master_public_key_bytes.len(),
    );
    master_keys_bytes.extend_from_slice(&u32::to_be_bytes(master_private_key_bytes.len() as u32));
    master_keys_bytes.extend_from_slice(&master_private_key_bytes);
    master_keys_bytes.extend_from_slice(&master_public_key_bytes);
    Ok(js_sys::Uint8Array::from(&master_keys_bytes[..]))
}

/// Generate a user private key.
///
/// - `master_private_key_bytes`    : master private key in bytes
/// - `access_policy_str`           : user access policy (boolean expression as
///   string)
/// - `policy_bytes`                : global policy (serialized from JSON)
#[wasm_bindgen]
pub fn webassembly_generate_user_private_key(
    master_private_key_bytes: js_sys::Uint8Array,
    access_policy_str: &str,
    policy_bytes: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let master_private_key: PrivateKey<X25519Crypto> =
        PrivateKey::try_from_bytes(master_private_key_bytes.to_vec().as_slice())
            .map_err(|e| JsValue::from_str(&format!("Error deserializing private key: {e}")))?;
    let policy = serde_json::from_slice(policy_bytes.to_vec().as_slice())
        .map_err(|e| JsValue::from_str(&format!("Error deserializing policy: {e}")))?;
    let access_policy = AccessPolicy::from_boolean_expression(access_policy_str)
        .map_err(|e| JsValue::from_str(&format!("Error deserializing access policy: {e}")))?;

    let user_key = CoverCrypt::<X25519Crypto>::default()
        .generate_user_private_key(&master_private_key, &access_policy, &policy)
        .map_err(|e| JsValue::from_str(&format!("Error generating user private key: {e}")))?;

    let user_key_bytes = user_key
        .try_to_bytes()
        .map_err(|e| JsValue::from_str(&format!("Error serializing user key: {e}")))?;
    Ok(js_sys::Uint8Array::from(user_key_bytes.as_slice()))
}
