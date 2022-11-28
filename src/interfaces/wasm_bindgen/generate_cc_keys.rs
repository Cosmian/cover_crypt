// needed to remove wasm_bindgen warnings
#![allow(non_upper_case_globals)]
#![allow(clippy::unused_unit)]
// Wait for `wasm-bindgen` issue 2774: https://github.com/rustwasm/wasm-bindgen/issues/2774

use crate::{
    api::CoverCrypt,
    interfaces::statics::{CoverCryptX25519Aes256, MasterSecretKey},
};
use abe_policy::{AccessPolicy, Attribute, Policy};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

/// Generate the master authority keys for supplied Policy
///
///  - `policy_bytes` : Policy to use to generate the keys (serialized from
///    JSON)
#[wasm_bindgen]
pub fn webassembly_generate_master_keys(policy_bytes: Uint8Array) -> Result<Uint8Array, JsValue> {
    let policy: Policy = serde_json::from_slice(policy_bytes.to_vec().as_slice())
        .map_err(|e| JsValue::from_str(&format!("Error deserializing policy:{e}")))?;

    //
    // Setup CoverCrypt
    let (msk, mpk) = CoverCryptX25519Aes256::default()
        .generate_master_keys(&policy)
        .map_err(|e| JsValue::from_str(&format!("Error generating master keys: {e}")))?;

    // Serialize master keys
    let msk_bytes = msk
        .try_to_bytes()
        .map_err(|e| JsValue::from_str(&format!("Error serializing master secret key: {e}")))?;
    let mpk_bytes = mpk
        .try_to_bytes()
        .map_err(|e| JsValue::from_str(&format!("Error serializing master public key: {e}")))?;

    let mut master_keys_bytes = Vec::with_capacity(4 + msk_bytes.len() + msk_bytes.len());
    master_keys_bytes.extend_from_slice(&u32::to_be_bytes(
        msk_bytes
            .len()
            .try_into()
            .map_err(|e| JsValue::from_str(&format!("Error while converting usize to u32: {e}")))?,
    ));
    master_keys_bytes.extend_from_slice(&msk_bytes);
    master_keys_bytes.extend_from_slice(&mpk_bytes);
    Ok(Uint8Array::from(&master_keys_bytes[..]))
}

/// Generate a user secret key.
///
/// - `msk_bytes`           : master secret key in bytes
/// - `access_policy_str`   : user access policy (boolean expression as string)
/// - `policy_bytes`        : global policy (serialized from JSON)
#[wasm_bindgen]
pub fn webassembly_generate_user_secret_key(
    msk_bytes: Uint8Array,
    access_policy_str: &str,
    policy_bytes: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let msk = MasterSecretKey::try_from_bytes(msk_bytes.to_vec().as_slice())
        .map_err(|e| JsValue::from_str(&format!("Error deserializing secret key: {e}")))?;
    let policy = serde_json::from_slice(policy_bytes.to_vec().as_slice())
        .map_err(|e| JsValue::from_str(&format!("Error deserializing policy: {e}")))?;
    let access_policy = AccessPolicy::from_boolean_expression(access_policy_str)
        .map_err(|e| JsValue::from_str(&format!("Error deserializing access policy: {e}")))?;

    let user_key = CoverCryptX25519Aes256::default()
        .generate_user_secret_key(&msk, &access_policy, &policy)
        .map_err(|e| JsValue::from_str(&format!("Error generating user secret key: {e}")))?;

    let user_key_bytes = user_key
        .try_to_bytes()
        .map_err(|e| JsValue::from_str(&format!("Error serializing user key: {e}")))?;
    Ok(Uint8Array::from(user_key_bytes.as_slice()))
}

/// Rotate attributes, changing their underlying values with that of an unused
/// slot
///
/// - `attributes_bytes`    : user access policy (boolean expression as string)
/// - `policy_bytes`        : global policy (serialized from JSON)
#[wasm_bindgen]
pub fn webassembly_rotate_attributes(
    attributes_bytes: Uint8Array,
    policy_bytes: Uint8Array,
) -> Result<String, JsValue> {
    let attributes: Vec<Attribute> =
        serde_json::from_slice(attributes_bytes.to_vec().as_slice())
            .map_err(|e| JsValue::from_str(&format!("Error deserializing attributes: {e}")))?;
    let mut policy: Policy = serde_json::from_slice(policy_bytes.to_vec().as_slice())
        .map_err(|e| JsValue::from_str(&format!("Error deserializing policy: {e}")))?;

    //
    // Rotate attributes of the current policy
    for attr in &attributes {
        policy
            .rotate(attr)
            .map_err(|e| JsValue::from_str(&format!("Error rotating attribute: {e}")))?;
    }

    Ok(policy.to_string())
}

/// Converts a boolean expression containing an access policy
/// into a JSON access policy which can be used in Vendor Attributes
#[wasm_bindgen]
pub fn webassembly_parse_boolean_access_policy(
    boolean_expression: &str,
) -> Result<String, JsValue> {
    let access_policy = AccessPolicy::from_boolean_expression(boolean_expression)
        .map_err(|e| JsValue::from_str(&format!("Error parsing the access policy: {e}")))?;
    serde_json::to_string(&access_policy)
        .map_err(|e| JsValue::from_str(&format!("Error serializing the access policy: {e}")))
}
