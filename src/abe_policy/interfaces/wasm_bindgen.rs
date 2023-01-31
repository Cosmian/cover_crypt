use crate::{
    abe_policy::{Attribute, EncryptionHint, Policy, PolicyAxis},
    Error,
};
use js_sys::{Array, Boolean, JsString, Reflect};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Array<string>")]
    pub type Attributes;
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "{name: string, isHybridized: boolean}")]
    pub type AttributeProperty;
}

#[wasm_bindgen]
pub fn webassembly_policy_axis(
    name: String,
    attribute_properties: Vec<AttributeProperty>,
    is_hierarchical: bool,
) -> Result<String, JsValue> {
    let attribute_properties = attribute_properties
        .into_iter()
        .map(|obj| -> Result<(String, EncryptionHint), JsValue> {
            let name = String::from(JsString::from(Reflect::get(
                &obj,
                &JsValue::from_str("name"),
            )?));
            let encryption_hint = bool::from(Boolean::from(Reflect::get(
                &obj,
                &JsValue::from_str("name"),
            )?));
            let encryption_hint = if encryption_hint {
                EncryptionHint::Hybridized
            } else {
                EncryptionHint::Classic
            };
            Ok((name, encryption_hint))
        })
        .collect::<Result<Vec<_>, _>>()?;

    serde_json::to_string(&PolicyAxis::new(
        &name,
        attribute_properties
            .iter()
            .map(|(name, encryption_hint)| (name.as_str(), *encryption_hint))
            .collect(),
        is_hierarchical,
    ))
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn webassembly_policy(nb_creations: u32) -> Result<Vec<u8>, JsValue> {
    serde_json::to_vec(&Policy::new(nb_creations)).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn webassembly_add_axis(policy: Vec<u8>, axis: String) -> Result<Vec<u8>, JsValue> {
    let mut policy = Policy::parse_and_convert(&policy)?;
    policy.add_axis(serde_json::from_str(&axis).map_err(Error::DeserializationError)?)?;
    serde_json::to_vec(&policy).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Rotates attributes, changing their underlying values with that of an unused
/// slot
///
/// - `attributes`  : user access policy (boolean expression as string)
/// - `policy`      : global policy data (JSON)
#[wasm_bindgen]
pub fn webassembly_rotate_attributes(
    attributes: Attributes,
    policy: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let attributes = Array::from(&JsValue::from(attributes));
    let mut policy = Policy::parse_and_convert(&policy)?;

    // Rotate attributes of the current policy
    for attr in attributes.values() {
        let attribute = Attribute::try_from(String::from(JsString::from(attr?)).as_str())?;
        policy.rotate(&attribute)?;
    }

    Ok(serde_json::to_vec(&policy).map_err(Error::DeserializationError)?)
}
