use std::{
    ffi::CStr,
    os::raw::{c_char, c_int},
};

use cosmian_crypto_base::asymmetric::ristretto::X25519Crypto;

use crate::{
    api::{CoverCrypt, PrivateKey},
    ffi_bail, ffi_not_null, ffi_unwrap,
    interfaces::ffi::error::{set_last_error, FfiError},
};

use abe_policy::{AccessPolicy, Attribute, Policy};

#[no_mangle]
/// Generate the master authority keys for supplied Policy
///
///  - `master_keys_ptr`    : Output buffer containing both master keys
///  - `master_keys_len`    : Size of the output buffer
///  - `policy_ptr`         : Policy to use to generate the keys
/// # Safety
pub unsafe extern "C" fn h_generate_master_keys(
    master_keys_ptr: *mut c_char,
    master_keys_len: *mut c_int,
    policy_ptr: *const c_char,
) -> c_int {
    //
    // Checks inputs
    ffi_not_null!(
        master_keys_ptr,
        "Master keys pointer should point to pre-allocated memory"
    );
    if *master_keys_len == 0 {
        ffi_bail!("The master keys buffer should have a size greater than zero");
    }

    ffi_not_null!(policy_ptr, "Policy pointer should not be null");

    //
    // Policy
    let policy = match CStr::from_ptr(policy_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(e) => {
            set_last_error(FfiError::Generic(format!(
                "CoverCrypt keys generation: invalid Policy: {e}",
            )));
            return 1;
        }
    };
    let policy: Policy = ffi_unwrap!(serde_json::from_str(&policy));

    //
    // Generate master keys
    let (master_private_key, master_public_key) =
        ffi_unwrap!(CoverCrypt::<X25519Crypto>::default().generate_master_keys(&policy));

    //
    // Serialize master keys
    let master_private_key_bytes = ffi_unwrap!(master_private_key.try_to_bytes());
    let master_public_key_bytes = ffi_unwrap!(master_public_key.try_to_bytes());

    let mut master_keys_bytes = Vec::<u8>::with_capacity(
        4 + master_private_key_bytes.len() + master_public_key_bytes.len(),
    );
    master_keys_bytes.extend_from_slice(&u32::to_be_bytes(master_private_key_bytes.len() as u32));
    master_keys_bytes.extend_from_slice(&master_private_key_bytes);
    master_keys_bytes.extend_from_slice(&master_public_key_bytes);

    //
    // Prepare output
    let allocated = *master_keys_len;
    let len = master_keys_bytes.len();
    *master_keys_len = len as c_int;
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated master keys buffer is too small; need {} bytes, allocated {}",
            len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(master_keys_ptr as *mut u8, len)
        .copy_from_slice(&master_keys_bytes);

    0
}

#[no_mangle]
/// Generate the user private key matching the given access policy
///
/// - `user_private_key_ptr`: Output buffer containing user private key
/// - `user_private_key_len`: Size of the output buffer
/// - `master_private_key_ptr`: Master private key (required for this
///   generation)
/// - `master_private_key_len`: Master private key length
/// - `access_policy_ptr`: Access policy of the user private key (JSON)
/// - `policy_ptr`: Policy to use to generate the keys (JSON)
/// # Safety
pub unsafe extern "C" fn h_generate_user_private_key(
    user_private_key_ptr: *mut c_char,
    user_private_key_len: *mut c_int,
    master_private_key_ptr: *const c_char,
    master_private_key_len: c_int,
    access_policy_ptr: *const c_char,
    policy_ptr: *const c_char,
) -> c_int {
    //
    // Checks inputs
    ffi_not_null!(
        user_private_key_ptr,
        "User private key pointer should point to pre-allocated memory"
    );
    if *user_private_key_len == 0 {
        ffi_bail!("The user private key buffer should not be empty");
    }
    ffi_not_null!(
        master_private_key_ptr,
        "Master private key pointer should not be null"
    );
    if master_private_key_len == 0 {
        ffi_bail!("The master private key should not be empty");
    }
    ffi_not_null!(
        access_policy_ptr,
        "Access Policy pointer should not be null"
    );
    ffi_not_null!(policy_ptr, "Policy pointer should not be null");

    //
    // Master private key deserialization
    let master_private_key_bytes = std::slice::from_raw_parts(
        master_private_key_ptr as *const u8,
        master_private_key_len as usize,
    );
    let master_private_key: PrivateKey<X25519Crypto> =
        ffi_unwrap!(PrivateKey::try_from_bytes(master_private_key_bytes));

    //
    // Access Policy
    let access_policy = match CStr::from_ptr(access_policy_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(e) => {
            set_last_error(FfiError::Generic(format!(
                "CoverCrypt keys generation: invalid Access Policy: {e}"
            )));
            return 1;
        }
    };
    let access_policy: AccessPolicy = ffi_unwrap!(serde_json::from_str(&access_policy));

    //
    // Policy
    let policy = match CStr::from_ptr(policy_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(e) => {
            set_last_error(FfiError::Generic(format!(
                "CoverCrypt keys generation: invalid Policy: {e}"
            )));
            return 1;
        }
    };
    let policy: Policy = ffi_unwrap!(serde_json::from_str(&policy));

    //
    // Generate user private key
    let user_key = ffi_unwrap!(
        CoverCrypt::<X25519Crypto>::default().generate_user_private_key(
            &master_private_key,
            &access_policy,
            &policy
        )
    );

    //
    // Serialize user private key
    let user_key_bytes = ffi_unwrap!(user_key.try_to_bytes());

    //
    // Prepare output
    let allocated = *user_private_key_len;
    let len = user_key_bytes.len();
    *user_private_key_len = len as c_int;
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated user private key buffer is too small; need {} bytes, allocated {}",
            len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(user_private_key_ptr as *mut u8, len)
        .copy_from_slice(&user_key_bytes);

    0
}

#[no_mangle]
/// Generate the user private key matching the given access policy
///
/// - `new_policy_ptr`: Output buffer containing new policy
/// - `new_policy_len`: Size of the output buffer
/// - `attributes_ptr`: Attributes to rotate (JSON)
/// - `policy_ptr`: Policy to use to generate the keys (JSON)
/// # Safety
pub unsafe extern "C" fn h_rotate_attributes(
    new_policy_ptr: *mut c_char,
    new_policy_len: *mut c_int,
    attributes_ptr: *const c_char,
    policy_ptr: *const c_char,
) -> c_int {
    //
    // Checks inputs
    ffi_not_null!(
        new_policy_ptr,
        "New policy pointer should point to pre-allocated memory"
    );
    if *new_policy_len == 0 {
        ffi_bail!("The new policy buffer should not be empty");
    }
    ffi_not_null!(attributes_ptr, "Attributes pointer should not be null");
    ffi_not_null!(policy_ptr, "Policy pointer should not be null");

    //
    // Attributes
    let attributes = match CStr::from_ptr(attributes_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(e) => {
            set_last_error(FfiError::Generic(format!(
                "CoverCrypt attributes rotation: invalid Attributes: {e}"
            )));
            return 1;
        }
    };
    let attributes: Vec<Attribute> = ffi_unwrap!(serde_json::from_str(&attributes));

    //
    // Policy
    let policy = match CStr::from_ptr(policy_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(e) => {
            set_last_error(FfiError::Generic(format!(
                "CoverCrypt keys generation: invalid Policy: {e}"
            )));
            return 1;
        }
    };
    let mut policy: Policy = ffi_unwrap!(serde_json::from_str(&policy));

    //
    // Rotate attributes of the current policy
    for attr in &attributes {
        ffi_unwrap!(policy.rotate(attr));
    }

    //
    // Serialize new policy
    let new_policy_string = policy.to_string();

    //
    // Prepare output
    let allocated = *new_policy_len;
    let len = new_policy_string.len();
    *new_policy_len = len as c_int;
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated output policy buffer is too small; need {len} bytes, allocated {allocated}"
        );
    }
    std::slice::from_raw_parts_mut(new_policy_ptr as *mut u8, len)
        .copy_from_slice(new_policy_string.as_bytes());

    0
}
