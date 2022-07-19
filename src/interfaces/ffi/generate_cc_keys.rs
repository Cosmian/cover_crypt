use std::{
    ffi::CStr,
    os::raw::{c_char, c_int},
};

use cosmian_crypto_base::asymmetric::ristretto::X25519Crypto;

use crate::{
    api::{CoverCrypt, PrivateKey, PublicKey},
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
/// Rotate the attributes of the given policy
///
/// - `updated_policy_ptr`: Output buffer containing new policy
/// - `updated_policy_len`: Size of the output buffer
/// - `attributes_ptr`: Attributes to rotate (JSON)
/// - `policy_ptr`: Policy to use to generate the keys (JSON)
/// # Safety
pub unsafe extern "C" fn h_rotate_attributes(
    updated_policy_ptr: *mut c_char,
    updated_policy_len: *mut c_int,
    attributes_ptr: *const c_char,
    policy_ptr: *const c_char,
) -> c_int {
    //
    // Checks inputs
    ffi_not_null!(
        updated_policy_ptr,
        "New policy pointer should point to pre-allocated memory"
    );
    if *updated_policy_len == 0 {
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
    let updated_policy_string = policy.to_string();

    //
    // Prepare output
    let allocated = *updated_policy_len;
    let len = updated_policy_string.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated output policy buffer is too small; need {len} bytes, allocated {allocated}"
        );
    }
    std::slice::from_raw_parts_mut(updated_policy_ptr as *mut u8, len)
        .copy_from_slice(updated_policy_string.as_bytes());
    *updated_policy_len = len as c_int;

    0
}

#[no_mangle]
/// Update the master keys according to this new policy.
///
/// When a partition exists in the new policy but not in the master keys,
/// a new keypair is added to the master keys for that partition.
/// When a partition exists on the master keys, but not in the new policy,
/// it is removed from the master keys.
///
/// - `updated_master_private_key_ptr`: Output buffer containing the updated master private key
/// - `updated_master_private_key_len`: Size of the updated master private key output buffer
/// - `updated_master_public_key_ptr`: Output buffer containing the updated master public key
/// - `updated_master_public_key_len`: Size of the updated master public key output buffer
/// - `current_master_private_key_ptr`: current master private key
/// - `current_master_private_key_len`: current master private key length
/// - `current_master_public_key_ptr`: current master public key
/// - `current_master_public_key_len`: current master public key length
/// - `policy_ptr`: Policy to use to update the master keys (JSON)
/// # Safety
pub unsafe extern "C" fn h_update_master_keys(
    updated_master_private_key_ptr: *mut c_char,
    updated_master_private_key_len: *mut c_int,
    updated_master_public_key_ptr: *mut c_char,
    updated_master_public_key_len: *mut c_int,
    current_master_private_key_ptr: *const c_char,
    current_master_private_key_len: c_int,
    current_master_public_key_ptr: *const c_char,
    current_master_public_key_len: c_int,
    policy_ptr: *const c_char,
) -> c_int {
    //
    // Checks inputs
    ffi_not_null!(
        updated_master_private_key_ptr,
        "User private key pointer should point to pre-allocated memory"
    );
    if *updated_master_private_key_len == 0 {
        ffi_bail!("The user private key buffer should not be empty");
    }
    ffi_not_null!(
        updated_master_public_key_ptr,
        "User public key pointer should point to pre-allocated memory"
    );
    if *updated_master_public_key_len == 0 {
        ffi_bail!("The user public key buffer should not be empty");
    }
    ffi_not_null!(
        current_master_private_key_ptr,
        "Master private key pointer should not be null"
    );
    if current_master_private_key_len == 0 {
        ffi_bail!("The master private key should not be empty");
    }
    ffi_not_null!(
        current_master_public_key_ptr,
        "Master public key pointer should not be null"
    );
    if current_master_public_key_len == 0 {
        ffi_bail!("The master public key should not be empty");
    }
    ffi_not_null!(policy_ptr, "Policy pointer should not be null");

    //
    // Master private key deserialization
    let master_private_key_bytes = std::slice::from_raw_parts(
        current_master_private_key_ptr as *const u8,
        current_master_private_key_len as usize,
    );
    let mut master_private_key: PrivateKey<X25519Crypto> =
        ffi_unwrap!(PrivateKey::try_from_bytes(master_private_key_bytes));
    // Master public key deserialization
    let master_public_key_bytes = std::slice::from_raw_parts(
        current_master_public_key_ptr as *const u8,
        current_master_public_key_len as usize,
    );
    let mut master_public_key: PublicKey<X25519Crypto> =
        ffi_unwrap!(PublicKey::try_from_bytes(master_public_key_bytes));

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
    // update the master keys
    ffi_unwrap!(CoverCrypt::<X25519Crypto>::default().update_master_keys(
        &policy,
        &mut master_private_key,
        &mut master_public_key
    ));

    //
    // Serialize the master private key
    let master_private_key_bytes = ffi_unwrap!(master_private_key.try_to_bytes());
    // Prepare output
    let allocated = *updated_master_private_key_len;
    let len = master_private_key_bytes.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated user private key buffer is too small; need {} bytes, allocated {}",
            len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(updated_master_private_key_ptr as *mut u8, len)
        .copy_from_slice(&master_private_key_bytes);
    *updated_master_private_key_len = len as c_int;

    //
    // Serialize the master public key
    let master_public_key_bytes = ffi_unwrap!(master_public_key.try_to_bytes());
    // Prepare output
    let allocated = *updated_master_public_key_len;
    let len = master_public_key_bytes.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated user public key buffer is too small; need {} bytes, allocated {}",
            len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(updated_master_public_key_ptr as *mut u8, len)
        .copy_from_slice(&master_public_key_bytes);
    *updated_master_public_key_len = len as c_int;

    0
}

#[no_mangle]
/// Refresh the user key according to the given master key and access policy.
///
/// The user key will be granted access to the current partitions, as determined by its access policy.
/// If preserve_old_partitions is set, the user access to rotated partitions will be preserved
///
/// - `updated_user_private_key_ptr`: Output buffer containing the updated user private key
/// - `updated_user_private_key_len`: Size of the updated user private key output buffer
/// - `master_private_key_ptr`: master private key
/// - `master_private_key_len`: master private key length
/// - `current_user_private_key_ptr`: current user private key
/// - `current_user_private_key_len`: current user private key length
/// - `access_policy_ptr`: Access policy of the user private key (JSON)
/// - `policy_ptr`: Policy to use to update the master keys (JSON)
/// - `preserve_old_partitions_access`: set to 1 to preserve the user access to the rotated partitions
/// # Safety
pub unsafe extern "C" fn h_refresh_user_private_key(
    updated_user_private_key_ptr: *mut c_char,
    updated_user_private_key_len: *mut c_int,
    master_private_key_ptr: *const c_char,
    master_private_key_len: c_int,
    current_user_private_key_ptr: *const c_char,
    current_user_private_key_len: c_int,
    access_policy_ptr: *const c_char,
    policy_ptr: *const c_char,
    preserve_old_partitions_access: c_int,
) -> c_int {
    //
    // Checks inputs
    ffi_not_null!(
        updated_user_private_key_ptr,
        "User private key pointer should point to pre-allocated memory"
    );
    if *updated_user_private_key_len == 0 {
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
        current_user_private_key_ptr,
        "User private key pointer should not be null"
    );
    if current_user_private_key_len == 0 {
        ffi_bail!("The user private key should not be empty");
    }
    ffi_not_null!(
        access_policy_ptr,
        "The access policy pointer should not be null"
    );
    ffi_not_null!(policy_ptr, "The policy pointer should not be null");

    //
    // Master private key deserialization
    let master_private_key_bytes = std::slice::from_raw_parts(
        master_private_key_ptr as *const u8,
        master_private_key_len as usize,
    );
    let master_private_key: PrivateKey<X25519Crypto> =
        ffi_unwrap!(PrivateKey::try_from_bytes(master_private_key_bytes));
    // Master public key deserialization
    let user_private_key_bytes = std::slice::from_raw_parts(
        current_user_private_key_ptr as *const u8,
        current_user_private_key_len as usize,
    );
    let mut user_private_key: PrivateKey<X25519Crypto> =
        ffi_unwrap!(PrivateKey::try_from_bytes(user_private_key_bytes));

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
    // update the master keys
    ffi_unwrap!(
        CoverCrypt::<X25519Crypto>::default().refresh_user_private_key(
            &mut user_private_key,
            &access_policy,
            &master_private_key,
            &policy,
            preserve_old_partitions_access != 0
        )
    );

    //
    // Serialize the master public key
    let user_private_key_bytes = ffi_unwrap!(user_private_key.try_to_bytes());
    // Prepare output
    let allocated = *updated_user_private_key_len;
    let len = user_private_key_bytes.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated user public key buffer is too small; need {} bytes, allocated {}",
            len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(updated_user_private_key_ptr as *mut u8, len)
        .copy_from_slice(&user_private_key_bytes);
    *updated_user_private_key_len = len as c_int;

    0
}
