use crate::{
    api::CoverCrypt,
    ffi_bail, ffi_not_null, ffi_unwrap,
    interfaces::{
        ffi::error::{set_last_error, FfiError},
        statics::{CoverCryptX25519Aes256, MasterSecretKey, PublicKey, UserSecretKey},
    },
    Serializable,
};
use abe_policy::{AccessPolicy, Attribute, Policy};
use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
};

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
    let (msk, mpk) = ffi_unwrap!(CoverCryptX25519Aes256::default().generate_master_keys(&policy));

    //
    // Serialize master keys
    let msk_bytes = ffi_unwrap!(msk.try_to_bytes());
    let mpk_bytes = ffi_unwrap!(mpk.try_to_bytes());

    let mut master_keys_bytes = Vec::<u8>::with_capacity(4 + msk_bytes.len() + mpk_bytes.len());
    master_keys_bytes.extend_from_slice(&u32::to_be_bytes(ffi_unwrap!(msk_bytes.len().try_into())));
    master_keys_bytes.extend_from_slice(&msk_bytes);
    master_keys_bytes.extend_from_slice(&mpk_bytes);

    //
    // Write output
    let allocated = *master_keys_len;
    *master_keys_len = master_keys_bytes.len() as c_int;
    if allocated < *master_keys_len {
        ffi_bail!(
            "The pre-allocated master keys buffer is too small; need {} bytes, allocated {}",
            *master_keys_len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(master_keys_ptr as *mut u8, master_keys_bytes.len())
        .copy_from_slice(&master_keys_bytes);

    0
}

#[no_mangle]
/// Generate the user secret key matching the given access policy
///
/// - `usk_ptr`             : Output buffer containing user secret key
/// - `usk_len`             : Size of the output buffer
/// - `msk_ptr`             : Master secret key (required for this generation)
/// - `msk_len`             : Master secret key length
/// - `access_policy_ptr`   : Access policy of the user secret key (JSON)
/// - `policy_ptr`          : Policy to use to generate the keys (JSON)
/// # Safety
pub unsafe extern "C" fn h_generate_user_secret_key(
    usk_ptr: *mut c_char,
    usk_len: *mut c_int,
    msk_ptr: *const c_char,
    msk_len: c_int,
    access_policy_ptr: *const c_char,
    policy_ptr: *const c_char,
) -> c_int {
    //
    // Checks inputs
    ffi_not_null!(
        usk_ptr,
        "User secret key pointer should point to pre-allocated memory"
    );
    if *usk_len == 0 {
        ffi_bail!("The user secret key buffer should not be empty");
    }
    ffi_not_null!(msk_ptr, "Master secret key pointer should not be null");
    if msk_len == 0 {
        ffi_bail!("The master secret key should not be empty");
    }
    ffi_not_null!(
        access_policy_ptr,
        "Access Policy pointer should not be null"
    );
    ffi_not_null!(policy_ptr, "Policy pointer should not be null");

    //
    // Master secret key deserialization
    let msk_bytes = std::slice::from_raw_parts(msk_ptr as *const u8, msk_len as usize);
    let msk = ffi_unwrap!(MasterSecretKey::try_from_bytes(msk_bytes));

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
    // Generate user secret key
    let usk = ffi_unwrap!(CoverCryptX25519Aes256::default().generate_user_secret_key(
        &msk,
        &access_policy,
        &policy
    ));

    //
    // Serialize user secret key
    let usk_bytes = ffi_unwrap!(usk.try_to_bytes());

    //
    // Write output
    let allocated = *usk_len;
    *usk_len = usk_bytes.len() as c_int;
    if allocated < *usk_len {
        ffi_bail!(
            "The pre-allocated user secret key buffer is too small; need {} bytes, allocated {}",
            *usk_len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(usk_ptr as *mut u8, usk_bytes.len()).copy_from_slice(&usk_bytes);

    0
}

#[no_mangle]
/// Rotate the attributes of the given policy
///
/// - `updated_policy_ptr`  : Output buffer containing new policy
/// - `updated_policy_len`  : Size of the output buffer
/// - `attributes_ptr`      : Attributes to rotate (JSON)
/// - `policy_ptr`          : Policy to use to generate the keys (JSON)
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
    // Write output
    let allocated = *updated_policy_len;
    *updated_policy_len = updated_policy_string.len() as c_int;
    if allocated < *updated_policy_len {
        ffi_bail!(
            "The pre-allocated output policy buffer is too small; need {} bytes, allocated {allocated}"
            ,*updated_policy_len
        );
    }
    std::slice::from_raw_parts_mut(updated_policy_ptr as *mut u8, updated_policy_string.len())
        .copy_from_slice(updated_policy_string.as_bytes());

    0
}

#[no_mangle]
/// Update the master keys according to this new policy.
///
/// When a partition exists in the new policy but not in the master keys,
/// a new key pair is added to the master keys for that partition.
/// When a partition exists on the master keys, but not in the new policy,
/// it is removed from the master keys.
///
/// - `updated_msk_ptr` : Output buffer containing the updated master secret key
/// - `updated_msk_len` : Size of the updated master secret key output buffer
/// - `updated_mpk_ptr` : Output buffer containing the updated master public key
/// - `updated_mpk_len` : Size of the updated master public key output buffer
/// - `current_msk_ptr` : current master secret key
/// - `current_msk_len` : current master secret key length
/// - `current_mpk_ptr` : current master public key
/// - `current_mpk_len` : current master public key length
/// - `policy_ptr`      : Policy to use to update the master keys (JSON)
/// # Safety
pub unsafe extern "C" fn h_update_master_keys(
    updated_msk_ptr: *mut c_char,
    updated_msk_len: *mut c_int,
    updated_mpk_ptr: *mut c_char,
    updated_mpk_len: *mut c_int,
    current_msk_ptr: *const c_char,
    current_msk_len: c_int,
    current_mpk_ptr: *const c_char,
    current_mpk_len: c_int,
    policy_ptr: *const c_char,
) -> c_int {
    //
    // Checks inputs
    ffi_not_null!(
        updated_msk_ptr,
        "User secret key pointer should point to pre-allocated memory"
    );
    if *updated_msk_len == 0 {
        ffi_bail!("The user secret key buffer should not be empty");
    }
    ffi_not_null!(
        updated_mpk_ptr,
        "User public key pointer should point to pre-allocated memory"
    );
    if *updated_mpk_len == 0 {
        ffi_bail!("The user public key buffer should not be empty");
    }
    ffi_not_null!(
        current_msk_ptr,
        "Master secret key pointer should not be null"
    );
    if current_msk_len == 0 {
        ffi_bail!("The master secret key should not be empty");
    }
    ffi_not_null!(
        current_mpk_ptr,
        "Master public key pointer should not be null"
    );
    if current_mpk_len == 0 {
        ffi_bail!("The master public key should not be empty");
    }
    ffi_not_null!(policy_ptr, "Policy pointer should not be null");

    //
    // Master secret key deserialization
    let msk_bytes =
        std::slice::from_raw_parts(current_msk_ptr as *const u8, current_msk_len as usize);
    let mut msk = ffi_unwrap!(MasterSecretKey::try_from_bytes(msk_bytes));
    // Master public key deserialization
    let mpk_bytes =
        std::slice::from_raw_parts(current_mpk_ptr as *const u8, current_mpk_len as usize);
    let mut mpk = ffi_unwrap!(PublicKey::try_from_bytes(mpk_bytes));

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
    ffi_unwrap!(CoverCryptX25519Aes256::default().update_master_keys(&policy, &mut msk, &mut mpk));

    //
    // Serialize the master secret key
    let msk_bytes = ffi_unwrap!(msk.try_to_bytes());

    // Write msk
    let allocated = *updated_msk_len;
    *updated_msk_len = msk_bytes.len() as c_int;
    if allocated < *updated_msk_len {
        ffi_bail!(
            "The pre-allocated user secret key buffer is too small; need {} bytes, allocated {}",
            *updated_msk_len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(updated_msk_ptr as *mut u8, msk_bytes.len())
        .copy_from_slice(&msk_bytes);

    //
    // Serialize the master public key
    let mpk_bytes = ffi_unwrap!(mpk.try_to_bytes());

    // Write mpk
    let allocated = *updated_mpk_len;
    *updated_mpk_len = mpk_bytes.len() as c_int;
    if allocated < *updated_mpk_len {
        ffi_bail!(
            "The pre-allocated user public key buffer is too small; need {} bytes, allocated {}",
            *updated_mpk_len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(updated_mpk_ptr as *mut u8, mpk_bytes.len())
        .copy_from_slice(&mpk_bytes);

    0
}

#[no_mangle]
/// Refresh the user key according to the given master key and access policy.
///
/// The user key will be granted access to the current partitions, as determined by its access policy.
/// If preserve_old_partitions is set, the user access to rotated partitions will be preserved
///
/// - `updated_usk_ptr`                 : Output buffer containing the updated user secret key
/// - `updated_usk_len`                 : Size of the updated user secret key output buffer
/// - `msk_ptr`                         : master secret key
/// - `msk_len`                         : master secret key length
/// - `current_usk_ptr`                 : current user secret key
/// - `current_usk_len`                 : current user secret key length
/// - `access_policy_ptr`               : Access policy of the user secret key (JSON)
/// - `policy_ptr`                      : Policy to use to update the master keys (JSON)
/// - `preserve_old_partitions_access`  : set to 1 to preserve the user access to the rotated partitions
/// # Safety
pub unsafe extern "C" fn h_refresh_user_secret_key(
    updated_usk_ptr: *mut c_char,
    updated_usk_len: *mut c_int,
    msk_ptr: *const c_char,
    msk_len: c_int,
    current_usk_ptr: *const c_char,
    current_usk_len: c_int,
    access_policy_ptr: *const c_char,
    policy_ptr: *const c_char,
    preserve_old_partitions_access: c_int,
) -> c_int {
    //
    // Checks inputs
    ffi_not_null!(
        updated_usk_ptr,
        "User secret key pointer should point to pre-allocated memory"
    );
    if *updated_usk_len == 0 {
        ffi_bail!("The user secret key buffer should not be empty");
    }
    ffi_not_null!(msk_ptr, "Master secret key pointer should not be null");
    if msk_len == 0 {
        ffi_bail!("The master secret key should not be empty");
    }
    ffi_not_null!(
        current_usk_ptr,
        "User secret key pointer should not be null"
    );
    if current_usk_len == 0 {
        ffi_bail!("The user secret key should not be empty");
    }
    ffi_not_null!(
        access_policy_ptr,
        "The access policy pointer should not be null"
    );
    ffi_not_null!(policy_ptr, "The policy pointer should not be null");

    //
    // Master secret key deserialization
    let msk_bytes = std::slice::from_raw_parts(msk_ptr as *const u8, msk_len as usize);
    let msk = ffi_unwrap!(MasterSecretKey::try_from_bytes(msk_bytes));
    // Master public key deserialization
    let usk_bytes =
        std::slice::from_raw_parts(current_usk_ptr as *const u8, current_usk_len as usize);
    let mut usk = ffi_unwrap!(UserSecretKey::try_from_bytes(usk_bytes));

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
    // update the user secret key
    ffi_unwrap!(CoverCryptX25519Aes256::default().refresh_user_secret_key(
        &mut usk,
        &access_policy,
        &msk,
        &policy,
        preserve_old_partitions_access != 0
    ));

    //
    // Serialize the user secret key
    let usk_bytes = ffi_unwrap!(usk.try_to_bytes());

    // Write output
    let allocated = *updated_usk_len;

    *updated_usk_len = usk_bytes.len() as c_int;
    if allocated < *updated_usk_len {
        ffi_bail!(
            "The pre-allocated user public key buffer is too small; need {} bytes, allocated {}",
            *updated_usk_len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(updated_usk_ptr as *mut u8, usk_bytes.len())
        .copy_from_slice(&usk_bytes);

    0
}

#[no_mangle]
/// Converts a boolean expression containing an access policy
/// into a JSON access policy which can be used in Vendor Attributes
///
/// Note: the return string is NULL terminated
///
/// - `json_access_policy_ptr`: Output buffer containing a null terminated string with the JSON access policy
/// - `json_access_policy_len`: Size of the output buffer
/// - `boolean_access_policy_ptr`: boolean access policy string
/// # Safety
pub unsafe extern "C" fn h_parse_boolean_access_policy(
    json_access_policy_ptr: *mut c_char,
    json_access_policy_len: *mut c_int,
    boolean_access_policy_ptr: *const c_char,
) -> c_int {
    //
    // Checks inputs
    ffi_not_null!(
        json_access_policy_ptr,
        "The JSON access policy pointer should point to pre-allocated memory"
    );
    if *json_access_policy_len == 0 {
        ffi_bail!("The JSON access policy buffer should not be empty");
    }
    ffi_not_null!(
        boolean_access_policy_ptr,
        "Policy pointer should not be null"
    );

    //
    // Policy
    let boolean_access_policy = match CStr::from_ptr(boolean_access_policy_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(e) => {
            set_last_error(FfiError::Generic(format!(
                "CoverCrypt keys generation: invalid Policy: {e}"
            )));
            return 1;
        }
    };

    let access_policy = ffi_unwrap!(AccessPolicy::from_boolean_expression(
        &boolean_access_policy
    ));
    let json_access_policy = ffi_unwrap!(serde_json::to_string(&access_policy));
    let json_access_policy_cstr = ffi_unwrap!(CString::new(json_access_policy));
    let json_access_policy_bytes = json_access_policy_cstr.as_bytes_with_nul();

    //
    // Prepare output
    let allocated = *json_access_policy_len;
    let len = json_access_policy_bytes.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated output JSON access policy buffer is too small; need {len} bytes, allocated {allocated}"
        );
    }
    std::slice::from_raw_parts_mut(json_access_policy_ptr as *mut u8, len)
        .copy_from_slice(json_access_policy_bytes);
    *json_access_policy_len = len as c_int;

    0
}
