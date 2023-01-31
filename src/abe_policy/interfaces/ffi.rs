use crate::abe_policy::{AccessPolicy, Attribute, Policy};
use cosmian_ffi::{ffi_read_bytes, ffi_read_string, ffi_unwrap, ffi_write_bytes};
use std::ffi::{c_char, c_int};

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn h_policy(
    policy_ptr: *mut c_char,
    policy_len: *mut c_int,
    max_attribute_creations: c_int,
) -> c_int {
    let policy = Policy::new(max_attribute_creations as u32);
    let policy_bytes = ffi_unwrap!(serde_json::to_vec(&policy));
    ffi_write_bytes!("policy", &policy_bytes, policy_ptr, policy_len);
    0
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn h_add_policy_axis(
    updated_policy_ptr: *mut c_char,
    updated_policy_len: *mut c_int,
    current_policy_ptr: *const c_char,
    current_policy_len: c_int,
    axis_ptr: *const c_char,
) -> c_int {
    let policy_bytes = ffi_read_bytes!("current policy", current_policy_ptr, current_policy_len);
    let mut policy = ffi_unwrap!(Policy::parse_and_convert(policy_bytes));
    let axis_string = ffi_read_string!("axis", axis_ptr);
    let axis = ffi_unwrap!(serde_json::from_str(&axis_string));

    ffi_unwrap!(policy.add_axis(axis));

    ffi_write_bytes!(
        "updated policy",
        &ffi_unwrap!(serde_json::to_vec(&policy)),
        updated_policy_ptr,
        updated_policy_len
    );

    0
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn h_rotate_attribute(
    updated_policy_ptr: *mut c_char,
    updated_policy_len: *mut c_int,
    current_policy_ptr: *const c_char,
    current_policy_len: c_int,
    attribute: *const c_char,
) -> c_int {
    let policy_bytes = ffi_read_bytes!("current policy", current_policy_ptr, current_policy_len);
    let mut policy = ffi_unwrap!(Policy::parse_and_convert(policy_bytes));
    let attr_string = ffi_read_string!("attribute", attribute);
    let attr = ffi_unwrap!(Attribute::try_from(attr_string.as_str()));

    ffi_unwrap!(policy.rotate(&attr));

    ffi_write_bytes!(
        "updated policy",
        &ffi_unwrap!(serde_json::to_vec(&policy)),
        updated_policy_ptr,
        updated_policy_len
    );

    0
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn h_validate_boolean_expression(
    boolean_expression_ptr: *const c_char,
) -> c_int {
    let boolean_expression = ffi_read_string!("boolean expression", boolean_expression_ptr);
    ffi_unwrap!(AccessPolicy::from_boolean_expression(&boolean_expression));
    0
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn h_validate_attribute(attribute_ptr: *const c_char) -> c_int {
    let attribute_str = ffi_read_string!("attribute", attribute_ptr);
    ffi_unwrap!(AccessPolicy::from_boolean_expression(&attribute_str));
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abe_policy::tests::policy;
    use cosmian_ffi::error::h_get_error;
    use std::ffi::{CStr, CString};

    #[test]
    fn test_rotate() {
        let mut policy = policy().unwrap();
        let mut policy_bytes = serde_json::to_vec(&policy).unwrap();
        let attributes = policy.attributes();

        // Rotate attributes using the ffi method.
        let attribute = CString::new(attributes[0].to_string()).unwrap();

        policy_bytes = unsafe {
            let current_policy_ptr = policy_bytes.as_ptr().cast();
            let current_policy_len = policy_bytes.len() as c_int;
            let mut updated_policy_bytes = vec![0u8; 8192];
            let updated_policy_ptr = updated_policy_bytes.as_mut_ptr().cast();
            let mut updated_policy_len = updated_policy_bytes.len() as c_int;

            let res = h_rotate_attribute(
                updated_policy_ptr,
                &mut updated_policy_len,
                current_policy_ptr,
                current_policy_len,
                attribute.as_ptr().cast(),
            );

            if res != 0 {
                let mut error = vec![0u8; 8192];
                let error_ptr = error.as_mut_ptr().cast();
                let mut error_len = error.len() as c_int;
                h_get_error(error_ptr, &mut error_len);
                panic!("{}", CStr::from_ptr(error_ptr).to_str().unwrap());
            }
            std::slice::from_raw_parts(updated_policy_ptr.cast(), updated_policy_len as usize)
                .to_vec()
        };

        let attribute = CString::new(attributes[2].to_string()).unwrap();

        policy_bytes = unsafe {
            let current_policy_ptr = policy_bytes.as_ptr().cast();
            let current_policy_len = policy_bytes.len() as c_int;
            let mut updated_policy_bytes = vec![0u8; 8192];
            let updated_policy_ptr = updated_policy_bytes.as_mut_ptr().cast();
            let mut updated_policy_len = updated_policy_bytes.len() as c_int;

            let res = h_rotate_attribute(
                updated_policy_ptr,
                &mut updated_policy_len,
                current_policy_ptr,
                current_policy_len,
                attribute.as_ptr().cast(),
            );
            if res != 0 {
                let mut error = vec![0u8; 8192];
                let error_ptr = error.as_mut_ptr().cast();
                let mut error_len = error.len() as c_int;
                h_get_error(error_ptr, &mut error_len);
                panic!("{}", CStr::from_ptr(error_ptr).to_str().unwrap());
            }
            std::slice::from_raw_parts(updated_policy_ptr.cast(), updated_policy_len as usize)
                .to_vec()
        };

        let ffi_rotated_policy = Policy::parse_and_convert(&policy_bytes).unwrap();

        // Rotate the same attributes using the classic method.
        policy.rotate(&attributes[0]).unwrap();
        policy.rotate(&attributes[2]).unwrap();

        // assert ffi and non-ffi have same behavior.
        assert_eq!(policy, ffi_rotated_policy);
    }
}
