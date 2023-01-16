use std::{
    cell::RefCell,
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum FfiError {
    #[error("Invalid NULL pointer passed for: {0}")]
    NullPointer(String),

    #[error("FFI error: {0}")]
    Generic(String),

    #[error("Deserialize error: {0}")]
    Deserialize(String),
}

/// Return early with an error if a pointer is null
///
/// This macro is equivalent to
///  `
/// if ptr.is_null() {
///     set_last_error(FfiError::NullPointer($msg));
///     return 1;
/// }
/// `.
#[macro_export]
macro_rules! ffi_not_null {
    ($ptr:expr, $msg:literal $(,)?) => {
        if $ptr.is_null() {
            $crate::interfaces::ffi::error::set_last_error(
                $crate::interfaces::ffi::error::FfiError::NullPointer($msg.to_owned()),
            );
            return 1_i32;
        }
    };
}

/// Unwrap a `std::result::Result`
///
/// If the result is in error, set the last error to its error and return 1
#[macro_export]
macro_rules! ffi_unwrap {
    ($result:expr, $msg:literal $(,)?) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                $crate::interfaces::ffi::error::set_last_error(
                    $crate::interfaces::ffi::error::FfiError::Generic(format!("{}: {}", $msg, e)),
                );
                return 1_i32;
            }
        }
    };
    ($result:expr) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                $crate::interfaces::ffi::error::set_last_error(
                    $crate::interfaces::ffi::error::FfiError::Generic(format!("{}", e)),
                );
                return 1_i32;
            }
        }
    };
}

/// Return early with an `FfiError::Generic` error if a condition is not
/// satisfied.
#[macro_export]
macro_rules! ffi_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            $crate::interfaces::ffi::error::set_last_error($crate::interfaces::ffi::error::FfiError::Generic($msg.to_owned()));
            return 1_i32;
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            $crate::interfaces::ffi::error::set_last_error($crate::interfaces::ffi::error::FfiError::Generic($err.to_string()));
            return 1_i32;
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            $crate::interfaces::ffi::error::set_last_error($crate::interfaces::ffi::error::FfiError::Generic(format!($fmt, $($arg)*)));
            return 1_i32;
        }
    };
}

/// Construct a generic error from a string, an ` Error` or an fmt expression.
#[macro_export]
macro_rules! ffi_error {
    ($msg:literal $(,)?) => {
        $crate::interfaces::ffi::error::FfiError::Generic($msg.to_owned())
    };
    ($err:expr $(,)?) => ({
        $crate::interfaces::ffi::error::FfiError::Generic($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::interfaces::ffi::error::FfiError::Generic(format!($fmt, $($arg)*))
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! ffi_bail {
    ($msg:literal $(,)?) => {
        $crate::interfaces::ffi::error::set_last_error($crate::interfaces::ffi::error::FfiError::Generic($msg.to_owned()));
        return 1_i32;
    };
    ($err:expr $(,)?) => {
        $crate::interfaces::ffi::error::set_last_error($crate::interfaces::ffi::error::FfiError::Generic($err.to_string()));
        return 1_i32;
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::interfaces::ffi::error::set_last_error($crate::interfaces::ffi::error::FfiError::Generic(format!($fmt, $($arg)*)));
        return 1_i32;
    };
}

thread_local! {
    /// a thread-local variable which holds the most recent error
    static LAST_ERROR: RefCell<Option<Box<FfiError>>> = RefCell::new(None);
}

/// Set the most recent error, clearing whatever may have been there before.
pub(crate) fn set_last_error(err: FfiError) {
    LAST_ERROR.with(|prev| {
        *prev.borrow_mut() = Some(Box::new(err));
    });
}

/// Externally set the last error recorded on the Rust side
///
/// # Safety
/// This function is meant to be called from the Foreign Function
/// Interface
#[no_mangle]
pub unsafe extern "C" fn set_error(error_message_ptr: *const c_char) -> i32 {
    ffi_not_null!(error_message_ptr, "error message");
    let error_message = match CStr::from_ptr(error_message_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(e) => {
            set_last_error(FfiError::Generic(format!(
                "failed to set error message: {e}"
            )));
            return 1;
        }
    };
    set_last_error(FfiError::Generic(error_message));
    0
}

/// Get the most recent error as utf-8 bytes, clearing it in the process.
/// # Safety
/// - `error_msg`: must be pre-allocated with a sufficient size
#[no_mangle]
pub unsafe extern "C" fn get_last_error(
    error_msg_ptr: *mut c_char,
    error_len: *mut c_int,
) -> c_int {
    if error_msg_ptr.is_null() {
        eprintln!("get_last_error: must pass a pre-allocated buffer");
        return 1;
    }
    if error_len.is_null() {
        eprintln!("get_last_error: must pass a pre-allocated len with the max buffer length");
        return 1;
    }
    if *error_len < 1 {
        eprintln!("get_last_error: the buffer must be at leas one byte long");
        return 1;
    }
    let err = LAST_ERROR.with(|prev| prev.borrow_mut().take());

    // Build a CString that will cleanup NULL bytes in the middle if needed
    let cs = ffi_unwrap!(
        CString::new(err.map_or(String::new(), |e| e.to_string())),
        "failed to convert error to CString"
    );
    // the CString as bytes
    let bytes = cs.as_bytes();

    // leave a space for a null byte at the end if the string exceeds the buffer
    // The actual bytes size, not taking into account the final NULL
    let actual_len = std::cmp::min((*error_len - 1) as usize, bytes.len());

    // create a 0 initialized vector with the message
    let mut result = vec![0; *error_len as usize];
    {
        let (left, _right) = result.split_at_mut(actual_len);
        left.copy_from_slice(&bytes[0..actual_len]);
    }

    //copy the result in the OUT array
    std::slice::from_raw_parts_mut(error_msg_ptr.cast(), *error_len as usize)
        .copy_from_slice(&result);

    *error_len = actual_len as i32;
    0
}
