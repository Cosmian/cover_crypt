#![allow(dead_code)]

use crate::{
    api::CoverCrypt,
    ffi_bail, ffi_not_null, ffi_unwrap,
    interfaces::{
        ffi::error::{set_last_error, FfiError},
        statics::{CoverCryptX25519Aes256, EncryptedHeader, PublicKey, UserSecretKey, DEM},
    },
};
use abe_policy::{AccessPolicy, Policy};
use cosmian_crypto_core::{bytes_ser_de::Serializable, symmetric_crypto::Dem, KeyTrait};
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    ffi::CStr,
    os::raw::{c_char, c_int},
    sync::{
        atomic::{AtomicI32, Ordering},
        RwLock,
    },
};

// -------------------------------
//         Encryption
// -------------------------------

// A static cache of the Encryption Caches
lazy_static! {
    static ref ENCRYPTION_CACHE_MAP: RwLock<HashMap<i32, EncryptionCache>> =
        RwLock::new(HashMap::new());
    static ref NEXT_ENCRYPTION_CACHE_ID: std::sync::atomic::AtomicI32 = AtomicI32::new(0);
}

/// An Encryption Cache that will be used to cache Rust side
/// the Public Key and the Policy when doing multiple serial encryptions
pub struct EncryptionCache {
    policy: Policy,
    pk: PublicKey,
}

#[no_mangle]
/// Create a cache of the Public Key and Policy which can be re-used
/// when encrypting multiple messages. This avoids having to re-instantiate
/// the public key on the Rust side on every encryption which is costly.
///
/// This method is to be used in conjunction with
///     h_aes_encrypt_header_using_cache
///
/// WARN: h_aes_destroy_encrypt_cache() should be called
/// to reclaim the memory of the cache when done
/// # Safety
pub unsafe extern "C" fn h_aes_create_encryption_cache(
    cache_handle: *mut c_int,
    policy_ptr: *const c_char,
    pk_ptr: *const c_char,
    pk_len: c_int,
) -> i32 {
    ffi_not_null!(policy_ptr, "Policy pointer should not be null");
    ffi_not_null!(pk_ptr, "Public key pointer should not be null");
    if pk_len == 0 {
        ffi_bail!("The public key should not be empty");
    }
    // Policy
    let policy = match CStr::from_ptr(policy_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(_e) => {
            ffi_bail!("Hybrid Cipher: invalid Policy".to_owned(),);
        }
    };
    let policy: Policy = match serde_json::from_str(&policy) {
        Ok(p) => p,
        Err(e) => {
            ffi_bail!(format!("Hybrid Cipher: invalid Policy: {:?}", e));
        }
    };

    // Public Key
    let pk_bytes = std::slice::from_raw_parts(pk_ptr.cast(), pk_len as usize);
    let pk = match PublicKey::try_from_bytes(pk_bytes) {
        Ok(key) => key,
        Err(e) => {
            ffi_bail!(format!("Hybrid Cipher: invalid public key: {:?}", e));
        }
    };

    let cache = EncryptionCache { policy, pk };
    let id = NEXT_ENCRYPTION_CACHE_ID.fetch_add(1, Ordering::Acquire);
    let mut map = ENCRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on encryption cache failed");
    map.insert(id, cache);
    *cache_handle = id;
    0
}

#[no_mangle]
/// The function should be called to reclaim memory
/// of the cache created using h_aes_create_encrypt_cache()
/// # Safety
pub unsafe extern "C" fn h_aes_destroy_encryption_cache(cache_handle: c_int) -> c_int {
    let mut map = ENCRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on encryption cache failed");
    map.remove(&cache_handle);
    0
}

#[no_mangle]
/// Encrypt a header using an encryption cache
/// The symmetric key and header bytes are returned in the first OUT parameters
/// # Safety
pub unsafe extern "C" fn h_aes_encrypt_header_using_cache(
    symmetric_key_ptr: *mut c_char,
    symmetric_key_len: *mut c_int,
    header_bytes_ptr: *mut c_char,
    header_bytes_len: *mut c_int,
    cache_handle: c_int,
    access_policy_ptr: *const c_char,
    additional_data_ptr: *const c_char,
    additional_data_len: c_int,
    authenticated_data_ptr: *const c_char,
    authenticated_data_len: c_int,
) -> c_int {
    ffi_not_null!(
        symmetric_key_ptr,
        "Symmetric key pointer should point to pre-allocated memory"
    );
    if (symmetric_key_len as usize) < CoverCryptX25519Aes256::SYM_KEY_LENGTH {
        ffi_bail!(
            "The pre-allocated symmetric key buffer is too small; need {} bytes",
            CoverCryptX25519Aes256::SYM_KEY_LENGTH
        );
    }
    ffi_not_null!(
        header_bytes_ptr,
        "Header bytes pointer should point to pre-allocated memory"
    );
    if *header_bytes_len == 0 {
        ffi_bail!("The header bytes buffer should have a size greater than zero");
    }
    ffi_not_null!(access_policy_ptr, "Attributes pointer should not be null");

    let map = ENCRYPTION_CACHE_MAP
        .read()
        .expect("a read mutex on the encryption cache failed");
    let cache = if let Some(cache) = map.get(&cache_handle) {
        cache
    } else {
        set_last_error(FfiError::Generic(format!(
            "Hybrid Cipher: no encryption cache with handle: {}",
            cache_handle
        )));
        return 1;
    };

    // Access policy
    let access_policy = match CStr::from_ptr(access_policy_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(_e) => {
            set_last_error(FfiError::Generic(
                "Hybrid Cipher: invalid Policy".to_owned(),
            ));
            return 1;
        }
    };
    let access_policy = ffi_unwrap!(AccessPolicy::from_boolean_expression(&access_policy));

    // Additional Data
    let additional_data = if additional_data_ptr.is_null() || additional_data_len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(
            additional_data_ptr.cast(),
            additional_data_len as usize,
        ))
    };

    // Authenticated Data
    let authenticated_data = if authenticated_data_ptr.is_null() || authenticated_data_len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(
            authenticated_data_ptr.cast(),
            authenticated_data_len as usize,
        ))
    };

    let (symmetric_key, encrypted_header) = ffi_unwrap!(EncryptedHeader::generate(
        &CoverCryptX25519Aes256::default(),
        &cache.policy,
        &cache.pk,
        &access_policy,
        additional_data,
        authenticated_data,
    ));

    // serialize symmetric key
    let symmetric_key_bytes = symmetric_key.to_bytes();
    *symmetric_key_len = CoverCryptX25519Aes256::SYM_KEY_LENGTH as c_int;
    std::slice::from_raw_parts_mut(symmetric_key_ptr.cast(), symmetric_key_bytes.len())
        .copy_from_slice(&symmetric_key_bytes);

    // serialize encrypted header
    let encrypted_header_bytes = ffi_unwrap!(encrypted_header.try_to_bytes());
    if (header_bytes_len as usize) < encrypted_header_bytes.len() {
        ffi_bail!(
            "The pre-allocated symmetric key buffer is too small; need {} bytes",
            *header_bytes_len
        );
    }
    *header_bytes_len = encrypted_header_bytes.len() as c_int;
    std::slice::from_raw_parts_mut(header_bytes_ptr.cast(), encrypted_header_bytes.len())
        .copy_from_slice(&encrypted_header_bytes);

    0
}

#[no_mangle]
/// Encrypt a header without using an encryption cache.
/// It is slower but does not require destroying any cache when done.
///
/// The symmetric key and header bytes are returned in the first OUT parameters
/// # Safety
pub unsafe extern "C" fn h_aes_encrypt_header(
    symmetric_key_ptr: *mut c_char,
    symmetric_key_len: *mut c_int,
    header_bytes_ptr: *mut c_char,
    header_bytes_len: *mut c_int,
    policy_ptr: *const c_char,
    pk_ptr: *const c_char,
    pk_len: c_int,
    access_policy_ptr: *const c_char,
    additional_data_ptr: *const c_char,
    additional_data_len: c_int,
    authenticated_data_ptr: *const c_char,
    authenticated_data_len: c_int,
) -> c_int {
    ffi_not_null!(
        symmetric_key_ptr,
        "Symmetric key pointer should point to pre-allocated memory"
    );
    if *symmetric_key_len == 0 {
        ffi_bail!("The symmetric key buffer should have a size greater than zero");
    }
    ffi_not_null!(
        header_bytes_ptr,
        "Header bytes pointer should point to pre-allocated memory"
    );
    if *header_bytes_len == 0 {
        ffi_bail!("The header bytes buffer should have a size greater than zero");
    }
    ffi_not_null!(policy_ptr, "Policy pointer should not be null");
    ffi_not_null!(pk_ptr, "Policy pointer should not be null");
    if pk_len == 0 {
        ffi_bail!("The public key should not be empty");
    }
    ffi_not_null!(access_policy_ptr, "Attributes pointer should not be null");

    // Policy
    let policy = match CStr::from_ptr(policy_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(_e) => {
            set_last_error(FfiError::Generic(
                "Hybrid Cipher: invalid Policy".to_owned(),
            ));
            return 1;
        }
    };
    let policy: Policy = ffi_unwrap!(serde_json::from_str(&policy));

    // Public Key
    let pk_bytes = std::slice::from_raw_parts(pk_ptr.cast(), pk_len as usize);
    let pk = ffi_unwrap!(PublicKey::try_from_bytes(pk_bytes));

    // Access policy
    let access_policy = match CStr::from_ptr(access_policy_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(_e) => {
            set_last_error(FfiError::Generic(
                "Hybrid Cipher: invalid attributes".to_owned(),
            ));
            return 1;
        }
    };
    let access_policy = ffi_unwrap!(AccessPolicy::from_boolean_expression(&access_policy));

    // Additional Data
    let additional_data = if additional_data_ptr.is_null() || additional_data_len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(
            additional_data_ptr.cast(),
            additional_data_len as usize,
        ))
    };

    // Authenticated Data
    let authenticated_data = if authenticated_data_ptr.is_null() || authenticated_data_len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(
            authenticated_data_ptr.cast(),
            authenticated_data_len as usize,
        ))
    };

    let (symmetric_key, encrypted_header) = ffi_unwrap!(EncryptedHeader::generate(
        &CoverCryptX25519Aes256::default(),
        &policy,
        &pk,
        &access_policy,
        additional_data,
        authenticated_data
    ));

    let allocated = *symmetric_key_len;
    let symmetric_key_bytes = symmetric_key.to_bytes();
    *symmetric_key_len = symmetric_key_bytes.len() as c_int;
    if allocated < *symmetric_key_len {
        ffi_bail!(
            "The pre-allocated symmetric key buffer is too small; need {} bytes, allocated {}",
            *symmetric_key_len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(symmetric_key_ptr.cast(), symmetric_key_bytes.len())
        .copy_from_slice(&symmetric_key_bytes);

    let encrypted_header_bytes = ffi_unwrap!(encrypted_header.try_to_bytes());
    let allocated = *header_bytes_len;
    *header_bytes_len = encrypted_header_bytes.len() as c_int;
    if allocated < *header_bytes_len {
        ffi_bail!(
            "The pre-allocated encrypted header buffer is too small; need {} bytes, allocated {}",
            *header_bytes_len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(header_bytes_ptr.cast(), encrypted_header_bytes.len())
        .copy_from_slice(&encrypted_header_bytes);

    0
}

// -------------------------------
//         Decryption
// -------------------------------

// A cache of the decryption caches
lazy_static! {
    static ref DECRYPTION_CACHE_MAP: RwLock<HashMap<i32, DecryptionCache>> =
        RwLock::new(HashMap::new());
    static ref NEXT_DECRYPTION_CACHE_ID: std::sync::atomic::AtomicI32 = AtomicI32::new(0);
}

/// A Decryption Cache that will be used to cache Rust side
/// the User Decryption Key when performing serial decryptions
pub struct DecryptionCache {
    usk: UserSecretKey,
}

#[no_mangle]
/// Create a cache of the User Decryption Key which can be re-used
/// when decrypting multiple messages. This avoids having to re-instantiate
/// the user key on the Rust side on every decryption which is costly.
///
/// This method is to be used in conjunction with
///     h_aes_decrypt_header_using_cache()
///
/// WARN: h_aes_destroy_decryption_cache() should be called
/// to reclaim the memory of the cache when done
/// # Safety
pub unsafe extern "C" fn h_aes_create_decryption_cache(
    cache_handle: *mut c_int,
    usk_ptr: *const c_char,
    usk_len: c_int,
) -> i32 {
    ffi_not_null!(usk_ptr, "User decryption key pointer should not be null");
    if usk_len == 0 {
        ffi_bail!("The user decryption key should not be empty");
    }

    // User decryption key
    let usk_bytes = std::slice::from_raw_parts(usk_ptr.cast(), usk_len as usize);
    let usk = match UserSecretKey::try_from_bytes(usk_bytes) {
        Ok(key) => key,
        Err(e) => {
            ffi_bail!(format!(
                "Hybrid Cipher: invalid user decryption key: {:?}",
                e
            ));
        }
    };

    let cache = DecryptionCache { usk };
    let id = NEXT_DECRYPTION_CACHE_ID.fetch_add(1, Ordering::Acquire);
    let mut map = DECRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on decryption cache failed");
    map.insert(id, cache);
    *cache_handle = id;
    0
}

#[no_mangle]
/// The function should be called to reclaim memory
/// of the cache created using h_aes_create_decryption_cache()
/// # Safety
pub unsafe extern "C" fn h_aes_destroy_decryption_cache(cache_handle: c_int) -> c_int {
    let mut map = DECRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on decryption cache failed");
    map.remove(&cache_handle);
    0
}

#[no_mangle]
/// Decrypts an encrypted header using a cache.
/// Returns the symmetric key and additional data if available.
///
/// No additional data will be returned if the `additional_data_ptr` is NULL.
///
/// # Safety
pub unsafe extern "C" fn h_aes_decrypt_header_using_cache(
    symmetric_key_ptr: *mut c_char,
    symmetric_key_len: *mut c_int,
    additional_data_ptr: *mut c_char,
    additional_data_len: *mut c_int,
    encrypted_header_ptr: *const c_char,
    encrypted_header_len: c_int,
    authenticated_data_ptr: *const c_char,
    authenticated_data_len: c_int,
    cache_handle: c_int,
) -> c_int {
    ffi_not_null!(
        symmetric_key_ptr,
        "Symmetric key pointer should point to pre-allocated memory"
    );
    if *symmetric_key_len == 0 {
        ffi_bail!("The symmetric key buffer should have a size greater than zero");
    }
    ffi_not_null!(
        encrypted_header_ptr,
        "Encrypted header bytes pointer should not be bull"
    );
    if encrypted_header_len == 0 {
        ffi_bail!("The encrypted header bytes size should be greater than zero");
    }

    let encrypted_header_bytes =
        std::slice::from_raw_parts(encrypted_header_ptr.cast(), encrypted_header_len as usize);

    let map = DECRYPTION_CACHE_MAP
        .read()
        .expect("a read mutex on the decryption cache failed");
    let cache = if let Some(cache) = map.get(&cache_handle) {
        cache
    } else {
        set_last_error(FfiError::Generic(format!(
            "Hybrid Cipher: no decryption cache with handle: {}",
            cache_handle
        )));
        return 1;
    };

    // Authenticated Data
    let authenticated_data = if authenticated_data_ptr.is_null() || authenticated_data_len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(
            authenticated_data_ptr.cast(),
            authenticated_data_len as usize,
        ))
    };

    // Decrypt header
    let encrypted_header = ffi_unwrap!(EncryptedHeader::try_from_bytes(encrypted_header_bytes));
    let header = ffi_unwrap!(encrypted_header.decrypt(
        &CoverCryptX25519Aes256::default(),
        &cache.usk,
        authenticated_data
    ));

    // Symmetric Key
    let allocated = *symmetric_key_len;
    let symmetric_key_bytes = header.symmetric_key.to_bytes();
    *symmetric_key_len = symmetric_key_bytes.len() as c_int;
    if allocated < *symmetric_key_len {
        ffi_bail!(
            "The pre-allocated symmetric key buffer is too small; need {} bytes",
            *symmetric_key_len
        );
    }
    std::slice::from_raw_parts_mut(symmetric_key_ptr.cast(), symmetric_key_bytes.len())
        .copy_from_slice(&symmetric_key_bytes);

    // serialize additional data
    if !additional_data_ptr.is_null() && *additional_data_len > 0 {
        if (additional_data_len as usize) < header.additional_data.len() {
            ffi_bail!(
                "The pre-allocated additional data buffer is too small; need {} bytes",
                header.additional_data.len()
            );
        }
        *additional_data_len = header.additional_data.len() as c_int;
        std::slice::from_raw_parts_mut(additional_data_ptr.cast(), header.additional_data.len())
            .copy_from_slice(&header.additional_data);
    }

    0
}

#[no_mangle]
/// Decrypts an encrypted header, returning the symmetric key and additional
/// data if available.
///
/// Slower than using a cache but avoids handling the cache creation and
/// destruction.
///
/// No additional data will be returned if the `additional_data_ptr` is NULL.
///
/// # Safety
pub unsafe extern "C" fn h_aes_decrypt_header(
    symmetric_key_ptr: *mut c_char,
    symmetric_key_len: *mut c_int,
    additional_data_ptr: *mut c_char,
    additional_data_len: *mut c_int,
    encrypted_header_ptr: *const c_char,
    encrypted_header_len: c_int,
    authenticated_data_ptr: *const c_char,
    authenticated_data_len: c_int,
    usk_ptr: *const c_char,
    usk_len: c_int,
) -> c_int {
    ffi_not_null!(
        symmetric_key_ptr,
        "Symmetric key pointer should point to pre-allocated memory"
    );
    if *symmetric_key_len == 0 {
        ffi_bail!("The symmetric key buffer should have a size greater than zero");
    }
    ffi_not_null!(
        encrypted_header_ptr,
        "Encrypted header bytes pointer should not be bull"
    );
    if encrypted_header_len == 0 {
        ffi_bail!("The encrypted header bytes size should be greater than zero");
    }
    ffi_not_null!(
        usk_ptr,
        "The user decryption key pointer should not be null"
    );
    if usk_len == 0 {
        ffi_bail!("The user decryption key should not be empty");
    }

    let encrypted_header_bytes =
        std::slice::from_raw_parts(encrypted_header_ptr.cast(), encrypted_header_len as usize);

    let usk_bytes = std::slice::from_raw_parts(usk_ptr.cast(), usk_len as usize);
    let usk = ffi_unwrap!(UserSecretKey::try_from_bytes(usk_bytes));

    // Authenticated Data
    let authenticated_data = if authenticated_data_ptr.is_null() || authenticated_data_len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(
            authenticated_data_ptr.cast(),
            authenticated_data_len as usize,
        ))
    };

    // Decrypt header
    let encrypted_header = ffi_unwrap!(EncryptedHeader::try_from_bytes(encrypted_header_bytes));
    let decrypted_header = ffi_unwrap!(encrypted_header.decrypt(
        &CoverCryptX25519Aes256::default(),
        &usk,
        authenticated_data
    ));

    // Symmetric Key
    let allocated = *symmetric_key_len;
    let symmetric_key_bytes = decrypted_header.symmetric_key.to_bytes();
    *symmetric_key_len = symmetric_key_bytes.len() as c_int;
    if allocated < *symmetric_key_len {
        ffi_bail!(
            "The pre-allocated symmetric key buffer is too small; need {} bytes",
            *symmetric_key_len
        );
    }
    std::slice::from_raw_parts_mut(symmetric_key_ptr.cast(), symmetric_key_bytes.len())
        .copy_from_slice(&symmetric_key_bytes);

    // additional data
    if !additional_data_ptr.is_null() && *additional_data_len > 0 {
        if (additional_data_len as usize) < decrypted_header.additional_data.len() {
            ffi_bail!(
                "The pre-allocated additional_data buffer is too small; need {} bytes",
                decrypted_header.additional_data.len()
            );
        }
        *additional_data_len = decrypted_header.additional_data.len() as c_int;
        std::slice::from_raw_parts_mut(
            additional_data_ptr.cast(),
            decrypted_header.additional_data.len(),
        )
        .copy_from_slice(&decrypted_header.additional_data);
    }

    0
}

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn h_aes_symmetric_encryption_overhead() -> c_int {
    DEM::ENCRYPTION_OVERHEAD as c_int
}

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn h_aes_encrypt_block(
    ciphertext_ptr: *mut c_char,
    ciphertext_len: *mut c_int,
    symmetric_key_ptr: *const c_char,
    symmetric_key_len: c_int,
    associated_data_ptr: *const c_char,
    associated_data_len: c_int,
    plaintext_ptr: *const c_char,
    plaintext_len: c_int,
) -> c_int {
    ffi_not_null!(
        ciphertext_ptr,
        "The encrypted bytes pointer should point to pre-allocated memory"
    );
    if *ciphertext_len == 0 {
        ffi_bail!("The encrypted bytes buffer should have a size greater than zero");
    }

    // Symmetric Key
    ffi_not_null!(
        symmetric_key_ptr,
        "Symmetric Key pointer should not be null"
    );
    if symmetric_key_len == 0 {
        ffi_bail!("The Symmetric Key should not be empty");
    }
    let symmetric_key =
        std::slice::from_raw_parts(symmetric_key_ptr.cast(), symmetric_key_len as usize).to_vec();

    //
    // Associated Data
    let associated_data = if !associated_data_ptr.is_null() && associated_data_len > 0 {
        std::slice::from_raw_parts(associated_data_ptr.cast(), associated_data_len as usize)
            .to_vec()
    } else {
        vec![]
    };

    let ad = if associated_data.is_empty() {
        None
    } else {
        Some(associated_data.as_slice())
    };

    ffi_not_null!(plaintext_ptr, "Plaintext pointer should not be null");
    if plaintext_len == 0 {
        ffi_bail!("The plaintext should not be empty");
    }

    let plaintext =
        std::slice::from_raw_parts(plaintext_ptr.cast(), plaintext_len as usize).to_vec();

    let symmetric_key = ffi_unwrap!(<DEM as Dem<{ DEM::KEY_LENGTH }>>::Key::try_from_bytes(
        &symmetric_key.to_vec()
    ));
    let ciphertext =
        ffi_unwrap!(CoverCryptX25519Aes256::default().encrypt(&symmetric_key, &plaintext, ad,));

    let allocated = *ciphertext_len;
    *ciphertext_len = ciphertext.len() as c_int;
    if allocated < *ciphertext_len {
        ffi_bail!(
            "The pre-allocated encrypted bytes buffer is too small; need {} bytes",
            *ciphertext_len
        );
    }
    std::slice::from_raw_parts_mut(ciphertext_ptr.cast(), ciphertext.len())
        .copy_from_slice(&ciphertext);

    0
}

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn h_aes_decrypt_block(
    cleartext_ptr: *mut c_char,
    cleartext_len: *mut c_int,
    symmetric_key_ptr: *const c_char,
    symmetric_key_len: c_int,
    associated_data_ptr: *const c_char,
    associated_data_len: c_int,
    encrypted_bytes_ptr: *const c_char,
    encrypted_bytes_len: c_int,
) -> c_int {
    ffi_not_null!(
        cleartext_ptr,
        "The clear text bytes pointer should point to pre-allocated memory"
    );
    if *cleartext_len == 0 {
        ffi_bail!("The clear text bytes buffer should have a size greater than zero");
    }

    // Symmetric Key
    ffi_not_null!(
        symmetric_key_ptr,
        "Symmetric Key pointer should not be null"
    );
    if symmetric_key_len == 0 {
        ffi_bail!("The Symmetric Key should not be empty");
    }
    let symmetric_key =
        std::slice::from_raw_parts(symmetric_key_ptr.cast(), symmetric_key_len as usize).to_vec();

    // Data
    ffi_not_null!(encrypted_bytes_ptr, "Data pointer should not be null");
    if encrypted_bytes_len == 0 {
        ffi_bail!("The data should not be empty");
    }
    let ciphertext =
        std::slice::from_raw_parts(encrypted_bytes_ptr.cast(), encrypted_bytes_len as usize)
            .to_vec();

    let symmetric_key = ffi_unwrap!(<DEM as Dem<{ DEM::KEY_LENGTH }>>::Key::try_from_bytes(
        &symmetric_key.to_vec()
    ));

    //
    // Associated Data
    let associated_data = if !associated_data_ptr.is_null() && associated_data_len > 0 {
        std::slice::from_raw_parts(associated_data_ptr.cast(), associated_data_len as usize)
            .to_vec()
    } else {
        vec![]
    };

    let ad = if associated_data.is_empty() {
        None
    } else {
        Some(associated_data.as_slice())
    };

    //
    // Decrypt block
    let cleartext =
        ffi_unwrap!(CoverCryptX25519Aes256::default().decrypt(&symmetric_key, &ciphertext, ad,));

    let allocated = *cleartext_len;
    *cleartext_len = cleartext.len() as c_int;
    if allocated < *cleartext_len {
        ffi_bail!(
            "The pre-allocated clear text buffer is too small; need {} bytes",
            *cleartext_len
        );
    }
    std::slice::from_raw_parts_mut(cleartext_ptr.cast(), cleartext.len())
        .copy_from_slice(&cleartext);

    0
}
