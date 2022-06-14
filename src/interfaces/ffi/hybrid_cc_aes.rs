#![allow(dead_code)]

use std::{
    collections::HashMap,
    ffi::CStr,
    os::raw::{c_char, c_int},
    sync::{
        atomic::{AtomicI32, Ordering},
        RwLock,
    },
};

use cosmian_crypto_base::{
    asymmetric::ristretto::X25519Crypto,
    hybrid_crypto::{Block, Metadata},
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, SymmetricCrypto},
    KeyTrait,
};
use lazy_static::lazy_static;

use crate::{
    api::{PrivateKey, PublicKey},
    ffi_bail, ffi_not_null, ffi_unwrap,
    interfaces::{
        ffi::error::{set_last_error, FfiError},
        statics::{
            decrypt_hybrid_block, decrypt_hybrid_header, encrypt_hybrid_block,
            encrypt_hybrid_header, ClearTextHeader,
        },
    },
    policies::{Attribute, Policy},
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
    public_key: PublicKey<X25519Crypto>,
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
    public_key_ptr: *const c_char,
    public_key_len: c_int,
) -> i32 {
    ffi_not_null!(policy_ptr, "Policy pointer should not be null");
    ffi_not_null!(public_key_ptr, "Public key pointer should not be null");
    if public_key_len == 0 {
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
    let public_key_bytes =
        std::slice::from_raw_parts(public_key_ptr as *const u8, public_key_len as usize);
    let public_key = match PublicKey::try_from_bytes(public_key_bytes) {
        Ok(key) => key,
        Err(e) => {
            ffi_bail!(format!("Hybrid Cipher: invalid public key: {:?}", e));
        }
    };

    let cache = EncryptionCache { policy, public_key };
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
    attributes_ptr: *const c_char,
    uid_ptr: *const c_char,
    uid_len: c_int,
    additional_data_ptr: *const c_char,
    additional_data_len: c_int,
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
    ffi_not_null!(attributes_ptr, "Attributes pointer should not be null");

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

    // Attributes
    let attributes = match CStr::from_ptr(attributes_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(_e) => {
            set_last_error(FfiError::Generic(
                "Hybrid Cipher: invalid Policy".to_owned(),
            ));
            return 1;
        }
    };
    let attributes: Vec<Attribute> = ffi_unwrap!(serde_json::from_str(&attributes));

    // UID
    let uid = if uid_ptr.is_null() || uid_len == 0 {
        vec![]
    } else {
        std::slice::from_raw_parts(uid_ptr as *const u8, uid_len as usize).to_vec()
    };

    // additional data
    let additional_data = if additional_data_ptr.is_null() || additional_data_len == 0 {
        None
    } else {
        Some(
            std::slice::from_raw_parts(
                additional_data_ptr as *const u8,
                additional_data_len as usize,
            )
            .to_vec(),
        )
    };

    let meta_data = Metadata {
        uid,
        additional_data,
    };

    let encrypted_header = ffi_unwrap!(encrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
        &cache.policy,
        &cache.public_key,
        &attributes,
        Some(&meta_data)
    ));

    let allocated = *symmetric_key_len;
    let symmetric_key_bytes = encrypted_header.symmetric_key.to_bytes();
    let len = symmetric_key_bytes.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated symmetric key buffer is too small; need {} bytes",
            len
        );
    }
    std::slice::from_raw_parts_mut(symmetric_key_ptr as *mut u8, len)
        .copy_from_slice(&symmetric_key_bytes);
    *symmetric_key_len = len as c_int;

    let allocated = *header_bytes_len;
    let len = encrypted_header.header_bytes.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated symmetric key buffer is too small; need {} bytes",
            len
        );
    }
    std::slice::from_raw_parts_mut(header_bytes_ptr as *mut u8, len)
        .copy_from_slice(&encrypted_header.header_bytes);
    *header_bytes_len = len as c_int;
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
    public_key_ptr: *const c_char,
    public_key_len: c_int,
    attributes_ptr: *const c_char,
    uid_ptr: *const c_char,
    uid_len: c_int,
    additional_data_ptr: *const c_char,
    additional_data_len: c_int,
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
    ffi_not_null!(public_key_ptr, "Policy pointer should not be null");
    if public_key_len == 0 {
        ffi_bail!("The public key should not be empty");
    }
    ffi_not_null!(attributes_ptr, "Attributes pointer should not be null");

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
    let public_key_bytes =
        std::slice::from_raw_parts(public_key_ptr as *const u8, public_key_len as usize);
    let public_key = ffi_unwrap!(PublicKey::try_from_bytes(public_key_bytes));

    // Attributes
    let attributes = match CStr::from_ptr(attributes_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(_e) => {
            set_last_error(FfiError::Generic(
                "Hybrid Cipher: invalid Policy".to_owned(),
            ));
            return 1;
        }
    };
    let attributes: Vec<Attribute> = ffi_unwrap!(serde_json::from_str(&attributes));

    // UID
    let uid = if uid_ptr.is_null() || uid_len == 0 {
        vec![]
    } else {
        std::slice::from_raw_parts(uid_ptr as *const u8, uid_len as usize).to_vec()
    };

    // additional data
    let additional_data = if additional_data_ptr.is_null() || additional_data_len == 0 {
        None
    } else {
        Some(
            std::slice::from_raw_parts(
                additional_data_ptr as *const u8,
                additional_data_len as usize,
            )
            .to_vec(),
        )
    };

    let meta_data = Metadata {
        uid,
        additional_data,
    };

    let encrypted_header = ffi_unwrap!(encrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
        &policy,
        &public_key,
        &attributes,
        Some(&meta_data)
    ));

    let allocated = *symmetric_key_len;
    let symmetric_key_bytes = encrypted_header.symmetric_key.to_bytes();
    let len = symmetric_key_bytes.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated symmetric key buffer is too small; need {} bytes, allocated {}",
            len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(symmetric_key_ptr as *mut u8, len)
        .copy_from_slice(&symmetric_key_bytes);
    *symmetric_key_len = len as c_int;

    let allocated = *header_bytes_len;
    let len = encrypted_header.header_bytes.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated encrypted header buffer is too small; need {} bytes, allocated {}",
            len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(header_bytes_ptr as *mut u8, len)
        .copy_from_slice(&encrypted_header.header_bytes);
    *header_bytes_len = len as c_int;

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
    user_decryption_key: PrivateKey<X25519Crypto>,
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
    user_decryption_key_ptr: *const c_char,
    user_decryption_key_len: c_int,
) -> i32 {
    ffi_not_null!(
        user_decryption_key_ptr,
        "User decryption key pointer should not be null"
    );
    if user_decryption_key_len == 0 {
        ffi_bail!("The user decryption key should not be empty");
    }

    // User decryption key
    let user_decryption_key_bytes = std::slice::from_raw_parts(
        user_decryption_key_ptr as *const u8,
        user_decryption_key_len as usize,
    );
    let user_decryption_key = match PrivateKey::try_from_bytes(user_decryption_key_bytes) {
        Ok(key) => key,
        Err(e) => {
            ffi_bail!(format!(
                "Hybrid Cipher: invalid user decryption key: {:?}",
                e
            ));
        }
    };

    let cache = DecryptionCache {
        user_decryption_key,
    };
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
/// Decrypt an encrypted header using a cache.
/// Returns the symmetric key,
/// the uid and additional data if available.
///
/// No additional data will be returned if the `additional_data_ptr` is NULL.
///
/// # Safety
pub unsafe extern "C" fn h_aes_decrypt_header_using_cache(
    symmetric_key_ptr: *mut c_char,
    symmetric_key_len: *mut c_int,
    uid_ptr: *mut c_char,
    uid_len: *mut c_int,
    additional_data_ptr: *mut c_char,
    additional_data_len: *mut c_int,
    encrypted_header_ptr: *const c_char,
    encrypted_header_len: c_int,
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

    let encrypted_header_bytes = std::slice::from_raw_parts(
        encrypted_header_ptr as *const u8,
        encrypted_header_len as usize,
    );

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

    let header: ClearTextHeader<Aes256GcmCrypto> =
        ffi_unwrap!(decrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
            &cache.user_decryption_key,
            encrypted_header_bytes
        ));

    // Symmetric Key
    let allocated = *symmetric_key_len;
    let symmetric_key_bytes = header.symmetric_key.to_bytes();
    let len = symmetric_key_bytes.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated symmetric key buffer is too small; need {} bytes",
            len
        );
    }
    std::slice::from_raw_parts_mut(symmetric_key_ptr as *mut u8, len)
        .copy_from_slice(&symmetric_key_bytes);
    *symmetric_key_len = len as c_int;

    // UID - if expected
    if !uid_ptr.is_null() && *uid_len > 0 {
        let allocated = *uid_len;
        let uid_bytes = &header.meta_data.uid;
        let len = uid_bytes.len();
        if (allocated as usize) < len {
            ffi_bail!(
                "The pre-allocated uid buffer is too small; need {} bytes",
                len
            );
        }
        std::slice::from_raw_parts_mut(uid_ptr as *mut u8, len).copy_from_slice(uid_bytes);
        *uid_len = len as c_int;
    }

    // additional data - if expected
    if !additional_data_ptr.is_null() && *additional_data_len > 0 {
        let allocated = *additional_data_len;
        let additional_data_bytes = &header.meta_data.additional_data;
        if let Some(ad) = additional_data_bytes {
            let len = ad.len();
            if (allocated as usize) < len {
                ffi_bail!(
                    "The pre-allocated additional_data buffer is too small; need {} bytes",
                    len
                );
            }
            std::slice::from_raw_parts_mut(additional_data_ptr as *mut u8, len).copy_from_slice(ad);
            *additional_data_len = len as c_int;
        } else {
            *additional_data_len = 0_i32;
        }
    }

    0
}

#[no_mangle]
/// # Safety
pub unsafe extern "C" fn h_get_encrypted_header_size(
    encrypted_ptr: *const c_char,
    encrypted_len: c_int,
) -> c_int {
    ffi_not_null!(encrypted_ptr, "Encrypted bytes pointer should not be bull");
    //
    // Check `encrypted_bytes` input param and store it locally
    if encrypted_len == 0 {
        ffi_bail!("Encrypted value must be at least 4-bytes long");
    }
    let encrypted_header_bytes =
        std::slice::from_raw_parts(encrypted_ptr as *const u8, encrypted_len as usize);

    //
    // Recover header from `encrypted_bytes`
    let mut header_size_bytes = [0; 4];
    header_size_bytes.copy_from_slice(&encrypted_header_bytes.to_vec()[0..4]);
    i32::from_be_bytes(header_size_bytes)
}

#[no_mangle]
/// Decrypt an encrypted header returning the symmetric key,
/// the uid and additional data if available.
///
/// Slower tha using a cache but avoids handling the cache creation and
/// destruction.
///
/// No additional data will be returned if the `additional_data_ptr` is NULL.
///
/// # Safety
pub unsafe extern "C" fn h_aes_decrypt_header(
    symmetric_key_ptr: *mut c_char,
    symmetric_key_len: *mut c_int,
    uid_ptr: *mut c_char,
    uid_len: *mut c_int,
    additional_data_ptr: *mut c_char,
    additional_data_len: *mut c_int,
    encrypted_header_ptr: *const c_char,
    encrypted_header_len: c_int,
    user_decryption_key_ptr: *const c_char,
    user_decryption_key_len: c_int,
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
        user_decryption_key_ptr,
        "The user decryption key pointer should not be null"
    );
    if user_decryption_key_len == 0 {
        ffi_bail!("The user decryption key should not be empty");
    }

    let encrypted_header_bytes = std::slice::from_raw_parts(
        encrypted_header_ptr as *const u8,
        encrypted_header_len as usize,
    );

    let user_decryption_key_bytes = std::slice::from_raw_parts(
        user_decryption_key_ptr as *const u8,
        user_decryption_key_len as usize,
    );
    let user_decryption_key = ffi_unwrap!(PrivateKey::try_from_bytes(user_decryption_key_bytes));

    let header: ClearTextHeader<Aes256GcmCrypto> =
        ffi_unwrap!(decrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
            &user_decryption_key,
            encrypted_header_bytes
        ));

    // Symmetric Key
    let allocated = *symmetric_key_len;
    let symmetric_key_bytes = header.symmetric_key.to_bytes();
    let len = symmetric_key_bytes.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated symmetric key buffer is too small; need {} bytes",
            len
        );
    }
    std::slice::from_raw_parts_mut(symmetric_key_ptr as *mut u8, len)
        .copy_from_slice(&symmetric_key_bytes);
    *symmetric_key_len = len as c_int;

    // UID - if expected
    if !uid_ptr.is_null() && *uid_len > 0 {
        let allocated = *uid_len;
        let uid_bytes = &header.meta_data.uid;
        let len = uid_bytes.len();
        if (allocated as usize) < len {
            ffi_bail!(
                "The pre-allocated uid buffer is too small; need {} bytes",
                len
            );
        }
        std::slice::from_raw_parts_mut(uid_ptr as *mut u8, len).copy_from_slice(uid_bytes);
        *uid_len = len as c_int;
    }

    // additional data - if expected
    if !additional_data_ptr.is_null() && *additional_data_len > 0 {
        let allocated = *additional_data_len;
        let additional_data_bytes = &header.meta_data.additional_data;
        if let Some(ad) = additional_data_bytes {
            let len = ad.len();
            if (allocated as usize) < len {
                ffi_bail!(
                    "The pre-allocated additional_data buffer is too small; need {} bytes",
                    len
                );
            }
            std::slice::from_raw_parts_mut(additional_data_ptr as *mut u8, len).copy_from_slice(ad);
            *additional_data_len = len as c_int;
        } else {
            *additional_data_len = 0_i32;
        }
    }

    0
}

// maximum clear text size that can be safely encrypted with AES GCM (using a a
// single random nonce)
pub const MAX_CLEAR_TEXT_SIZE: usize = 1_usize << 30;

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn h_aes_symmetric_encryption_overhead() -> c_int {
    Block::<Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>::ENCRYPTION_OVERHEAD as c_int
}

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn h_aes_encrypt_block(
    encrypted_ptr: *mut c_char,
    encrypted_len: *mut c_int,
    symmetric_key_ptr: *const c_char,
    symmetric_key_len: c_int,
    uid_ptr: *const c_char,
    uid_len: c_int,
    block_number: c_int,
    data_ptr: *const c_char,
    data_len: c_int,
) -> c_int {
    ffi_not_null!(
        encrypted_ptr,
        "The encrypted bytes pointer should point to pre-allocated memory"
    );
    if *encrypted_len == 0 {
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
        std::slice::from_raw_parts(symmetric_key_ptr as *const u8, symmetric_key_len as usize)
            .to_vec();

    // UID
    let uid = if !uid_ptr.is_null() && uid_len > 0 {
        std::slice::from_raw_parts(uid_ptr as *const u8, uid_len as usize).to_vec()
    } else {
        vec![]
    };

    // Data
    ffi_not_null!(data_ptr, "Data pointer should not be null");
    if data_len == 0 {
        ffi_bail!("The data should not be empty");
    }
    let data = std::slice::from_raw_parts(data_ptr as *const u8, data_len as usize).to_vec();

    let symmetric_key = ffi_unwrap!(<Aes256GcmCrypto as SymmetricCrypto>::Key::try_from_bytes(
        symmetric_key
    ));
    let encrypted_block = ffi_unwrap!(encrypt_hybrid_block::<
        X25519Crypto,
        Aes256GcmCrypto,
        MAX_CLEAR_TEXT_SIZE,
    >(&symmetric_key, &uid, block_number as usize, &data));

    let allocated = *encrypted_len;
    let len = encrypted_block.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated encrypted bytes buffer is too small; need {} bytes",
            len
        );
    }
    std::slice::from_raw_parts_mut(encrypted_ptr as *mut u8, len).copy_from_slice(&encrypted_block);
    *encrypted_len = len as c_int;

    0
}

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn h_aes_decrypt_block(
    clear_text_ptr: *mut c_char,
    clear_text_len: *mut c_int,
    symmetric_key_ptr: *const c_char,
    symmetric_key_len: c_int,
    uid_ptr: *const c_char,
    uid_len: c_int,
    block_number: c_int,
    encrypted_bytes_ptr: *const c_char,
    encrypted_bytes_len: c_int,
) -> c_int {
    ffi_not_null!(
        clear_text_ptr,
        "The clear text bytes pointer should point to pre-allocated memory"
    );
    if *clear_text_len == 0 {
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
        std::slice::from_raw_parts(symmetric_key_ptr as *const u8, symmetric_key_len as usize)
            .to_vec();

    // UID
    let uid = if !uid_ptr.is_null() && uid_len > 0 {
        std::slice::from_raw_parts(uid_ptr as *const u8, uid_len as usize).to_vec()
    } else {
        vec![]
    };

    // Data
    ffi_not_null!(encrypted_bytes_ptr, "Data pointer should not be null");
    if encrypted_bytes_len == 0 {
        ffi_bail!("The data should not be empty");
    }
    let data = std::slice::from_raw_parts(
        encrypted_bytes_ptr as *const u8,
        encrypted_bytes_len as usize,
    )
    .to_vec();

    let symmetric_key = ffi_unwrap!(<Aes256GcmCrypto as SymmetricCrypto>::Key::try_from_bytes(
        symmetric_key
    ));
    let encrypted_block = ffi_unwrap!(decrypt_hybrid_block::<
        X25519Crypto,
        Aes256GcmCrypto,
        MAX_CLEAR_TEXT_SIZE,
    >(&symmetric_key, &uid, block_number as usize, &data));

    let allocated = *clear_text_len;
    let len = encrypted_block.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated clear text buffer is too small; need {} bytes",
            len
        );
    }
    std::slice::from_raw_parts_mut(clear_text_ptr as *mut u8, len)
        .copy_from_slice(&encrypted_block);
    *clear_text_len = len as c_int;

    0
}
