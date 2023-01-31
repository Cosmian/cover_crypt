#![allow(dead_code)]

use std::{
    collections::HashMap,
    os::raw::{c_char, c_int},
    sync::{
        atomic::{AtomicI32, Ordering},
        RwLock,
    },
};

use abe_policy::{AccessPolicy, Policy};
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    symmetric_crypto::{Dem, SymKey},
    KeyTrait,
};
use cosmian_ffi::{ffi_bail, ffi_read_bytes, ffi_read_string, ffi_unwrap, ffi_write_bytes};
use lazy_static::lazy_static;

use crate::{
    statics::{CoverCryptX25519Aes256, EncryptedHeader, PublicKey, UserSecretKey, DEM},
    CoverCrypt,
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
    mpk: PublicKey,
}

#[no_mangle]
/// Creates a cache containing the Public Key and Policy. This cache can be
/// reused when encrypting messages which avoids passing these objects to Rust
/// in each call.
///
/// WARNING: [`h_aes_destroy_encrypt_cache()`](h_aes_destroy_encryption_cache)
/// should be called to reclaim the cache memory.
///
/// # Safety
pub unsafe extern "C" fn h_create_encryption_cache(
    cache_handle: *mut c_int,
    policy_ptr: *const c_char,
    policy_len: c_int,
    mpk_ptr: *const c_char,
    mpk_len: c_int,
) -> i32 {
    //
    // Read input from buffers.
    let policy = ffi_read_bytes!("policy", policy_ptr, policy_len);
    let policy = ffi_unwrap!(Policy::try_from(policy));
    let mpk = ffi_read_bytes!("mpk", mpk_ptr, mpk_len);
    let mpk = ffi_unwrap!(PublicKey::try_from_bytes(mpk), "mpk");

    let cache = EncryptionCache { policy, mpk };
    let id = NEXT_ENCRYPTION_CACHE_ID.fetch_add(1, Ordering::Acquire);
    let mut map = ENCRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on encryption cache failed");
    map.insert(id, cache);
    *cache_handle = id;

    0
}

#[no_mangle]
/// Reclaims the memory of the cache.
///
/// Cf [`h_aes_create_encrypt_cache()`](h_aes_create_encryption_cache).
///
/// # Safety
pub unsafe extern "C" fn h_destroy_encryption_cache(cache_handle: c_int) -> c_int {
    let mut map = ENCRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on encryption cache failed");
    map.remove(&cache_handle);
    0
}

#[no_mangle]
/// Encrypts a header using an encryption cache.
///
/// # Safety
pub unsafe extern "C" fn h_encrypt_header_using_cache(
    symmetric_key_ptr: *mut c_char,
    symmetric_key_len: *mut c_int,
    header_bytes_ptr: *mut c_char,
    header_bytes_len: *mut c_int,
    cache_handle: c_int,
    encryption_policy_ptr: *const c_char,
    header_metadata_ptr: *const c_char,
    header_metadata_len: c_int,
    authentication_data_ptr: *const c_char,
    authentication_data_len: c_int,
) -> c_int {
    let encryption_policy_bytes = ffi_read_string!("encryption policy", encryption_policy_ptr);
    let encryption_policy = ffi_unwrap!(AccessPolicy::from_boolean_expression(
        &encryption_policy_bytes
    ));

    let header_metadata = if header_metadata_ptr.is_null() || header_metadata_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "header metadata",
            header_metadata_ptr,
            header_metadata_len
        ))
    };

    let authentication_data = if authentication_data_ptr.is_null() || authentication_data_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "authentication data",
            authentication_data_ptr,
            authentication_data_len
        ))
    };

    let map = ENCRYPTION_CACHE_MAP
        .read()
        .expect("a read mutex on the encryption cache failed");
    let cache = if let Some(cache) = map.get(&cache_handle) {
        cache
    } else {
        ffi_bail!(format!(
            "Hybrid Cipher: no encryption cache with handle: {cache_handle}"
        ));
    };

    let (symmetric_key, encrypted_header) = ffi_unwrap!(EncryptedHeader::generate(
        &CoverCryptX25519Aes256::default(),
        &cache.policy,
        &cache.mpk,
        &encryption_policy,
        header_metadata,
        authentication_data,
    ));

    ffi_write_bytes!(
        "symmetric key",
        symmetric_key.as_bytes(),
        symmetric_key_ptr,
        symmetric_key_len,
        "encrypted header",
        &ffi_unwrap!(encrypted_header.try_to_bytes()),
        header_bytes_ptr,
        header_bytes_len
    );

    0
}

#[no_mangle]
/// Encrypts a header without using an encryption cache.
/// It is slower but does not require destroying any cache when done.
///
/// The symmetric key and header bytes are returned in the first OUT parameters
/// # Safety
pub unsafe extern "C" fn h_encrypt_header(
    symmetric_key_ptr: *mut c_char,
    symmetric_key_len: *mut c_int,
    header_bytes_ptr: *mut c_char,
    header_bytes_len: *mut c_int,
    policy_ptr: *const c_char,
    policy_len: c_int,
    mpk_ptr: *const c_char,
    mpk_len: c_int,
    encryption_policy_ptr: *const c_char,
    header_metadata_ptr: *const c_char,
    header_metadata_len: c_int,
    authentication_data_ptr: *const c_char,
    authentication_data_len: c_int,
) -> c_int {
    let policy = ffi_read_bytes!("policy", policy_ptr, policy_len);
    let policy = ffi_unwrap!(Policy::try_from(policy));

    let mpk = ffi_read_bytes!("mpk", mpk_ptr, mpk_len);
    let mpk = ffi_unwrap!(PublicKey::try_from_bytes(mpk), "mpk");

    let encryption_policy_bytes = ffi_read_string!("encryption policy", encryption_policy_ptr);
    let encryption_policy = ffi_unwrap!(AccessPolicy::from_boolean_expression(
        &encryption_policy_bytes
    ));

    let header_metadata = if header_metadata_ptr.is_null() || header_metadata_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "header metadata",
            header_metadata_ptr,
            header_metadata_len
        ))
    };

    let authentication_data = if authentication_data_ptr.is_null() || authentication_data_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "authentication data",
            authentication_data_ptr,
            authentication_data_len
        ))
    };

    let (symmetric_key, encrypted_header) = ffi_unwrap!(EncryptedHeader::generate(
        &CoverCryptX25519Aes256::default(),
        &policy,
        &mpk,
        &encryption_policy,
        header_metadata,
        authentication_data
    ));

    ffi_write_bytes!(
        "symmetric key",
        symmetric_key.as_bytes(),
        symmetric_key_ptr,
        symmetric_key_len,
        "encrypted header",
        &ffi_unwrap!(encrypted_header.try_to_bytes()),
        header_bytes_ptr,
        header_bytes_len
    );

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

/// Cache used to store the user secret key on the Rust side.
pub struct DecryptionCache {
    usk: UserSecretKey,
}

#[no_mangle]
/// Creates a cache containing the user secret key. This cache can be reused
/// when decrypting messages which avoids passing this key to Rust in each call.
///
/// Cf [`h_aes_decrypt_header_using_cache()`](h_aes_decrypt_header_using_cache).
///
/// WARNING: [`h_aes_destroy_decryption_cache()`](h_aes_destroy_decryption_cache)
/// should be called to reclaim the cache memory.
///
/// # Safety
pub unsafe extern "C" fn h_create_decryption_cache(
    cache_handle: *mut c_int,
    usk_ptr: *const c_char,
    usk_len: c_int,
) -> i32 {
    let usk_bytes = ffi_read_bytes!("usk", usk_ptr, usk_len);
    let usk = ffi_unwrap!(UserSecretKey::try_from_bytes(usk_bytes), "usk");

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
/// Reclaims decryption cache memory.
///
/// # Safety
pub unsafe extern "C" fn h_destroy_decryption_cache(cache_handle: c_int) -> c_int {
    let mut map = DECRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on decryption cache failed");
    map.remove(&cache_handle);
    0
}

#[no_mangle]
/// Decrypts an encrypted header using a cache. Returns the symmetric key and
/// header metadata if any.
///
/// No header metadata is returned if `header_metadata_ptr` is `NULL`.
///
/// # Safety
pub unsafe extern "C" fn h_decrypt_header_using_cache(
    symmetric_key_ptr: *mut c_char,
    symmetric_key_len: *mut c_int,
    header_metadata_ptr: *mut c_char,
    header_metadata_len: *mut c_int,
    encrypted_header_ptr: *const c_char,
    encrypted_header_len: c_int,
    authentication_data_ptr: *const c_char,
    authentication_data_len: c_int,
    cache_handle: c_int,
) -> c_int {
    let encrypted_header_bytes = ffi_read_bytes!(
        "encrypted header",
        encrypted_header_ptr,
        encrypted_header_len
    );
    let encrypted_header = ffi_unwrap!(EncryptedHeader::try_from_bytes(encrypted_header_bytes));

    let authentication_data = if authentication_data_ptr.is_null() || authentication_data_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "authentication data",
            authentication_data_ptr,
            authentication_data_len
        ))
    };

    let map = DECRYPTION_CACHE_MAP
        .read()
        .expect("a read mutex on the decryption cache failed");
    let cache = if let Some(cache) = map.get(&cache_handle) {
        cache
    } else {
        ffi_bail!(format!(
            "Hybrid Cipher: no decryption cache with handle: {cache_handle}",
        ));
    };

    // Decrypt header
    let header = ffi_unwrap!(encrypted_header.decrypt(
        &CoverCryptX25519Aes256::default(),
        &cache.usk,
        authentication_data
    ));

    if header_metadata_ptr.is_null() {
        *header_metadata_len = 0;
        ffi_write_bytes!(
            "symmetric key",
            header.symmetric_key.as_bytes(),
            symmetric_key_ptr,
            symmetric_key_len
        );
    } else {
        ffi_write_bytes!(
            "symmetric key",
            header.symmetric_key.as_bytes(),
            symmetric_key_ptr,
            symmetric_key_len,
            "header metadata",
            &header.metadata,
            header_metadata_ptr,
            header_metadata_len
        );
    }

    0
}

#[no_mangle]
/// Decrypts an encrypted header, returning the symmetric key and header
/// metadata if any.
///
/// No header metadata is returned if `header_metadata_ptr` is `NULL`.
///
/// # Safety
pub unsafe extern "C" fn h_decrypt_header(
    symmetric_key_ptr: *mut c_char,
    symmetric_key_len: *mut c_int,
    header_metadata_ptr: *mut c_char,
    header_metadata_len: *mut c_int,
    encrypted_header_ptr: *const c_char,
    encrypted_header_len: c_int,
    authentication_data_ptr: *const c_char,
    authentication_data_len: c_int,
    usk_ptr: *const c_char,
    usk_len: c_int,
) -> c_int {
    let usk_bytes = ffi_read_bytes!("usk", usk_ptr, usk_len);
    let usk = ffi_unwrap!(UserSecretKey::try_from_bytes(usk_bytes), "usk");
    let encrypted_header_bytes = ffi_read_bytes!(
        "encrypted header",
        encrypted_header_ptr,
        encrypted_header_len
    );
    let encrypted_header = ffi_unwrap!(
        EncryptedHeader::try_from_bytes(encrypted_header_bytes),
        "encrypted header"
    );

    let authentication_data = if authentication_data_ptr.is_null() || authentication_data_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "authentication data",
            authentication_data_ptr,
            authentication_data_len
        ))
    };

    // Decrypt header
    let decrypted_header = ffi_unwrap!(encrypted_header.decrypt(
        &CoverCryptX25519Aes256::default(),
        &usk,
        authentication_data
    ));

    if header_metadata_ptr.is_null() {
        *header_metadata_len = 0;
        ffi_write_bytes!(
            "symmetric key",
            decrypted_header.symmetric_key.as_bytes(),
            symmetric_key_ptr,
            symmetric_key_len
        );
    } else {
        ffi_write_bytes!(
            "symmetric key",
            decrypted_header.symmetric_key.as_bytes(),
            symmetric_key_ptr,
            symmetric_key_len,
            "header metadata",
            &decrypted_header.metadata,
            header_metadata_ptr,
            header_metadata_len
        );
    }

    0
}

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn h_symmetric_encryption_overhead() -> c_int {
    DEM::ENCRYPTION_OVERHEAD as c_int
}

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn h_dem_encrypt(
    ciphertext_ptr: *mut c_char,
    ciphertext_len: *mut c_int,
    symmetric_key_ptr: *const c_char,
    symmetric_key_len: c_int,
    authentication_data_ptr: *const c_char,
    authentication_data_len: c_int,
    plaintext_ptr: *const c_char,
    plaintext_len: c_int,
) -> c_int {
    let plaintext = ffi_read_bytes!("plaintext", plaintext_ptr, plaintext_len);
    let symmetric_key_bytes =
        ffi_read_bytes!("symmetric key", symmetric_key_ptr, symmetric_key_len);
    let symmetric_key = ffi_unwrap!(<DEM as Dem<{ DEM::KEY_LENGTH }>>::Key::try_from_bytes(
        symmetric_key_bytes
    ));
    let authentication_data = if authentication_data_ptr.is_null() || authentication_data_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "authentication data",
            authentication_data_ptr,
            authentication_data_len
        ))
    };

    let ciphertext = ffi_unwrap!(CoverCryptX25519Aes256::default().encrypt(
        &symmetric_key,
        plaintext,
        authentication_data,
    ));

    ffi_write_bytes!("ciphertext", &ciphertext, ciphertext_ptr, ciphertext_len);

    0
}

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn h_dem_decrypt(
    plaintext_ptr: *mut c_char,
    plaintext_len: *mut c_int,
    symmetric_key_ptr: *const c_char,
    symmetric_key_len: c_int,
    authentication_data_ptr: *const c_char,
    authentication_data_len: c_int,
    ciphertext_ptr: *const c_char,
    ciphertext_len: c_int,
) -> c_int {
    let ciphertext = ffi_read_bytes!("ciphertext", ciphertext_ptr, ciphertext_len);
    let symmetric_key_bytes =
        ffi_read_bytes!("symmetric key", symmetric_key_ptr, symmetric_key_len);
    let symmetric_key = ffi_unwrap!(<DEM as Dem<{ DEM::KEY_LENGTH }>>::Key::try_from_bytes(
        symmetric_key_bytes
    ));
    let authentication_data = if authentication_data_ptr.is_null() || authentication_data_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "authentication data",
            authentication_data_ptr,
            authentication_data_len
        ))
    };

    //
    // Decrypt block
    let plaintext = ffi_unwrap!(CoverCryptX25519Aes256::default().decrypt(
        &symmetric_key,
        ciphertext,
        authentication_data,
    ));

    ffi_write_bytes!("plaintext", &plaintext, plaintext_ptr, plaintext_len);

    0
}

#[no_mangle]
/// Hybrid encrypt some content
///
/// # Safety
pub unsafe extern "C" fn h_hybrid_encrypt(
    ciphertext_ptr: *mut c_char,
    ciphertext_len: *mut c_int,
    policy_ptr: *const c_char,
    policy_len: c_int,
    mpk_ptr: *const c_char,
    mpk_len: c_int,
    encryption_policy_ptr: *const c_char,
    plaintext_ptr: *const c_char,
    plaintext_len: c_int,
    header_metadata_ptr: *const c_char,
    header_metadata_len: c_int,
    authentication_data_ptr: *const c_char,
    authentication_data_len: c_int,
) -> c_int {
    let policy_bytes = ffi_read_bytes!("policy", policy_ptr, policy_len);
    let policy = ffi_unwrap!(Policy::parse_and_convert(policy_bytes));

    let encryption_policy_string = ffi_read_string!("encryption policy", encryption_policy_ptr);
    let encryption_policy = ffi_unwrap!(AccessPolicy::from_boolean_expression(
        &encryption_policy_string
    ));

    let plaintext = ffi_read_bytes!("plaintext", plaintext_ptr, plaintext_len);

    let mpk_bytes = ffi_read_bytes!("mpk", mpk_ptr, mpk_len);
    let mpk = ffi_unwrap!(PublicKey::try_from_bytes(mpk_bytes), "mpk");

    let header_metadata = if header_metadata_ptr.is_null() || header_metadata_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "header metadata",
            header_metadata_ptr,
            header_metadata_len
        ))
    };

    let authentication_data = if authentication_data_ptr.is_null() || authentication_data_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "authentication data",
            authentication_data_ptr,
            authentication_data_len
        ))
    };

    let (symmetric_key, encrypted_header) = ffi_unwrap!(EncryptedHeader::generate(
        &CoverCryptX25519Aes256::default(),
        &policy,
        &mpk,
        &encryption_policy,
        header_metadata,
        authentication_data
    ));

    // encrypt the plaintext
    let ciphertext = ffi_unwrap!(CoverCryptX25519Aes256::default().encrypt(
        &symmetric_key,
        plaintext,
        authentication_data,
    ));

    let mut ser = Serializer::with_capacity(encrypted_header.length() + ciphertext.len());
    ffi_unwrap!(ser.write(&encrypted_header));
    ffi_unwrap!(ser.write_array(&ciphertext));
    let bytes = ser.finalize();

    ffi_write_bytes!("ciphertext", &bytes, ciphertext_ptr, ciphertext_len);

    0
}

#[no_mangle]
/// Hybrid decrypt some content.
///
/// No header metadata is returned if `header_metadata_ptr` is `NULL`.
///
/// # Safety
pub unsafe extern "C" fn h_hybrid_decrypt(
    plaintext_ptr: *mut c_char,
    plaintext_len: *mut c_int,
    header_metadata_ptr: *mut c_char,
    header_metadata_len: *mut c_int,
    ciphertext_ptr: *const c_char,
    ciphertext_len: c_int,
    authentication_data_ptr: *const c_char,
    authentication_data_len: c_int,
    usk_ptr: *const c_char,
    usk_len: c_int,
) -> c_int {
    let usk_bytes = ffi_read_bytes!("usk", usk_ptr, usk_len);
    let usk = ffi_unwrap!(UserSecretKey::try_from_bytes(usk_bytes), "usk");

    let authentication_data = if authentication_data_ptr.is_null() || authentication_data_len == 0 {
        None
    } else {
        Some(ffi_read_bytes!(
            "authentication data",
            authentication_data_ptr,
            authentication_data_len
        ))
    };

    let ciphertext = ffi_read_bytes!("encrypted header", ciphertext_ptr, ciphertext_len);

    let mut de = Deserializer::new(ciphertext);
    // this will read the exact header size
    let encrypted_header = ffi_unwrap!(de.read::<EncryptedHeader>());
    // the rest is the symmetric ciphertext
    let encrypted_content = de.finalize();

    // Decrypt header
    let decrypted_header = ffi_unwrap!(encrypted_header.decrypt(
        &CoverCryptX25519Aes256::default(),
        &usk,
        authentication_data
    ));

    // Decrypt block
    let plaintext = ffi_unwrap!(CoverCryptX25519Aes256::default().decrypt(
        &decrypted_header.symmetric_key,
        &encrypted_content,
        authentication_data,
    ));

    if header_metadata_ptr.is_null() {
        *header_metadata_len = 0;
        ffi_write_bytes!("plaintext", &plaintext, plaintext_ptr, plaintext_len);
    } else {
        ffi_write_bytes!(
            "plaintext",
            &plaintext,
            plaintext_ptr,
            plaintext_len,
            "header metadata",
            &decrypted_header.metadata,
            header_metadata_ptr,
            header_metadata_len
        );
    }

    0
}
