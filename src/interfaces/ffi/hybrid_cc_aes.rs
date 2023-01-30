#![allow(dead_code)]

use std::os::raw::{c_char, c_int};

use abe_policy::{AccessPolicy, Policy};
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    symmetric_crypto::{Dem, SymKey},
    KeyTrait,
};
use cosmian_ffi::{ffi_read_bytes, ffi_read_string, ffi_unwrap, ffi_write_bytes};

use crate::{
    statics::{CoverCryptX25519Aes256, EncryptedHeader, PublicKey, UserSecretKey, DEM},
    CoverCrypt,
};

// -------------------------------
//         Encryption
// -------------------------------

#[no_mangle]
/// Encrypts a header.
///
/// The symmetric key and header bytes are returned in the first OUT parameters
///
/// # Safety
pub unsafe extern "C" fn h_aes_encrypt_header(
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
        symmetric_key_len
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

#[no_mangle]
/// Decrypts an encrypted header, returning the symmetric key and header
/// metadata if any.
///
/// No header metadata is returned if `header_metadata_ptr` is `NULL`.
///
/// # Safety
pub unsafe extern "C" fn h_aes_decrypt_header(
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
        // Only return the symmetric Key
        ffi_write_bytes!(
            "symmetric key",
            decrypted_header.symmetric_key.as_bytes(),
            symmetric_key_ptr,
            symmetric_key_len
        );
    } else {
        // Return both the symmetric Key and the metadata
        ffi_write_bytes!(
            "symmetric key",
            decrypted_header.symmetric_key.as_bytes(),
            symmetric_key_ptr,
            symmetric_key_len
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
pub const unsafe extern "C" fn h_aes_symmetric_encryption_overhead() -> c_int {
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
pub unsafe extern "C" fn h_aes_decrypt_block(
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
pub unsafe extern "C" fn h_aes_encrypt(
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
/// Hybrid decrypt some content
///
/// No header metadata is returned if `header_metadata_ptr` is `NULL`.
///
/// # Safety
pub unsafe extern "C" fn h_aes_decrypt(
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
