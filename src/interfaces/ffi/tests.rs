use super::hybrid_gpsw_aes::*;
use crate::{
    api::{self, CoverCrypt},
    error::Error,
    interfaces::{ffi::error::get_last_error, statics::EncryptedHeader},
    policy::{AccessPolicy, Attribute, Attributes, Policy, PolicyAxis},
};
use cosmian_crypto_base::{
    asymmetric::ristretto::X25519Crypto,
    hybrid_crypto::Metadata,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, SymmetricCrypto},
    KeyTrait,
};
use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
};

type PublicKey = api::PublicKey<X25519Crypto>;
type UserDecryptionKey = api::PrivateKey<X25519Crypto>;

unsafe fn encrypt_header(
    meta_data: &Metadata,
    policy: &Policy,
    attributes: &Attributes,
    public_key: &PublicKey,
) -> Result<EncryptedHeader<Aes256GcmCrypto>, Error> {
    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr() as *mut c_char;
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut encrypted_header_bytes = vec![0u8; 8128];
    let encrypted_header_ptr = encrypted_header_bytes.as_mut_ptr() as *mut c_char;
    let mut encrypted_header_len = encrypted_header_bytes.len() as c_int;

    let policy_cs = CString::new(serde_json::to_string(policy)?.as_str())
        .map_err(|e| Error::Other(e.to_string()))?;
    let policy_ptr = policy_cs.as_ptr();

    let public_key_bytes = serde_json::to_vec(public_key)?;
    let public_key_ptr = public_key_bytes.as_ptr();
    let public_key_len = public_key_bytes.len() as i32;

    let attributes_json = CString::new(serde_json::to_string(&attributes)?.as_str())
        .map_err(|e| Error::Other(e.to_string()))?;
    let attributes_ptr = attributes_json.as_ptr();

    unwrap_ffi_error(h_aes_encrypt_header(
        symmetric_key_ptr,
        &mut symmetric_key_len,
        encrypted_header_ptr,
        &mut encrypted_header_len,
        policy_ptr,
        public_key_ptr as *const c_char,
        public_key_len,
        attributes_ptr,
        meta_data.uid.as_ptr() as *const c_char,
        meta_data.uid.len() as i32,
        meta_data.additional_data.as_ref().unwrap().as_ptr() as *const c_char,
        meta_data.additional_data.as_ref().unwrap().len() as i32,
    ))?;

    let symmetric_key_ = <Aes256GcmCrypto as SymmetricCrypto>::Key::parse(
        std::slice::from_raw_parts(symmetric_key_ptr as *const u8, symmetric_key_len as usize)
            .to_vec(),
    )
    .map_err(|e| Error::Other(e.to_string()))?;

    let encrypted_header_bytes_ = std::slice::from_raw_parts(
        encrypted_header_ptr as *const u8,
        encrypted_header_len as usize,
    )
    .to_vec();
    Ok(EncryptedHeader {
        symmetric_key: symmetric_key_,
        header_bytes: encrypted_header_bytes_,
    })
}

struct DecryptedHeader {
    symmetric_key: <Aes256GcmCrypto as SymmetricCrypto>::Key,
    meta_data: Metadata,
}

unsafe fn decrypt_header(
    header: &EncryptedHeader<Aes256GcmCrypto>,
    user_decryption_key: &UserDecryptionKey,
) -> Result<DecryptedHeader, Error> {
    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr() as *mut c_char;
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut uid = vec![0u8; 8128];
    let uid_ptr = uid.as_mut_ptr() as *mut c_char;
    let mut uid_len = uid.len() as c_int;

    let mut additional_data = vec![0u8; 8128];
    let additional_data_ptr = additional_data.as_mut_ptr() as *mut c_char;
    let mut additional_data_len = additional_data.len() as c_int;

    let user_decryption_key_bytes = serde_json::to_vec(user_decryption_key)?;
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr() as *const c_char;
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    unwrap_ffi_error(h_aes_decrypt_header(
        symmetric_key_ptr,
        &mut symmetric_key_len,
        uid_ptr,
        &mut uid_len,
        additional_data_ptr,
        &mut additional_data_len,
        header.header_bytes.as_ptr() as *const c_char,
        header.header_bytes.len() as c_int,
        user_decryption_key_ptr,
        user_decryption_key_len,
    ))?;

    let symmetric_key_ = <Aes256GcmCrypto as SymmetricCrypto>::Key::parse(
        std::slice::from_raw_parts(symmetric_key_ptr as *const u8, symmetric_key_len as usize)
            .to_vec(),
    )
    .map_err(|e| Error::Other(e.to_string()))?;

    let uid_bytes_ = std::slice::from_raw_parts(uid_ptr as *const u8, uid_len as usize).to_vec();

    let additional_data_bytes_ = std::slice::from_raw_parts(
        additional_data_ptr as *const u8,
        additional_data_len as usize,
    )
    .to_vec();

    Ok(DecryptedHeader {
        symmetric_key: symmetric_key_,
        meta_data: Metadata {
            uid: uid_bytes_,
            additional_data: Some(additional_data_bytes_),
        },
    })
}

unsafe fn unwrap_ffi_error(val: i32) -> Result<(), Error> {
    if val != 0 {
        let mut message_bytes_key = vec![0u8; 8128];
        let message_bytes_ptr = message_bytes_key.as_mut_ptr() as *mut c_char;
        let mut message_bytes_len = message_bytes_key.len() as c_int;
        get_last_error(message_bytes_ptr, &mut message_bytes_len);
        let cstr = CStr::from_ptr(message_bytes_ptr);
        Err(Error::Other(
            cstr.to_str()
                .map_err(|e| Error::Other(e.to_string()))?
                .to_string(),
        ))
    } else {
        Ok(())
    }
}

#[test]
fn test_ffi_hybrid_header() -> Result<(), Error> {
    unsafe {
        //
        // Policy settings
        //
        let sec_level = PolicyAxis::new(
            "Security Level",
            &["Protected", "Confidential", "Top Secret"],
            true,
        );
        let department = PolicyAxis::new("Department", &["R&D", "HR", "MKG", "FIN"], false);
        let mut policy = Policy::new(100);
        policy.add_axis(&sec_level)?;
        policy.add_axis(&department)?;
        policy.rotate(&Attribute::new("Department", "FIN"))?;
        let attributes = Attributes::from(vec![
            Attribute::new("Security Level", "Confidential"),
            Attribute::new("Department", "HR"),
            Attribute::new("Department", "FIN"),
        ]);
        let access_policy = AccessPolicy::from_attribute_list(&attributes)?;

        //
        // CoverCrypt setup
        //
        let cc = CoverCrypt::<X25519Crypto>::default();
        let (msk, mpk) = cc.generate_master_keys(&policy)?;
        let sk_u = cc.generate_user_private_key(&msk, &access_policy, &policy)?;
        for autorisation in sk_u.keys() {
            println!("{autorisation}");
        }

        //
        // Encrypt / decrypt
        //
        let meta_data = Metadata {
            uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            additional_data: Some(vec![10, 11, 12, 13, 14]),
        };

        let encrypted_header = encrypt_header(&meta_data, &policy, &attributes, &mpk)?;
        let decrypted_header = decrypt_header(&encrypted_header, &sk_u)?;

        assert_eq!(
            encrypted_header.symmetric_key,
            decrypted_header.symmetric_key
        );
        assert_eq!(&meta_data.uid, &decrypted_header.meta_data.uid);
        assert_eq!(
            &meta_data.additional_data,
            &decrypted_header.meta_data.additional_data
        );
    }
    Ok(())
}

unsafe fn encrypt_header_using_cache(
    public_key: &PublicKey,
    policy: &Policy,
    meta_data: &Metadata,
) -> Result<EncryptedHeader<Aes256GcmCrypto>, Error> {
    let policy_cs = CString::new(serde_json::to_string(&policy)?.as_str())
        .map_err(|e| Error::Other(e.to_string()))?;
    let policy_ptr = policy_cs.as_ptr();

    let public_key_bytes = serde_json::to_vec(public_key)?;
    let public_key_ptr = public_key_bytes.as_ptr() as *const c_char;
    let public_key_len = public_key_bytes.len() as i32;

    let mut cache_handle: i32 = 0;

    unwrap_ffi_error(h_aes_create_encryption_cache(
        &mut cache_handle,
        policy_ptr,
        public_key_ptr,
        public_key_len,
    ))?;

    let attributes = Attributes::from(vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ]);

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr() as *mut c_char;
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut encrypted_header_bytes = vec![0u8; 8128];
    let encrypted_header_ptr = encrypted_header_bytes.as_mut_ptr() as *mut c_char;
    let mut encrypted_header_len = encrypted_header_bytes.len() as c_int;

    let attributes_json = CString::new(serde_json::to_string(&attributes)?.as_str())
        .map_err(|e| Error::Other(e.to_string()))?;
    let attributes_ptr = attributes_json.as_ptr();

    unwrap_ffi_error(h_aes_encrypt_header_using_cache(
        symmetric_key_ptr,
        &mut symmetric_key_len,
        encrypted_header_ptr,
        &mut encrypted_header_len,
        cache_handle,
        attributes_ptr,
        meta_data.uid.as_ptr() as *const c_char,
        meta_data.uid.len() as i32,
        meta_data.additional_data.as_ref().unwrap().as_ptr() as *const c_char,
        meta_data.additional_data.as_ref().unwrap().len() as i32,
    ))?;

    let symmetric_key_ = <Aes256GcmCrypto as SymmetricCrypto>::Key::parse(
        std::slice::from_raw_parts(symmetric_key_ptr as *const u8, symmetric_key_len as usize)
            .to_vec(),
    )
    .map_err(|e| Error::Other(e.to_string()))?;

    let encrypted_header_bytes_ = std::slice::from_raw_parts(
        encrypted_header_ptr as *const u8,
        encrypted_header_len as usize,
    )
    .to_vec();

    unwrap_ffi_error(h_aes_destroy_encryption_cache(cache_handle))?;

    Ok(EncryptedHeader {
        symmetric_key: symmetric_key_,
        header_bytes: encrypted_header_bytes_,
    })
}

unsafe fn decrypt_header_using_cache(
    user_decryption_key: &UserDecryptionKey,
    header: &EncryptedHeader<Aes256GcmCrypto>,
) -> Result<DecryptedHeader, Error> {
    let user_decryption_key_bytes =
        serde_json::to_vec(user_decryption_key).map_err(|e| Error::Other(e.to_string()))?;
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr() as *const c_char;
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    let mut cache_handle: i32 = 0;

    unwrap_ffi_error(h_aes_create_decryption_cache(
        &mut cache_handle,
        user_decryption_key_ptr,
        user_decryption_key_len,
    ))?;

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr() as *mut c_char;
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut uid = vec![0u8; 8128];
    let uid_ptr = uid.as_mut_ptr() as *mut c_char;
    let mut uid_len = uid.len() as c_int;

    let mut additional_data = vec![0u8; 8128];
    let additional_data_ptr = additional_data.as_mut_ptr() as *mut c_char;
    let mut additional_data_len = additional_data.len() as c_int;

    unwrap_ffi_error(h_aes_decrypt_header_using_cache(
        symmetric_key_ptr,
        &mut symmetric_key_len,
        uid_ptr,
        &mut uid_len,
        additional_data_ptr,
        &mut additional_data_len,
        header.header_bytes.as_ptr() as *const c_char,
        header.header_bytes.len() as c_int,
        cache_handle,
    ))?;

    let symmetric_key_ = <Aes256GcmCrypto as SymmetricCrypto>::Key::parse(
        std::slice::from_raw_parts(symmetric_key_ptr as *const u8, symmetric_key_len as usize)
            .to_vec(),
    )
    .map_err(|e| Error::Other(e.to_string()))?;

    let uid_bytes_ = std::slice::from_raw_parts(uid_ptr as *const u8, uid_len as usize).to_vec();

    let additional_data_bytes_ = std::slice::from_raw_parts(
        additional_data_ptr as *const u8,
        additional_data_len as usize,
    )
    .to_vec();

    unwrap_ffi_error(h_aes_destroy_decryption_cache(cache_handle))?;

    Ok(DecryptedHeader {
        symmetric_key: symmetric_key_,
        meta_data: Metadata {
            uid: uid_bytes_,
            additional_data: Some(additional_data_bytes_),
        },
    })
}

#[test]
fn test_ffi_hybrid_header_using_cache() -> Result<(), Error> {
    unsafe {
        //
        // Policy settings
        //
        let sec_level = PolicyAxis::new(
            "Security Level",
            &["Protected", "Confidential", "Top Secret"],
            true,
        );
        let department = PolicyAxis::new("Department", &["R&D", "HR", "MKG", "FIN"], false);
        let mut policy = Policy::new(100);
        policy.add_axis(&sec_level)?;
        policy.add_axis(&department)?;
        policy.rotate(&Attribute::new("Department", "FIN"))?;
        let attributes = Attributes::from(vec![
            Attribute::new("Security Level", "Confidential"),
            Attribute::new("Department", "HR"),
            Attribute::new("Department", "FIN"),
        ]);
        let access_policy = AccessPolicy::from_attribute_list(&attributes)?;

        //
        // CoverCrypt setup
        //
        let cc = CoverCrypt::<X25519Crypto>::default();
        let (msk, mpk) = cc.generate_master_keys(&policy)?;
        let sk_u = cc.generate_user_private_key(&msk, &access_policy, &policy)?;
        for autorisation in sk_u.keys() {
            println!("{autorisation}");
        }

        //
        // Encrypt / decrypt
        //
        let meta_data = Metadata {
            uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            additional_data: Some(vec![10, 11, 12, 13, 14]),
        };
        let encrypted_header = encrypt_header_using_cache(&mpk, &policy, &meta_data)?;
        let decrypted_header = decrypt_header_using_cache(&sk_u, &encrypted_header)?;

        assert_eq!(
            encrypted_header.symmetric_key,
            decrypted_header.symmetric_key
        );
        assert_eq!(&meta_data.uid, &decrypted_header.meta_data.uid);
        assert_eq!(
            &meta_data.additional_data,
            &decrypted_header.meta_data.additional_data
        );
    }
    Ok(())
}
