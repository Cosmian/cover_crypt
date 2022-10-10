use super::{
    generate_cc_keys::{
        h_generate_master_keys, h_generate_user_private_key, h_refresh_user_private_key,
        h_update_master_keys,
    },
    hybrid_cc_aes::*,
};
use crate::{
    api::CoverCrypt,
    cover_crypt_core::Partition,
    error::Error,
    interfaces::{
        ffi::{error::get_last_error, generate_cc_keys::h_rotate_attributes},
        statics::EncryptedHeader,
    },
    MasterPrivateKey, PublicKey, UserPrivateKey,
};
use abe_policy::{AccessPolicy, Attribute, Policy, PolicyAxis};
use cosmian_crypto_core::{
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Metadata, SymmetricCrypto},
    KeyTrait,
};
use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
};

unsafe fn encrypt_header(
    meta_data: &Metadata,
    policy: &Policy,
    attributes: &[Attribute],
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

    let public_key_bytes = public_key.try_to_bytes()?;
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

    let symmetric_key_ = <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from_bytes(
        std::slice::from_raw_parts(symmetric_key_ptr as *const u8, symmetric_key_len as usize),
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
    user_decryption_key: &UserPrivateKey,
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

    let user_decryption_key_bytes = user_decryption_key.try_to_bytes()?;
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

    let symmetric_key_ = <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from_bytes(
        std::slice::from_raw_parts(symmetric_key_ptr as *const u8, symmetric_key_len as usize),
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

pub fn policy() -> Result<Policy, Error> {
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
    Ok(policy)
}

#[test]
fn test_ffi_hybrid_header() -> Result<(), Error> {
    unsafe {
        //
        // Policy settings
        //
        let policy = policy()?;
        let attributes = vec![
            Attribute::new("Security Level", "Confidential"),
            Attribute::new("Department", "HR"),
            Attribute::new("Department", "FIN"),
        ];

        //
        // CoverCrypt setup
        //
        let cc = CoverCrypt::default();
        let (msk, mpk) = cc.generate_master_keys(&policy)?;
        let access_policy = AccessPolicy::new("Department", "FIN")
            & AccessPolicy::new("Security Level", "Top Secret");
        let sk_u = cc.generate_user_private_key(&msk, &access_policy, &policy)?;

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

    let public_key_bytes = public_key.try_to_bytes()?;
    let public_key_ptr = public_key_bytes.as_ptr() as *const c_char;
    let public_key_len = public_key_bytes.len() as i32;

    let mut cache_handle: i32 = 0;

    unwrap_ffi_error(h_aes_create_encryption_cache(
        &mut cache_handle,
        policy_ptr,
        public_key_ptr,
        public_key_len,
    ))?;

    let attributes = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ];

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

    let symmetric_key_ = <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from_bytes(
        std::slice::from_raw_parts(symmetric_key_ptr as *const u8, symmetric_key_len as usize),
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
    user_decryption_key: &UserPrivateKey,
    header: &EncryptedHeader<Aes256GcmCrypto>,
) -> Result<DecryptedHeader, Error> {
    let user_decryption_key_bytes = user_decryption_key.try_to_bytes()?;
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

    let symmetric_key_ = <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from_bytes(
        std::slice::from_raw_parts(symmetric_key_ptr as *const u8, symmetric_key_len as usize),
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

        //
        // CoverCrypt setup
        //
        let cc = CoverCrypt::default();
        let (msk, mpk) = cc.generate_master_keys(&policy)?;
        let access_policy = AccessPolicy::new("Department", "FIN")
            & AccessPolicy::new("Security Level", "Top Secret");
        let sk_u = cc.generate_user_private_key(&msk, &access_policy, &policy)?;

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

unsafe fn generate_master_keys(policy: &Policy) -> Result<(MasterPrivateKey, PublicKey), Error> {
    let policy_cs = CString::new(serde_json::to_string(&policy)?.as_str())
        .map_err(|e| Error::Other(e.to_string()))?;
    let policy_ptr = policy_cs.as_ptr();

    let mut master_keys_bytes = vec![0u8; 8192];
    let master_keys_ptr = master_keys_bytes.as_mut_ptr() as *mut c_char;
    let mut master_keys_len = master_keys_bytes.len() as c_int;

    unwrap_ffi_error(h_generate_master_keys(
        master_keys_ptr,
        &mut master_keys_len,
        policy_ptr,
    ))?;

    let master_keys_bytes =
        std::slice::from_raw_parts(master_keys_ptr as *const u8, master_keys_len as usize).to_vec();

    let master_private_key_size = u32::from_be_bytes(master_keys_bytes[0..4].try_into()?);
    let master_private_key_bytes = &master_keys_bytes[4..4 + master_private_key_size as usize];
    let public_key_bytes = &master_keys_bytes[4 + master_private_key_size as usize..];

    let master_private_key = MasterPrivateKey::try_from_bytes(master_private_key_bytes)?;
    let public_key = PublicKey::try_from_bytes(public_key_bytes)?;

    Ok((master_private_key, public_key))
}

unsafe fn generate_user_private_key(
    master_private_key: &MasterPrivateKey,
    access_policy: &AccessPolicy,
    policy: &Policy,
) -> Result<UserPrivateKey, Error> {
    //
    // Prepare private key
    let master_private_key_bytes = master_private_key.try_to_bytes()?;
    let master_private_key_ptr = master_private_key_bytes.as_ptr() as *const c_char;
    let master_private_key_len = master_private_key_bytes.len() as i32;

    //
    // Get pointer from access policy
    let access_policy_cs = CString::new(serde_json::to_string(&access_policy)?.as_str())
        .map_err(|e| Error::Other(e.to_string()))?;
    let access_policy_ptr = access_policy_cs.as_ptr();
    //
    // Get pointer from policy
    let policy_cs = CString::new(serde_json::to_string(&policy)?.as_str())
        .map_err(|e| Error::Other(e.to_string()))?;
    let policy_ptr = policy_cs.as_ptr();

    // Prepare OUT buffer
    let mut user_private_key_bytes = vec![0u8; 8192];
    let user_private_key_ptr = user_private_key_bytes.as_mut_ptr() as *mut c_char;
    let mut user_private_key_len = user_private_key_bytes.len() as c_int;

    unwrap_ffi_error(h_generate_user_private_key(
        user_private_key_ptr,
        &mut user_private_key_len,
        master_private_key_ptr,
        master_private_key_len,
        access_policy_ptr,
        policy_ptr,
    ))?;

    let user_key_bytes = std::slice::from_raw_parts(
        user_private_key_ptr as *const u8,
        user_private_key_len as usize,
    )
    .to_vec();

    // Check deserialization of private key
    let user_key = UserPrivateKey::try_from_bytes(&user_key_bytes)?;

    Ok(user_key)
}

#[test]
fn test_ffi_keygen() -> Result<(), Error> {
    //
    // Policy settings
    let policy = policy()?;

    //
    // Generate master keys
    let master_keys = unsafe { generate_master_keys(&policy)? };

    //
    // Set an access policy
    let access_policy =
        AccessPolicy::from_boolean_expression("Department::FIN && Security Level::Top Secret")?;

    //
    // Generate user private key
    let _user_private_key =
        unsafe { generate_user_private_key(&master_keys.0, &access_policy, &policy)? };

    Ok(())
}

unsafe fn rotate_policy(policy: &Policy, attributes: &[Attribute]) -> Result<Policy, Error> {
    let policy_cs = CString::new(serde_json::to_string(&policy)?.as_str())
        .map_err(|e| Error::Other(e.to_string()))?;
    let policy_ptr = policy_cs.as_ptr();

    let attributes_json = CString::new(serde_json::to_string(attributes)?.as_str())
        .map_err(|e| Error::Other(e.to_string()))?;
    let attributes_ptr = attributes_json.as_ptr();

    // prepare update policy pointer
    let mut updated_policy_bytes = vec![0u8; 64 * 1024];
    let updated_policy_ptr = updated_policy_bytes.as_mut_ptr() as *mut c_char;
    let mut updated_policy_len = updated_policy_bytes.len() as c_int;

    unwrap_ffi_error(h_rotate_attributes(
        updated_policy_ptr,
        &mut updated_policy_len,
        attributes_ptr,
        policy_ptr,
    ))?;

    let updated_policy_bytes =
        std::slice::from_raw_parts(updated_policy_ptr as *const u8, updated_policy_len as usize)
            .to_vec();
    let updated_policy: Policy = serde_json::from_slice(&updated_policy_bytes)?;

    Ok(updated_policy)
}

unsafe fn update_master_keys(
    policy: &Policy,
    master_private_key: &MasterPrivateKey,
    master_public_key: &PublicKey,
) -> Result<(MasterPrivateKey, PublicKey), Error> {
    let policy_cs = CString::new(serde_json::to_string(&policy)?.as_str())
        .map_err(|e| Error::Other(e.to_string()))?;
    let policy_ptr = policy_cs.as_ptr();

    let master_private_key_bytes = master_private_key.try_to_bytes()?;
    let master_private_key_ptr = master_private_key_bytes.as_ptr() as *const c_char;
    let master_private_key_len = master_private_key_bytes.len() as i32;

    let master_public_key_bytes = master_public_key.try_to_bytes()?;
    let master_public_key_ptr = master_public_key_bytes.as_ptr() as *const c_char;
    let master_public_key_len = master_public_key_bytes.len() as i32;

    // prepare updated master private key pointer
    let mut updated_master_private_key_bytes = vec![0u8; 64 * 1024];
    let updated_master_private_key_ptr =
        updated_master_private_key_bytes.as_mut_ptr() as *mut c_char;
    let mut updated_master_private_key_len = updated_master_private_key_bytes.len() as c_int;

    // prepare updated master public key pointer
    let mut updated_master_public_key_bytes = vec![0u8; 64 * 1024];
    let updated_master_public_key_ptr = updated_master_public_key_bytes.as_mut_ptr() as *mut c_char;
    let mut updated_master_public_key_len = updated_master_public_key_bytes.len() as c_int;

    unwrap_ffi_error(h_update_master_keys(
        updated_master_private_key_ptr,
        &mut updated_master_private_key_len,
        updated_master_public_key_ptr,
        &mut updated_master_public_key_len,
        master_private_key_ptr,
        master_private_key_len,
        master_public_key_ptr,
        master_public_key_len,
        policy_ptr,
    ))?;

    let updated_master_private_key_bytes = std::slice::from_raw_parts(
        updated_master_private_key_ptr as *const u8,
        updated_master_private_key_len as usize,
    )
    .to_vec();
    let updated_master_private_key =
        MasterPrivateKey::try_from_bytes(&updated_master_private_key_bytes)?;

    let updated_master_public_key_bytes = std::slice::from_raw_parts(
        updated_master_public_key_ptr as *const u8,
        updated_master_public_key_len as usize,
    )
    .to_vec();
    let update_master_public_key = PublicKey::try_from_bytes(&updated_master_public_key_bytes)?;

    Ok((updated_master_private_key, update_master_public_key))
}

unsafe fn refresh_user_private_key(
    user_private_key: &UserPrivateKey,
    access_policy: &AccessPolicy,
    master_private_key: &MasterPrivateKey,
    policy: &Policy,
    preserve_old_partitions_access: bool,
) -> Result<UserPrivateKey, Error> {
    let policy_cs = CString::new(serde_json::to_string(&policy)?.as_str())
        .map_err(|e| Error::Other(e.to_string()))?;
    let policy_ptr = policy_cs.as_ptr();

    let master_private_key_bytes = master_private_key.try_to_bytes()?;
    let master_private_key_ptr = master_private_key_bytes.as_ptr() as *const c_char;
    let master_private_key_len = master_private_key_bytes.len() as i32;

    let user_private_key_bytes = user_private_key.try_to_bytes()?;
    let user_private_key_ptr = user_private_key_bytes.as_ptr() as *const c_char;
    let user_private_key_len = user_private_key_bytes.len() as i32;

    // Get pointer from access policy
    let access_policy_cs = CString::new(serde_json::to_string(&access_policy)?.as_str())
        .map_err(|e| Error::Other(e.to_string()))?;
    let access_policy_ptr = access_policy_cs.as_ptr();

    let preserve_old_partitions_access_c: c_int = i32::from(preserve_old_partitions_access);

    // prepare updated user private key pointer
    let mut updated_user_private_key_bytes = vec![0u8; 64 * 1024];
    let updated_user_private_key_ptr = updated_user_private_key_bytes.as_mut_ptr() as *mut c_char;
    let mut updated_user_private_key_len = updated_user_private_key_bytes.len() as c_int;

    unwrap_ffi_error(h_refresh_user_private_key(
        updated_user_private_key_ptr,
        &mut updated_user_private_key_len,
        master_private_key_ptr,
        master_private_key_len,
        user_private_key_ptr,
        user_private_key_len,
        access_policy_ptr,
        policy_ptr,
        preserve_old_partitions_access_c,
    ))?;

    let updated_user_private_key_bytes = std::slice::from_raw_parts(
        updated_user_private_key_ptr as *const u8,
        updated_user_private_key_len as usize,
    )
    .to_vec();
    let updated_user_private_key = UserPrivateKey::try_from_bytes(&updated_user_private_key_bytes)?;

    Ok(updated_user_private_key)
}

#[test]
fn test_ffi_rotate_attribute() -> Result<(), Error> {
    //
    // CoverCrypt setup
    //
    let policy = policy()?;
    let cc = CoverCrypt::default();
    let (msk, mpk) = cc.generate_master_keys(&policy)?;
    let original_msk_partitions: Vec<Partition> = msk.x.clone().into_keys().collect();
    let original_mpk_partitions: Vec<Partition> = mpk.H.clone().into_keys().collect();

    let access_policy = AccessPolicy::new("Department", "MKG")
        & AccessPolicy::new("Security Level", "Confidential");
    let usk = cc.generate_user_private_key(&msk, &access_policy, &policy)?;
    let original_user_partitions: Vec<Partition> = usk.x.clone().into_keys().collect();

    unsafe {
        //rotate the policy
        let updated_policy = rotate_policy(&policy, &[Attribute::new("Department", "MKG")])?;
        // update the master keys
        let (updated_msk, updated_mpk) = update_master_keys(&updated_policy, &msk, &mpk)?;
        // check the msk updated partitions
        let updated_msk_partitions: Vec<Partition> = updated_msk.x.clone().into_keys().collect();
        assert_eq!(
            updated_msk_partitions.len(),
            original_msk_partitions.len() + 3
        );
        for original_partition in &original_msk_partitions {
            assert!(updated_msk_partitions.contains(original_partition));
        }
        // check the mpk updated partitions
        let updated_mpk_partitions: Vec<Partition> = updated_mpk.H.into_keys().collect();
        assert_eq!(
            updated_mpk_partitions.len(),
            original_mpk_partitions.len() + 3
        );
        for original_partition in &original_mpk_partitions {
            assert!(updated_mpk_partitions.contains(original_partition));
        }
        // update the user key, preserving the accesses to the rotated partitions
        let updated_usk =
            refresh_user_private_key(&usk, &access_policy, &updated_msk, &updated_policy, true)?;
        let new_user_partitions: Vec<Partition> = updated_usk.x.clone().into_keys().collect();
        // 2 partitions accessed by the user were rotated (MKG Confidential and MKG Protected)
        assert_eq!(
            new_user_partitions.len(),
            original_user_partitions.len() + 2
        );
        for original_partition in &original_user_partitions {
            assert!(new_user_partitions.contains(original_partition));
        }
        // update the user key, but do NOT preserve the accesses to the rotated partitions
        let updated_usk =
            refresh_user_private_key(&usk, &access_policy, &updated_msk, &updated_policy, false)?;
        let new_user_partitions: Vec<Partition> = updated_usk.x.clone().into_keys().collect();
        // 2 partitions accessed by the user were rotated (MKG Confidential and MKG Protected)
        assert_eq!(new_user_partitions.len(), original_user_partitions.len());
        for original_partition in &original_user_partitions {
            assert!(!new_user_partitions.contains(original_partition));
        }
    }
    Ok(())
}
