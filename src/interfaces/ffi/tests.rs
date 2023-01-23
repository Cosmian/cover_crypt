use crate::{
    core::partitions::Partition,
    interfaces::ffi::{
        generate_cc_keys::{
            h_generate_master_keys, h_generate_user_secret_key, h_refresh_user_secret_key,
            h_update_master_keys,
        },
        hybrid_cc_aes::{
            h_aes_create_decryption_cache, h_aes_create_encryption_cache, h_aes_decrypt,
            h_aes_decrypt_header, h_aes_decrypt_header_using_cache, h_aes_destroy_decryption_cache,
            h_aes_destroy_encryption_cache, h_aes_encrypt, h_aes_encrypt_header,
            h_aes_encrypt_header_using_cache,
        },
    },
    statics::{
        tests::policy, CleartextHeader, CoverCryptX25519Aes256, EncryptedHeader, MasterSecretKey,
        PublicKey, UserSecretKey, DEM,
    },
    CoverCrypt, Error,
};
use abe_policy::{
    interfaces::ffi::{error::get_last_error, policy::h_rotate_attribute},
    AccessPolicy, Attribute, Policy,
};
use cosmian_crypto_core::{bytes_ser_de::Serializable, symmetric_crypto::Dem, KeyTrait};
use std::{
    ffi::{CStr, CString},
    os::raw::c_int,
};

unsafe fn encrypt_header(
    policy: &Policy,
    encryption_policy: &str,
    public_key: &PublicKey,
    header_metadata: &[u8],
    authentication_data: &[u8],
) -> Result<(<DEM as Dem<{ DEM::KEY_LENGTH }>>::Key, EncryptedHeader), Error> {
    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut encrypted_header_bytes = vec![0u8; 8128];
    let encrypted_header_ptr = encrypted_header_bytes.as_mut_ptr().cast();
    let mut encrypted_header_len = encrypted_header_bytes.len() as c_int;

    let policy_bytes = serde_json::to_vec(&policy)?;
    let policy_ptr = policy_bytes.as_ptr().cast();
    let policy_len = policy_bytes.len() as c_int;

    let public_key_bytes = public_key.try_to_bytes()?;
    let public_key_ptr = public_key_bytes.as_ptr();
    let public_key_len = public_key_bytes.len() as i32;

    let encryption_policy_cs =
        CString::new(encryption_policy).map_err(|e| Error::Other(e.to_string()))?;
    let encryption_policy_ptr = encryption_policy_cs.as_ptr();

    unwrap_ffi_error(h_aes_encrypt_header(
        symmetric_key_ptr,
        &mut symmetric_key_len,
        encrypted_header_ptr,
        &mut encrypted_header_len,
        policy_ptr,
        policy_len,
        public_key_ptr.cast(),
        public_key_len,
        encryption_policy_ptr,
        header_metadata.as_ptr().cast(),
        header_metadata.len() as i32,
        authentication_data.as_ptr().cast(),
        authentication_data.len() as i32,
    ))?;

    let symmetric_key_ = <DEM as Dem<{ DEM::KEY_LENGTH }>>::Key::try_from_bytes(
        std::slice::from_raw_parts(symmetric_key_ptr.cast(), symmetric_key_len as usize),
    )
    .map_err(|e| Error::Other(e.to_string()))?;

    let encrypted_header_bytes_ =
        std::slice::from_raw_parts(encrypted_header_ptr.cast(), encrypted_header_len as usize)
            .to_vec();
    Ok((
        symmetric_key_,
        EncryptedHeader::try_from_bytes(&encrypted_header_bytes_)?,
    ))
}

unsafe fn decrypt_header(
    header: &EncryptedHeader,
    user_decryption_key: &UserSecretKey,
    authentication_data: &[u8],
) -> Result<CleartextHeader, Error> {
    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let authentication_data_ptr = authentication_data.as_ptr().cast();
    let authentication_data_len = authentication_data.len() as c_int;

    let mut header_metadata = vec![0u8; 8128];
    let header_metadata_ptr = header_metadata.as_mut_ptr().cast();
    let mut header_metadata_len = header_metadata.len() as c_int;

    let user_decryption_key_bytes = user_decryption_key.try_to_bytes()?;
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr().cast();
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    let header_bytes = header.try_to_bytes()?;

    unwrap_ffi_error(h_aes_decrypt_header(
        symmetric_key_ptr,
        &mut symmetric_key_len,
        header_metadata_ptr,
        &mut header_metadata_len,
        header_bytes.as_ptr().cast(),
        header_bytes.len() as c_int,
        authentication_data_ptr,
        authentication_data_len,
        user_decryption_key_ptr,
        user_decryption_key_len,
    ))?;

    let symmetric_key = <DEM as Dem<{ DEM::KEY_LENGTH }>>::Key::try_from_bytes(
        std::slice::from_raw_parts(symmetric_key_ptr.cast(), symmetric_key_len as usize),
    )
    .map_err(|e| Error::Other(e.to_string()))?;

    let header_metadata =
        std::slice::from_raw_parts(header_metadata_ptr.cast(), header_metadata_len as usize)
            .to_vec();

    Ok(CleartextHeader {
        symmetric_key,
        metadata: header_metadata,
    })
}

unsafe fn unwrap_ffi_error(val: i32) -> Result<(), Error> {
    if val != 0 {
        let mut message_bytes_key = vec![0u8; 8128];
        let message_bytes_ptr = message_bytes_key.as_mut_ptr().cast();
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
fn test_ffi_simple() -> Result<(), Error> {
    unsafe {
        //
        // Policy settings
        //
        let policy = policy()?;
        let encryption_policy =
            "(Department::HR || Department::FIN) && Security Level::Confidential";

        //
        // CoverCrypt setup
        //
        let cover_crypt = CoverCryptX25519Aes256::default();
        let (msk, mpk) = cover_crypt.generate_master_keys(&policy)?;
        let user_access_policy =
            AccessPolicy::from_boolean_expression("Department::FIN && Security Level::Top Secret")?;
        let usk = cover_crypt.generate_user_secret_key(&msk, &user_access_policy, &policy)?;

        //
        // Encrypt / decrypt
        //
        let header_metadata = vec![];
        let authentication_data = vec![];

        let (sym_key, encrypted_header) = encrypt_header(
            &policy,
            encryption_policy,
            &mpk,
            &header_metadata,
            &authentication_data,
        )?;

        let decrypted_header = decrypt_header(&encrypted_header, &usk, &authentication_data)?;

        assert_eq!(sym_key, decrypted_header.symmetric_key);
        assert_eq!(&header_metadata, &decrypted_header.metadata);
    }
    Ok(())
}

#[test]
fn test_ffi_hybrid_header() -> Result<(), Error> {
    unsafe {
        //
        // Policy settings
        //
        let policy = policy()?;
        let encryption_policy =
            "(Department::HR || Department::FIN) && Security Level::Confidential";

        //
        // CoverCrypt setup
        //
        let cover_crypt = CoverCryptX25519Aes256::default();
        let (msk, mpk) = cover_crypt.generate_master_keys(&policy)?;
        let user_access_policy =
            AccessPolicy::from_boolean_expression("Department::FIN && Security Level::Top Secret")?;
        let usk = cover_crypt.generate_user_secret_key(&msk, &user_access_policy, &policy)?;

        //
        // Encrypt / decrypt
        //
        let header_metadata = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let authentication_data = vec![10, 11, 12, 13, 14];

        let (sym_key, encrypted_header) = encrypt_header(
            &policy,
            encryption_policy,
            &mpk,
            &header_metadata,
            &authentication_data,
        )?;

        let decrypted_header = decrypt_header(&encrypted_header, &usk, &authentication_data)?;

        assert_eq!(sym_key, decrypted_header.symmetric_key);
        assert_eq!(&header_metadata, &decrypted_header.metadata);
    }
    Ok(())
}

unsafe fn encrypt_header_using_cache(
    public_key: &PublicKey,
    policy: &Policy,
    header_metadata: &[u8],
    authentication_data: &[u8],
) -> Result<(<DEM as Dem<{ DEM::KEY_LENGTH }>>::Key, EncryptedHeader), Error> {
    let policy_bytes = serde_json::to_vec(&policy)?;
    let policy_ptr = policy_bytes.as_ptr().cast();
    let policy_len = policy_bytes.len() as c_int;

    let public_key_bytes = public_key.try_to_bytes()?;
    let public_key_ptr = public_key_bytes.as_ptr().cast();
    let public_key_len = public_key_bytes.len() as i32;

    let mut cache_handle: i32 = 0;

    unwrap_ffi_error(h_aes_create_encryption_cache(
        &mut cache_handle,
        policy_ptr,
        policy_len,
        public_key_ptr,
        public_key_len,
    ))?;

    let encryption_policy = "Department::FIN && Security Level::Confidential";

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut encrypted_header_bytes = vec![0u8; 8128];
    let encrypted_header_ptr = encrypted_header_bytes.as_mut_ptr().cast();
    let mut encrypted_header_len = encrypted_header_bytes.len() as c_int;

    let encryption_policy_cs =
        CString::new(encryption_policy).map_err(|e| Error::Other(e.to_string()))?;

    unwrap_ffi_error(h_aes_encrypt_header_using_cache(
        symmetric_key_ptr,
        &mut symmetric_key_len,
        encrypted_header_ptr,
        &mut encrypted_header_len,
        cache_handle,
        encryption_policy_cs.as_ptr(),
        header_metadata.as_ptr().cast(),
        header_metadata.len() as i32,
        authentication_data.as_ptr().cast(),
        authentication_data.len() as i32,
    ))?;

    let symmetric_key_ = <DEM as Dem<{ DEM::KEY_LENGTH }>>::Key::try_from_bytes(
        std::slice::from_raw_parts(symmetric_key_ptr.cast(), symmetric_key_len as usize),
    )
    .map_err(|e| Error::Other(e.to_string()))?;

    let encrypted_header_bytes_ =
        std::slice::from_raw_parts(encrypted_header_ptr.cast(), encrypted_header_len as usize)
            .to_vec();

    unwrap_ffi_error(h_aes_destroy_encryption_cache(cache_handle))?;

    Ok((
        symmetric_key_,
        EncryptedHeader::try_from_bytes(&encrypted_header_bytes_)?,
    ))
}

unsafe fn decrypt_header_using_cache(
    user_decryption_key: &UserSecretKey,
    header: &EncryptedHeader,
    authentication_data: &[u8],
) -> Result<CleartextHeader, Error> {
    let user_decryption_key_bytes = user_decryption_key.try_to_bytes()?;
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr().cast();
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    let mut cache_handle: i32 = 0;

    unwrap_ffi_error(h_aes_create_decryption_cache(
        &mut cache_handle,
        user_decryption_key_ptr,
        user_decryption_key_len,
    ))?;

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut header_metadata = vec![0u8; 8128];
    let header_metadata_ptr = header_metadata.as_mut_ptr().cast();
    let mut header_metadata_len = header_metadata.len() as c_int;

    let header_bytes = header.try_to_bytes()?;

    unwrap_ffi_error(h_aes_decrypt_header_using_cache(
        symmetric_key_ptr,
        &mut symmetric_key_len,
        header_metadata_ptr,
        &mut header_metadata_len,
        header_bytes.as_ptr().cast(),
        header_bytes.len() as c_int,
        authentication_data.as_ptr().cast(),
        authentication_data.len() as c_int,
        cache_handle,
    ))?;

    let symmetric_key = <DEM as Dem<{ DEM::KEY_LENGTH }>>::Key::try_from_bytes(
        std::slice::from_raw_parts(symmetric_key_ptr.cast(), symmetric_key_len as usize),
    )
    .map_err(|e| Error::Other(e.to_string()))?;

    let header_metadata =
        std::slice::from_raw_parts(header_metadata_ptr.cast(), header_metadata_len as usize)
            .to_vec();

    unwrap_ffi_error(h_aes_destroy_decryption_cache(cache_handle))?;

    Ok(CleartextHeader {
        symmetric_key,
        metadata: header_metadata,
    })
}

#[test]
fn test_ffi_hybrid_header_using_cache() -> Result<(), Error> {
    unsafe {
        let policy = policy()?;

        //
        // CoverCrypt setup
        //
        let cover_crypt = CoverCryptX25519Aes256::default();
        let (msk, mpk) = cover_crypt.generate_master_keys(&policy)?;
        let access_policy = AccessPolicy::new("Department", "FIN")
            & AccessPolicy::new("Security Level", "Top Secret");
        let sk_u = cover_crypt.generate_user_secret_key(&msk, &access_policy, &policy)?;

        //
        // Encrypt / decrypt
        //
        let header_metadata = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let authentication_data = vec![10, 11, 12, 13, 14];

        let (symmetric_key, encrypted_header) =
            encrypt_header_using_cache(&mpk, &policy, &header_metadata, &authentication_data)?;
        let decrypted_header =
            decrypt_header_using_cache(&sk_u, &encrypted_header, &authentication_data)?;

        assert_eq!(symmetric_key, decrypted_header.symmetric_key);
        assert_eq!(&header_metadata, &decrypted_header.metadata);
    }
    Ok(())
}

unsafe fn generate_master_keys(policy: &Policy) -> Result<(MasterSecretKey, PublicKey), Error> {
    let policy_bytes = serde_json::to_vec(&policy)?;
    let policy_ptr = policy_bytes.as_ptr().cast();
    let policy_len = policy_bytes.len() as c_int;

    // use a large enough buffer size
    let mut msk_bytes = vec![0u8; 8 * 1024];
    let msk_ptr = msk_bytes.as_mut_ptr().cast();
    let mut msk_len = msk_bytes.len() as c_int;

    // use a large enough buffer size
    let mut mpk_bytes = vec![0u8; 8 * 1024];
    let mpk_ptr = mpk_bytes.as_mut_ptr().cast();
    let mut mpk_len = mpk_bytes.len() as c_int;

    unwrap_ffi_error(h_generate_master_keys(
        msk_ptr,
        &mut msk_len,
        mpk_ptr,
        &mut mpk_len,
        policy_ptr,
        policy_len,
    ))?;

    let msk_bytes = std::slice::from_raw_parts(msk_ptr.cast(), msk_len as usize);
    let mpk_bytes = std::slice::from_raw_parts(mpk_ptr.cast(), mpk_len as usize);

    let msk = MasterSecretKey::try_from_bytes(msk_bytes)?;
    let mpk = PublicKey::try_from_bytes(mpk_bytes)?;

    Ok((msk, mpk))
}

unsafe fn generate_user_secret_key(
    msk: &MasterSecretKey,
    access_policy: &str,
    policy: &Policy,
) -> Result<UserSecretKey, Error> {
    //
    // Prepare secret key
    let msk_bytes = msk.try_to_bytes()?;
    let msk_ptr = msk_bytes.as_ptr().cast();
    let msk_len = msk_bytes.len() as i32;

    //
    // Get pointer from access policy
    let access_policy_cs = CString::new(access_policy).map_err(|e| Error::Other(e.to_string()))?;
    let access_policy_ptr = access_policy_cs.as_ptr();
    //
    // Get pointer from policy
    let policy_bytes = serde_json::to_vec(&policy)?;
    let policy_ptr = policy_bytes.as_ptr().cast();
    let policy_len = policy_bytes.len() as c_int;

    // Prepare OUT buffer
    // use a large enough buffer size
    let mut usk_bytes = vec![0u8; 37696];
    let usk_ptr = usk_bytes.as_mut_ptr().cast();
    let mut usk_len = usk_bytes.len() as c_int;

    unwrap_ffi_error(h_generate_user_secret_key(
        usk_ptr,
        &mut usk_len,
        msk_ptr,
        msk_len,
        access_policy_ptr,
        policy_ptr,
        policy_len,
    ))?;

    let user_key_bytes = std::slice::from_raw_parts(usk_ptr.cast(), usk_len as usize).to_vec();

    // Check deserialization of secret key
    let user_key = UserSecretKey::try_from_bytes(&user_key_bytes)?;

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
    let access_policy = "Department::FIN && Security Level::Top Secret";

    //
    // Generate user secret key
    let _usk = unsafe { generate_user_secret_key(&master_keys.0, access_policy, &policy)? };

    Ok(())
}

unsafe fn rotate_policy(policy: &Policy, attribute: &Attribute) -> Result<Policy, Error> {
    let policy_bytes = serde_json::to_vec(&policy)?;
    let policy_ptr = policy_bytes.as_ptr().cast();
    let policy_len = policy_bytes.len() as c_int;

    let attribute_json =
        CString::new(attribute.to_string()).map_err(|e| Error::Other(e.to_string()))?;
    let attribute_ptr = attribute_json.as_ptr();

    // prepare update policy pointer
    let mut updated_policy_bytes = vec![0u8; 64 * 1024];
    let updated_policy_ptr = updated_policy_bytes.as_mut_ptr().cast();
    let mut updated_policy_len = updated_policy_bytes.len() as c_int;

    unwrap_ffi_error(h_rotate_attribute(
        updated_policy_ptr,
        &mut updated_policy_len,
        policy_ptr,
        policy_len,
        attribute_ptr,
    ))?;

    let updated_policy_bytes =
        std::slice::from_raw_parts(updated_policy_ptr.cast(), updated_policy_len as usize).to_vec();
    let updated_policy: Policy = serde_json::from_slice(&updated_policy_bytes)?;

    Ok(updated_policy)
}

unsafe fn update_master_keys(
    policy: &Policy,
    msk: MasterSecretKey,
    master_public_key: PublicKey,
) -> Result<(MasterSecretKey, PublicKey), Error> {
    let policy_bytes = serde_json::to_vec(&policy)?;
    let policy_ptr = policy_bytes.as_ptr().cast();
    let policy_len = policy_bytes.len() as c_int;

    let msk_bytes = msk.try_to_bytes()?;
    let msk_ptr = msk_bytes.as_ptr().cast();
    let msk_len = msk_bytes.len() as i32;

    let master_public_key_bytes = master_public_key.try_to_bytes()?;
    let master_public_key_ptr = master_public_key_bytes.as_ptr().cast();
    let master_public_key_len = master_public_key_bytes.len() as i32;

    // prepare updated master secret key pointer
    let mut updated_msk_bytes = vec![0u8; 64 * 1024];
    let updated_msk_ptr = updated_msk_bytes.as_mut_ptr().cast();
    let mut updated_msk_len = updated_msk_bytes.len() as c_int;

    // prepare updated master public key pointer
    let mut updated_master_public_key_bytes = vec![0u8; 64 * 1024];
    let updated_master_public_key_ptr = updated_master_public_key_bytes.as_mut_ptr().cast();
    let mut updated_master_public_key_len = updated_master_public_key_bytes.len() as c_int;

    unwrap_ffi_error(h_update_master_keys(
        updated_msk_ptr,
        &mut updated_msk_len,
        updated_master_public_key_ptr,
        &mut updated_master_public_key_len,
        msk_ptr,
        msk_len,
        master_public_key_ptr,
        master_public_key_len,
        policy_ptr,
        policy_len,
    ))?;

    let updated_msk_bytes =
        std::slice::from_raw_parts(updated_msk_ptr.cast(), updated_msk_len as usize).to_vec();
    let updated_msk = MasterSecretKey::try_from_bytes(&updated_msk_bytes)?;

    let updated_master_public_key_bytes = std::slice::from_raw_parts(
        updated_master_public_key_ptr.cast(),
        updated_master_public_key_len as usize,
    )
    .to_vec();
    let update_master_public_key = PublicKey::try_from_bytes(&updated_master_public_key_bytes)?;

    Ok((updated_msk, update_master_public_key))
}

unsafe fn refresh_user_secret_key(
    usk: &UserSecretKey,
    access_policy: &str,
    msk: &MasterSecretKey,
    policy: &Policy,
    preserve_old_partitions_access: bool,
) -> Result<UserSecretKey, Error> {
    let policy_bytes = serde_json::to_vec(&policy)?;
    let policy_ptr = policy_bytes.as_ptr().cast();
    let policy_len = policy_bytes.len() as c_int;

    let msk_bytes = msk.try_to_bytes()?;
    let msk_ptr = msk_bytes.as_ptr().cast();
    let msk_len = msk_bytes.len() as i32;

    let usk_bytes = usk.try_to_bytes()?;
    let usk_ptr = usk_bytes.as_ptr().cast();
    let usk_len = usk_bytes.len() as i32;

    // Get pointer from access policy
    let access_policy_cs = CString::new(access_policy).map_err(|e| Error::Other(e.to_string()))?;
    let access_policy_ptr = access_policy_cs.as_ptr();

    let preserve_old_partitions_access_c: c_int = i32::from(preserve_old_partitions_access);

    // prepare updated user secret key pointer
    let mut updated_usk_bytes = vec![0u8; 64 * 1024];
    let updated_usk_ptr = updated_usk_bytes.as_mut_ptr().cast();
    let mut updated_usk_len = updated_usk_bytes.len() as c_int;

    unwrap_ffi_error(h_refresh_user_secret_key(
        updated_usk_ptr,
        &mut updated_usk_len,
        msk_ptr,
        msk_len,
        usk_ptr,
        usk_len,
        access_policy_ptr,
        policy_ptr,
        policy_len,
        preserve_old_partitions_access_c,
    ))?;

    let updated_usk_bytes =
        std::slice::from_raw_parts(updated_usk_ptr.cast(), updated_usk_len as usize).to_vec();
    let updated_usk = UserSecretKey::try_from_bytes(&updated_usk_bytes)?;

    Ok(updated_usk)
}

#[test]
fn test_ffi_rotate_attribute() -> Result<(), Error> {
    //
    // CoverCrypt setup
    //
    let policy = policy()?;
    let cover_crypt = CoverCryptX25519Aes256::default();
    let (msk, mpk) = cover_crypt.generate_master_keys(&policy)?;
    let original_msk_partitions: Vec<Partition> = msk.x.clone().into_keys().collect();
    let original_mpk_partitions: Vec<Partition> = mpk.H.clone().into_keys().collect();

    let access_policy = "Department::MKG && Security Level::Confidential";
    let usk = cover_crypt.generate_user_secret_key(
        &msk,
        &AccessPolicy::from_boolean_expression(access_policy)?,
        &policy,
    )?;
    let original_usk = usk.clone();

    unsafe {
        //rotate the policy
        let updated_policy = rotate_policy(&policy, &Attribute::new("Department", "MKG"))?;
        // update the master keys
        let (updated_msk, updated_mpk) = update_master_keys(&updated_policy, msk, mpk)?;
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
            refresh_user_secret_key(&usk, access_policy, &updated_msk, &updated_policy, true)?;
        // 2 partitions accessed by the user were rotated (MKG Confidential and MKG
        // Protected)
        assert_eq!(updated_usk.x.len(), original_usk.x.len() + 2);
        for x_i in &original_usk.x {
            assert!(updated_usk.x.contains(x_i));
        }
        // update the user key, but do NOT preserve the accesses to the rotated
        // partitions
        let updated_usk =
            refresh_user_secret_key(&usk, access_policy, &updated_msk, &updated_policy, false)?;
        // 2 partitions accessed by the user were rotated (MKG Confidential and MKG
        // Protected)
        assert_eq!(updated_usk.x.len(), original_usk.x.len());
        for x_i in &original_usk.x {
            assert!(!updated_usk.x.contains(x_i));
        }
    }
    Ok(())
}

//
// Encrypt / decrypt
//

unsafe fn encrypt(
    policy: &Policy,
    public_key: &PublicKey,
    encryption_policy: &str,
    plaintext: &[u8],
    header_metadata: &[u8],
    authentication_data: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut ciphertext_bytes = vec![0u8; 8128];
    let ciphertext_ptr = ciphertext_bytes.as_mut_ptr().cast();
    let mut ciphertext_len = ciphertext_bytes.len() as c_int;

    let policy_bytes = serde_json::to_vec(&policy)?;
    let policy_ptr = policy_bytes.as_ptr().cast();
    let policy_len = policy_bytes.len() as c_int;

    let public_key_bytes = public_key.try_to_bytes()?;
    let public_key_ptr = public_key_bytes.as_ptr();
    let public_key_len = public_key_bytes.len() as i32;

    let encryption_policy_cs =
        CString::new(encryption_policy).map_err(|e| Error::Other(e.to_string()))?;
    let encryption_policy_ptr = encryption_policy_cs.as_ptr();

    unwrap_ffi_error(h_aes_encrypt(
        ciphertext_ptr,
        &mut ciphertext_len,
        policy_ptr,
        policy_len,
        public_key_ptr.cast(),
        public_key_len,
        encryption_policy_ptr,
        plaintext.as_ptr().cast(),
        plaintext.len() as i32,
        header_metadata.as_ptr().cast(),
        header_metadata.len() as i32,
        authentication_data.as_ptr().cast(),
        authentication_data.len() as i32,
    ))?;

    let ciphertext_bytes =
        std::slice::from_raw_parts(ciphertext_ptr.cast(), ciphertext_len as usize).to_vec();
    Ok(ciphertext_bytes)
}

unsafe fn decrypt(
    ciphertext: &[u8],
    user_decryption_key: &UserSecretKey,
    authentication_data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    // use a large enough buffer size
    let mut plaintext = vec![0u8; 8192];
    let plaintext_ptr = plaintext.as_mut_ptr().cast();
    let mut plaintext_len = plaintext.len() as c_int;

    // use a large enough buffer size
    let mut metadata = vec![0u8; 8192];
    let metadata_ptr = metadata.as_mut_ptr().cast();
    let mut metadata_len = metadata.len() as c_int;

    let ciphertext_ptr = ciphertext.as_ptr().cast();
    let ciphertext_len = ciphertext.len() as c_int;

    let authentication_data_ptr = authentication_data.as_ptr().cast();
    let authentication_data_len = authentication_data.len() as c_int;

    let user_decryption_key_bytes = user_decryption_key.try_to_bytes()?;
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr().cast();
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    unwrap_ffi_error(h_aes_decrypt(
        plaintext_ptr,
        &mut plaintext_len,
        metadata_ptr,
        &mut metadata_len,
        ciphertext_ptr,
        ciphertext_len,
        authentication_data_ptr,
        authentication_data_len,
        user_decryption_key_ptr,
        user_decryption_key_len,
    ))?;

    let plaintext =
        std::slice::from_raw_parts(plaintext_ptr.cast(), plaintext_len as usize).to_vec();
    let header_metadata =
        std::slice::from_raw_parts(metadata_ptr.cast(), metadata_len as usize).to_vec();

    Ok((plaintext, header_metadata))
}

#[test]
fn test_encrypt_decrypt() -> Result<(), Error> {
    unsafe {
        //
        // Policy settings
        //
        let policy = policy()?;
        let encryption_policy =
            "(Department::HR || Department::FIN) && Security Level::Confidential";

        //
        // CoverCrypt setup
        //
        let cover_crypt = CoverCryptX25519Aes256::default();
        let (msk, mpk) = cover_crypt.generate_master_keys(&policy)?;
        let user_access_policy =
            AccessPolicy::from_boolean_expression("Department::FIN && Security Level::Top Secret")?;
        let usk = cover_crypt.generate_user_secret_key(&msk, &user_access_policy, &policy)?;

        //
        // Encrypt / decrypt
        //
        let plaintext = vec![16, 17, 18, 19, 20, 21];
        let header_metadata = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let authentication_data = vec![10, 11, 12, 13, 14];

        let ciphertext = encrypt(
            &policy,
            &mpk,
            encryption_policy,
            &plaintext,
            &header_metadata,
            &authentication_data,
        )?;

        let (plaintext_, header_metadata_) = decrypt(&ciphertext, &usk, &authentication_data)?;

        assert_eq!(plaintext, plaintext_);
        assert_eq!(header_metadata, header_metadata_);
    }
    Ok(())
}
