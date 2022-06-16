#[cfg(feature = "ffi")]
use cosmian_crypto_base::symmetric_crypto::aes_256_gcm_pure;
use cosmian_crypto_base::{
    asymmetric::ristretto::X25519Crypto, hybrid_crypto::Metadata,
    symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto,
};
use cover_crypt::{
    api::{CoverCrypt, PublicKey},
    error::Error,
    interfaces::statics::{decrypt_hybrid_header, encrypt_hybrid_header, EncryptedHeader},
    policies::{ap, Attribute, Policy, PolicyAxis},
};
use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(feature = "ffi")]
use {
    cover_crypt::interfaces::ffi::{
        error::get_last_error,
        hybrid_cc_aes::{
            h_aes_create_decryption_cache, h_aes_create_encryption_cache, h_aes_decrypt_header,
            h_aes_decrypt_header_using_cache, h_aes_destroy_decryption_cache,
            h_aes_destroy_encryption_cache, h_aes_encrypt_header, h_aes_encrypt_header_using_cache,
        },
    },
    std::{
        ffi::{CStr, CString},
        os::raw::c_int,
    },
};

// Policy settings
fn policy() -> Result<Policy, Error> {
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

/// Generate encrypted header with some metadata
fn generate_encrypted_header(
    public_key: &PublicKey<X25519Crypto>,
) -> EncryptedHeader<Aes256GcmCrypto> {
    let policy = policy().expect("cannot generate policy");
    let policy_attributes = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ];
    let metadata = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };

    encrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
        &policy,
        public_key,
        &policy_attributes,
        Some(&metadata),
    )
    .expect("cannot encrypt header 1")
}

fn bench_header_encryption(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");

    let cc = CoverCrypt::<X25519Crypto>::default();
    let (_msk, mpk) = cc
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");

    let policy_attributes_1 = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ];
    let encrypted_header_1 = encrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
        &policy,
        &mpk,
        &policy_attributes_1,
        None,
    )
    .expect("cannot encrypt header 1");
    let policy_attributes_3 = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Top Secret"),
        Attribute::new("Security Level", "Confidential"),
        Attribute::new("Security Level", "Protected"),
    ];
    let encrypted_header_3 = encrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
        &policy,
        &mpk,
        &policy_attributes_3,
        None,
    )
    .expect("cannot encrypt header 3");

    print!("Bench header encryption size: ");
    println!(
        "1 partition: {} bytes, 3 partitions: {} bytes",
        encrypted_header_1.header_bytes.len(),
        encrypted_header_3.header_bytes.len(),
    );

    let mut group = c.benchmark_group("Header encryption");
    group.bench_function("1 partition", |b| {
        b.iter(|| {
            encrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
                &policy,
                &mpk,
                &policy_attributes_1,
                None,
            )
            .expect("cannot encrypt header 1")
        })
    });
    group.bench_function("3 partitions", |b| {
        b.iter(|| {
            encrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
                &policy,
                &mpk,
                &policy_attributes_3,
                None,
            )
            .expect("cannot encrypt header 3")
        })
    });

    let metadata = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };
    group.bench_function("speed with metadata", |b| {
        b.iter(|| {
            encrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
                &policy,
                &mpk,
                &policy_attributes_1,
                Some(&metadata),
            )
            .expect("cannot encrypt header 1")
        })
    });
}

///
/// # Safety
#[cfg(feature = "ffi")]
fn bench_ffi_header_encryption(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");

    let cc = CoverCrypt::<X25519Crypto>::default();
    let (_msk, public_key) = cc
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");

    let policy_attributes = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ];
    let metadata = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };

    let mut symmetric_key = vec![0u8; aes_256_gcm_pure::KEY_LENGTH];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut header_bytes_key = vec![0u8; 4096];
    let header_bytes_ptr = header_bytes_key.as_mut_ptr().cast::<i8>();
    let mut header_bytes_len = header_bytes_key.len() as c_int;

    let policy_cs = CString::new(
        serde_json::to_string(&policy)
            .expect("cannot convert policy to string")
            .as_str(),
    )
    .expect("cannot create CString from String converted policy");
    let policy_ptr = policy_cs.as_ptr();

    let public_key_bytes = public_key
        .try_to_bytes()
        .expect("cannot convert public key to bytes");
    let public_key_ptr = public_key_bytes.as_ptr();

    let attributes_json = CString::new(
        serde_json::to_string(&policy_attributes)
            .expect("cannot convert policy attributes to string")
            .as_str(),
    )
    .expect("cannot create CString from String converted policy attributes");
    let attributes_ptr = attributes_json.as_ptr();

    c.bench_function("FFI AES header encryption", |b| {
        b.iter(|| unsafe {
            unwrap_ffi_error(h_aes_encrypt_header(
                symmetric_key_ptr,
                &mut symmetric_key_len,
                header_bytes_ptr,
                &mut header_bytes_len,
                policy_ptr,
                public_key_ptr.cast::<i8>(),
                public_key_bytes.len() as i32,
                attributes_ptr,
                metadata.uid.as_ptr().cast::<i8>(),
                metadata.uid.len() as i32,
                metadata
                    .additional_data
                    .as_ref()
                    .unwrap()
                    .as_ptr()
                    .cast::<i8>(),
                metadata.additional_data.as_ref().unwrap().len() as i32,
            ))
            .expect("Failed unwrapping aes encrypt header FFI operation")
        })
    });
}

///
/// # Safety
#[cfg(feature = "ffi")]
fn bench_ffi_header_encryption_using_cache(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");

    let cc = CoverCrypt::<X25519Crypto>::default();
    let (_msk, public_key) = cc
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");

    let policy_attributes = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ];
    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };

    let policy_cs = CString::new(
        serde_json::to_string(&policy)
            .expect("cannot convert policy to string")
            .as_str(),
    )
    .expect("cannot create CString from String converted policy");
    let policy_ptr = policy_cs.as_ptr();

    let public_key_bytes = public_key
        .try_to_bytes()
        .expect("cannot convert public key to bytes");
    let public_key_ptr = public_key_bytes.as_ptr().cast::<i8>();

    let mut cache_handle: i32 = 0;
    unsafe {
        unwrap_ffi_error(h_aes_create_encryption_cache(
            &mut cache_handle,
            policy_ptr,
            public_key_ptr,
            public_key_bytes.len() as i32,
        ))
        .expect("cannot create aes encryption cache");
    }

    let mut symmetric_key = vec![0u8; aes_256_gcm_pure::KEY_LENGTH];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut header_bytes_key = vec![0u8; 4096];
    let header_bytes_ptr = header_bytes_key.as_mut_ptr().cast::<i8>();
    let mut header_bytes_len = header_bytes_key.len() as c_int;

    let attributes_json = CString::new(
        serde_json::to_string(&policy_attributes)
            .expect("cannot convert policy attributes to string")
            .as_str(),
    )
    .expect("cannot create CString from String converted policy attributes");
    let attributes_ptr = attributes_json.as_ptr();

    c.bench_function("FFI AES header encryption using cache", |b| {
        b.iter(|| unsafe {
            unwrap_ffi_error(h_aes_encrypt_header_using_cache(
                symmetric_key_ptr,
                &mut symmetric_key_len,
                header_bytes_ptr,
                &mut header_bytes_len,
                cache_handle,
                attributes_ptr,
                meta_data.uid.as_ptr().cast::<i8>(),
                meta_data.uid.len() as i32,
                meta_data
                    .additional_data
                    .as_ref()
                    .unwrap()
                    .as_ptr()
                    .cast::<i8>(),
                meta_data.additional_data.as_ref().unwrap().len() as i32,
            ))
            .expect("Failed unwrapping FFI AES encrypt header operation")
        })
    });

    unsafe {
        unwrap_ffi_error(h_aes_destroy_encryption_cache(cache_handle))
            .expect("cannot destroy encryption cache");
    }
}

#[cfg(feature = "ffi")]
unsafe fn unwrap_ffi_error(val: i32) -> Result<(), Error> {
    if val != 0 {
        let mut message_bytes_key = vec![0u8; 4096];
        let message_bytes_ptr = message_bytes_key.as_mut_ptr().cast::<i8>();
        let mut message_bytes_len = message_bytes_key.len() as c_int;
        get_last_error(message_bytes_ptr, &mut message_bytes_len);
        let cstr = CStr::from_ptr(message_bytes_ptr);
        return Err(Error::Other(format!("FFI ERROR: {}", cstr.to_str()?)));
    } else {
        Ok(())
    }
}

fn bench_header_decryption(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");

    let cc = CoverCrypt::<X25519Crypto>::default();
    let (msk, public_key) = cc
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");
    let encrypted_header = generate_encrypted_header(&public_key);

    let access_policy = ap("Department", "FIN") & ap("Security Level", "Top Secret");
    let user_decryption_key = cc
        .generate_user_private_key(&msk, &access_policy, &policy)
        .expect("cannot generate user private key");

    c.bench_function("Header decryption", |b| {
        b.iter(|| {
            decrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
                &user_decryption_key,
                &encrypted_header.header_bytes,
            )
            .expect("cannot decrypt hybrid header")
        })
    });
}

#[cfg(feature = "ffi")]
fn bench_ffi_header_decryption(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");

    let cc = CoverCrypt::<X25519Crypto>::default();
    let (msk, public_key) = cc
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");
    let encrypted_header = generate_encrypted_header(&public_key);

    let access_policy = ap("Department", "FIN") & ap("Security Level", "Top Secret");
    let user_decryption_key = cc
        .generate_user_private_key(&msk, &access_policy, &policy)
        .expect("cannot generate user decryption key");

    let mut symmetric_key = vec![0u8; aes_256_gcm_pure::KEY_LENGTH];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut uid = vec![0u8; 4096];
    let uid_ptr = uid.as_mut_ptr().cast::<i8>();
    let mut uid_len = uid.len() as c_int;

    let mut additional_data = vec![0u8; 4096];
    let additional_data_ptr = additional_data.as_mut_ptr().cast::<i8>();
    let mut additional_data_len = additional_data.len() as c_int;

    let user_decryption_key_bytes = user_decryption_key
        .try_to_bytes()
        .expect("cannot convert public key to bytes");
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr().cast::<i8>();
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    c.bench_function("FFI AES header decryption", |b| {
        b.iter(|| unsafe {
            unwrap_ffi_error(h_aes_decrypt_header(
                symmetric_key_ptr,
                &mut symmetric_key_len,
                uid_ptr,
                &mut uid_len,
                additional_data_ptr,
                &mut additional_data_len,
                encrypted_header.header_bytes.as_ptr().cast::<i8>(),
                encrypted_header.header_bytes.len() as c_int,
                user_decryption_key_ptr,
                user_decryption_key_len,
            ))
            .expect("Failed unwrapping FFI AES decrypt header operation")
        })
    });
}

#[cfg(feature = "ffi")]
fn bench_ffi_header_decryption_using_cache(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");

    let cc = CoverCrypt::<X25519Crypto>::default();
    let (msk, public_key) = cc
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");
    let encrypted_header = generate_encrypted_header(&public_key);

    let access_policy = ap("Department", "FIN") & ap("Security Level", "Top Secret");
    let user_decryption_key = cc
        .generate_user_private_key(&msk, &access_policy, &policy)
        .expect("cannot generate user private key");

    let mut symmetric_key = vec![0u8; aes_256_gcm_pure::KEY_LENGTH];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut uid = vec![0u8; 4096];
    let uid_ptr = uid.as_mut_ptr().cast::<i8>();
    let mut uid_len = uid.len() as c_int;

    let mut additional_data = vec![0u8; 4096];
    let additional_data_ptr = additional_data.as_mut_ptr().cast::<i8>();
    let mut additional_data_len = additional_data.len() as c_int;

    let user_decryption_key_bytes = user_decryption_key
        .try_to_bytes()
        .expect("cannot convert public key to bytes");
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr().cast::<i8>();

    let mut cache_handle = 0;
    unsafe {
        unwrap_ffi_error(h_aes_create_decryption_cache(
            &mut cache_handle,
            user_decryption_key_ptr,
            user_decryption_key_bytes.len() as i32,
        ))
        .expect("cannot create aes decryption cache");
    }

    c.bench_function("FFI AES header decryption using cache", |b| {
        b.iter(|| unsafe {
            unwrap_ffi_error(h_aes_decrypt_header_using_cache(
                symmetric_key_ptr,
                &mut symmetric_key_len,
                uid_ptr,
                &mut uid_len,
                additional_data_ptr,
                &mut additional_data_len,
                encrypted_header.header_bytes.as_ptr().cast::<i8>(),
                encrypted_header.header_bytes.len() as c_int,
                cache_handle,
            ))
            .expect("Failed unwrapping FFI AES encrypt header operation")
        })
    });

    unsafe {
        unwrap_ffi_error(h_aes_destroy_decryption_cache(cache_handle))
            .expect("cannot destroy encryption cache");
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(500);
    targets =
        bench_header_encryption,
        bench_header_decryption
);

#[cfg(feature = "ffi")]
criterion_group!(
    name = benches_ffi;
    config = Criterion::default().sample_size(5000);
    targets =
        bench_ffi_header_encryption,
        bench_ffi_header_encryption_using_cache,
        bench_ffi_header_decryption,
        bench_ffi_header_decryption_using_cache
);

#[cfg(feature = "ffi")]
criterion_main!(benches, benches_ffi);

#[cfg(not(feature = "ffi"))]
criterion_main!(benches);
