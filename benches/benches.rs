use abe_policy::{AccessPolicy, Attribute, Policy, PolicyAxis};
use cosmian_cover_crypt::{
    interfaces::statics::{CoverCryptX25519Aes256, EncryptedHeader, PublicKey},
    CoverCrypt, Error, Serializable,
};
use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(feature = "ffi")]
use {
    cosmian_cover_crypt::interfaces::ffi::{
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

/// Generate encrypted header with some additional data
fn generate_encrypted_header(
    cover_crypt: &CoverCryptX25519Aes256,
    public_key: &PublicKey,
    authenticated_data: &[u8],
) -> EncryptedHeader {
    let policy = policy().expect("cannot generate policy");
    let policy_attributes = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ];

    let (_, ctx) = EncryptedHeader::generate(
        cover_crypt,
        &policy,
        public_key,
        &policy_attributes,
        None,
        Some(authenticated_data),
    )
    .expect("cannot encrypt header 1");
    ctx
}

fn bench_header_encryption(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");

    let cover_crypt = CoverCryptX25519Aes256::default();
    let (_msk, mpk) = cover_crypt
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");

    let policy_attributes_1 = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ];
    let (_, encrypted_header_1) = EncryptedHeader::generate(
        &cover_crypt,
        &policy,
        &mpk,
        &policy_attributes_1,
        None,
        None,
    )
    .expect("cannot encrypt header 1");
    let policy_attributes_3 = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Top Secret"),
        Attribute::new("Security Level", "Confidential"),
        Attribute::new("Security Level", "Protected"),
    ];
    let (_, encrypted_header_3) = EncryptedHeader::generate(
        &cover_crypt,
        &policy,
        &mpk,
        &policy_attributes_3,
        None,
        None,
    )
    .expect("cannot encrypt header 3");

    print!("Bench header encryption size: ");
    println!(
        "1 partition: {} bytes, 3 partitions: {} bytes",
        encrypted_header_1.try_to_bytes().unwrap().len(),
        encrypted_header_3.try_to_bytes().unwrap().len(),
    );

    let mut group = c.benchmark_group("Header encryption");
    group.bench_function("1 partition", |b| {
        b.iter(|| {
            EncryptedHeader::generate(
                &cover_crypt,
                &policy,
                &mpk,
                &policy_attributes_1,
                None,
                None,
            )
            .expect("cannot encrypt header 1")
        })
    });
    group.bench_function("3 partitions", |b| {
        b.iter(|| {
            EncryptedHeader::generate(
                &cover_crypt,
                &policy,
                &mpk,
                &policy_attributes_3,
                None,
                None,
            )
            .expect("cannot encrypt header 3")
        })
    });

    let additional_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
    let authenticated_data = vec![10, 11, 12, 13, 14];

    group.bench_function("speed with additional data", |b| {
        b.iter(|| {
            EncryptedHeader::generate(
                &cover_crypt,
                &policy,
                &mpk,
                &policy_attributes_1,
                Some(&additional_data),
                Some(&authenticated_data),
            )
            .expect("cannot encrypt header 1")
        })
    });
}

#[cfg(feature = "ffi")]
fn bench_ffi_header_encryption(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");

    let cover_crypt = CoverCryptX25519Aes256::default();
    let (_msk, public_key) = cover_crypt
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");

    let policy_attributes = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ];

    let additional_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
    let authenticated_data = vec![10, 11, 12, 13, 14];

    let mut symmetric_key = vec![0u8; CoverCryptX25519Aes256::SYM_KEY_LENGTH];
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
                additional_data.as_ptr().cast::<i8>(),
                additional_data.len() as i32,
                authenticated_data.as_ptr().cast::<i8>(),
                authenticated_data.len() as i32,
            ))
            .expect("Failed unwrapping aes encrypt header FFI operation")
        })
    });
}

#[cfg(feature = "ffi")]
fn bench_ffi_header_encryption_using_cache(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");

    let cover_crypt = CoverCryptX25519Aes256::default();
    let (_msk, public_key) = cover_crypt
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");

    let policy_attributes = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ];
    let additional_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
    let authenticated_data = vec![10, 11, 12, 13, 14];

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

    let mut symmetric_key = vec![0u8; CoverCryptX25519Aes256::SYM_KEY_LENGTH];
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
                additional_data.as_ptr().cast::<i8>(),
                additional_data.len() as i32,
                authenticated_data.as_ptr().cast::<i8>(),
                authenticated_data.len() as i32,
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
        Err(Error::Other(format!("FFI ERROR: {}", cstr.to_str()?)))
    } else {
        Ok(())
    }
}

fn bench_header_decryption(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");
    let authenticated_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];

    let cover_crypt = CoverCryptX25519Aes256::default();
    let (msk, public_key) = cover_crypt
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");
    let encrypted_header =
        generate_encrypted_header(&cover_crypt, &public_key, &authenticated_data);

    let access_policy_1 = AccessPolicy::new("Department", "FIN")
        & AccessPolicy::new("Security Level", "Confidential");
    let user_decryption_key_1 = cover_crypt
        .generate_user_secret_key(&msk, &access_policy_1, &policy)
        .expect("cannot generate user private key");

    c.bench_function("Header decryption/1 partition access", |b| {
        b.iter(|| {
            encrypted_header
                .decrypt(
                    &cover_crypt,
                    &user_decryption_key_1,
                    Some(&authenticated_data),
                )
                .expect("cannot decrypt hybrid header")
        })
    });

    let access_policy_3 =
        AccessPolicy::new("Department", "FIN") & AccessPolicy::new("Security Level", "Top Secret");
    let user_decryption_key_3 = cover_crypt
        .generate_user_secret_key(&msk, &access_policy_3, &policy)
        .expect("cannot generate user private key");

    c.bench_function("Header decryption/3 partition access", |b| {
        b.iter(|| {
            encrypted_header
                .decrypt(
                    &cover_crypt,
                    &user_decryption_key_3,
                    Some(&authenticated_data),
                )
                .expect("cannot decrypt hybrid header")
        })
    });
}

#[cfg(feature = "ffi")]
fn bench_ffi_header_decryption(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");

    let authenticated_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];

    let cover_crypt = CoverCryptX25519Aes256::default();
    let (msk, public_key) = cover_crypt
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");
    let encrypted_header =
        generate_encrypted_header(&cover_crypt, &public_key, &authenticated_data);

    let access_policy =
        AccessPolicy::new("Department", "FIN") & AccessPolicy::new("Security Level", "Top Secret");
    let user_decryption_key = cover_crypt
        .generate_user_secret_key(&msk, &access_policy, &policy)
        .expect("cannot generate user decryption key");

    let mut symmetric_key = vec![0u8; CoverCryptX25519Aes256::SYM_KEY_LENGTH];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut additional_data = vec![0u8; 4096];
    let additional_data_ptr = additional_data.as_mut_ptr().cast::<i8>();
    let mut additional_data_len = additional_data.len() as c_int;

    let user_decryption_key_bytes = user_decryption_key
        .try_to_bytes()
        .expect("cannot convert public key to bytes");
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr().cast::<i8>();
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    let header_bytes = encrypted_header.try_to_bytes().unwrap();

    c.bench_function("FFI AES header decryption", |b| {
        b.iter(|| unsafe {
            unwrap_ffi_error(h_aes_decrypt_header(
                symmetric_key_ptr,
                &mut symmetric_key_len,
                additional_data_ptr,
                &mut additional_data_len,
                header_bytes.as_ptr().cast::<i8>(),
                header_bytes.len() as c_int,
                authenticated_data.as_ptr().cast::<i8>(),
                authenticated_data.len() as c_int,
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

    let authenticated_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];

    let cover_crypt = CoverCryptX25519Aes256::default();
    let (msk, public_key) = cover_crypt
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");
    let encrypted_header =
        generate_encrypted_header(&cover_crypt, &public_key, &authenticated_data);

    let access_policy =
        AccessPolicy::new("Department", "FIN") & AccessPolicy::new("Security Level", "Top Secret");
    let user_decryption_key = cover_crypt
        .generate_user_secret_key(&msk, &access_policy, &policy)
        .expect("cannot generate user private key");

    let mut symmetric_key = vec![0u8; CoverCryptX25519Aes256::SYM_KEY_LENGTH];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

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

    let header_bytes = encrypted_header.try_to_bytes().unwrap();

    c.bench_function("FFI AES header decryption using cache", |b| {
        b.iter(|| unsafe {
            unwrap_ffi_error(h_aes_decrypt_header_using_cache(
                symmetric_key_ptr,
                &mut symmetric_key_len,
                additional_data_ptr,
                &mut additional_data_len,
                header_bytes.as_ptr().cast::<i8>(),
                header_bytes.len() as c_int,
                authenticated_data.as_ptr().cast::<i8>(),
                authenticated_data.len() as c_int,
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
    config = Criterion::default().sample_size(5000);
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
