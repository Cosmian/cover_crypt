use abe_policy::{AccessPolicy, Attribute, Policy, PolicyAxis};
use cosmian_cover_crypt::{
    interfaces::statics::{CoverCryptX25519Aes256, EncryptedHeader},
    CoverCrypt, Error, Serializable,
};
use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(feature = "ffi")]
use {
    cosmian_cover_crypt::interfaces::{
        ffi::{
            error::get_last_error,
            hybrid_cc_aes::{
                h_aes_create_decryption_cache, h_aes_create_encryption_cache, h_aes_decrypt_header,
                h_aes_decrypt_header_using_cache, h_aes_destroy_decryption_cache,
                h_aes_destroy_encryption_cache, h_aes_encrypt_header,
                h_aes_encrypt_header_using_cache,
            },
        },
        statics::PublicKey,
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
#[cfg(feature = "ffi")]
fn generate_encrypted_header(
    cover_crypt: &CoverCryptX25519Aes256,
    public_key: &PublicKey,
    authenticated_data: &[u8],
) -> EncryptedHeader {
    let policy = policy().expect("cannot generate policy");
    let policy_access =
        AccessPolicy::from_boolean_expression("Department::FIN && Security Level::Confidential")
            .unwrap();

    let (_, ctx) = EncryptedHeader::generate(
        cover_crypt,
        &policy,
        public_key,
        &policy_access,
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

    // Access policy with 1 partition
    let access_policy_1 =
        AccessPolicy::from_boolean_expression("Department::FIN && Security Level::Protected")
            .unwrap();

    // Access policy with 2 partition
    let access_policy_2 = AccessPolicy::from_boolean_expression(
        "(Department::FIN || Department::HR) && Security Level::Protected",
    )
    .unwrap();

    // Access policy with 3 partition
    let access_policy_3 = AccessPolicy::from_boolean_expression(
        "(Department::FIN || Department::HR || Department::MKG) && Security Level::Protected",
    )
    .unwrap();

    // Access policy with 4 partition
    let access_policy_4 = AccessPolicy::from_boolean_expression(
        "(Department::FIN || Department::HR || Department::MKG || Department::R&D) && Security Level::Protected",
    )
    .unwrap();

    // Access policy with 5 partition
    let access_policy_5 = AccessPolicy::from_boolean_expression(
        "((Department::FIN || Department::HR || Department::MKG || Department::R&D) && Security Level::Protected) || (Department::HR && Security Level::Top Secret)",
    )
    .unwrap();

    // Get ready ciphertexts for size benchmark
    let (_, encrypted_header_1) =
        EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy_1, None, None)
            .expect("cannot encrypt header 1");

    let (_, encrypted_header_2) =
        EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy_2, None, None)
            .expect("cannot encrypt header 2");

    let (_, encrypted_header_3) =
        EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy_3, None, None)
            .expect("cannot encrypt header 3");

    let (_, encrypted_header_4) =
        EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy_4, None, None)
            .expect("cannot encrypt header 4");

    let (_, encrypted_header_5) =
        EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy_5, None, None)
            .expect("cannot encrypt header 5");

    println!("Bench header encryption size:");
    println!(
        "1 partition: {} bytes\n2 partitions: {} bytes\n3 partitions: {} bytes\n4 partitions: {} bytes\n5 partitions: {} bytes\n",
        encrypted_header_1.try_to_bytes().unwrap().len(),
        encrypted_header_2.try_to_bytes().unwrap().len(),
        encrypted_header_3.try_to_bytes().unwrap().len(),
        encrypted_header_4.try_to_bytes().unwrap().len(),
        encrypted_header_5.try_to_bytes().unwrap().len(),
    );

    let mut group = c.benchmark_group("Header encryption");
    group.bench_function("1 partition", |b| {
        b.iter(|| {
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy_1, None, None)
                .expect("cannot encrypt header 1")
        })
    });
    group.bench_function("2 partitions", |b| {
        b.iter(|| {
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy_2, None, None)
                .expect("cannot encrypt header 2")
        })
    });
    group.bench_function("3 partitions", |b| {
        b.iter(|| {
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy_3, None, None)
                .expect("cannot encrypt header 3")
        })
    });
    group.bench_function("4 partitions", |b| {
        b.iter(|| {
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy_4, None, None)
                .expect("cannot encrypt header 4")
        })
    });
    group.bench_function("5 partitions", |b| {
        b.iter(|| {
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy_5, None, None)
                .expect("cannot encrypt header 5")
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
                &access_policy_1,
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

    let target_access_policy = "Department::FIN && Security Level::Confidential";

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

    let target_access_policy = CString::new(target_access_policy)
        .expect("cannot create CString from String converted policy attributes");

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
                target_access_policy.as_ptr(),
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

    let policy_attributes = "Department::FIN && Security Level::Confidential";
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

    let target_policy_attributes = CString::new(policy_attributes)
        .expect("cannot create CString from String converted policy attributes");

    c.bench_function("FFI AES header encryption using cache", |b| {
        b.iter(|| unsafe {
            unwrap_ffi_error(h_aes_encrypt_header_using_cache(
                symmetric_key_ptr,
                &mut symmetric_key_len,
                header_bytes_ptr,
                &mut header_bytes_len,
                cache_handle,
                target_policy_attributes.as_ptr(),
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
    let (msk, mpk) = cover_crypt
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");

    // Access policy with 1 partition
    let access_policy_1 =
        AccessPolicy::from_boolean_expression("Department::FIN && Security Level::Protected")
            .unwrap();

    // Access policy with 2 partition
    let access_policy_2 = AccessPolicy::from_boolean_expression(
        "(Department::FIN || Department::HR) && Security Level::Protected",
    )
    .unwrap();

    // Access policy with 3 partition
    let access_policy_3 = AccessPolicy::from_boolean_expression(
        "(Department::FIN || Department::HR || Department::MKG) && Security Level::Protected",
    )
    .unwrap();

    // Access policy with 4 partition
    let access_policy_4 = AccessPolicy::from_boolean_expression(
        "(Department::FIN || Department::HR || Department::MKG || Department::R&D) && Security Level::Protected",
    )
    .unwrap();

    // Access policy with 5 partition
    let access_policy_5 = AccessPolicy::from_boolean_expression(
        "((Department::FIN || Department::HR || Department::MKG || Department::R&D) && Security Level::Protected) || (Department::HR && Security Level::Top Secret)",
    )
    .unwrap();

    // Get ready ciphertexts for size benchmark
    let (_, encrypted_header_1) =
        EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy_1, None, None)
            .expect("cannot encrypt header 1");

    let (_, encrypted_header_2) =
        EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy_2, None, None)
            .expect("cannot encrypt header 2");

    let (_, encrypted_header_3) =
        EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy_3, None, None)
            .expect("cannot encrypt header 3");

    let (_, encrypted_header_4) =
        EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy_4, None, None)
            .expect("cannot encrypt header 4");

    let (_, encrypted_header_5) =
        EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy_5, None, None)
            .expect("cannot encrypt header 5");

    let user_access_policy =
        AccessPolicy::from_boolean_expression("Department::FIN && Security Level::Protected")
            .unwrap();
    let user_decryption_key = cover_crypt
        .generate_user_secret_key(&msk, &user_access_policy, &policy)
        .expect("cannot generate user private key");

    c.bench_function("Header decryption/1 partition, 1 access", |b| {
        b.iter(|| {
            encrypted_header_1
                .decrypt(
                    &cover_crypt,
                    &user_decryption_key,
                    Some(&authenticated_data),
                )
                .expect("cannot decrypt hybrid header")
        })
    });
    c.bench_function("Header decryption/2 partition, 1 access", |b| {
        b.iter(|| {
            encrypted_header_2
                .decrypt(
                    &cover_crypt,
                    &user_decryption_key,
                    Some(&authenticated_data),
                )
                .expect("cannot decrypt hybrid header")
        })
    });
    c.bench_function("Header decryption/3 partition, 1 access", |b| {
        b.iter(|| {
            encrypted_header_3
                .decrypt(
                    &cover_crypt,
                    &user_decryption_key,
                    Some(&authenticated_data),
                )
                .expect("cannot decrypt hybrid header")
        })
    });
    c.bench_function("Header decryption/4 partition, 1 access", |b| {
        b.iter(|| {
            encrypted_header_4
                .decrypt(
                    &cover_crypt,
                    &user_decryption_key,
                    Some(&authenticated_data),
                )
                .expect("cannot decrypt hybrid header")
        })
    });
    c.bench_function("Header decryption/5 partition, 1 access", |b| {
        b.iter(|| {
            encrypted_header_5
                .decrypt(
                    &cover_crypt,
                    &user_decryption_key,
                    Some(&authenticated_data),
                )
                .expect("cannot decrypt hybrid header")
        })
    });
    c.bench_function("Header decryption/1 partition, 1 access", |b| {
        b.iter(|| {
            encrypted_header_1
                .decrypt(
                    &cover_crypt,
                    &user_decryption_key,
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
