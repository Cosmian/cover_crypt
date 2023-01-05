use abe_policy::{AccessPolicy, EncryptionHint, Policy, PolicyAxis};
use cosmian_cover_crypt::{
    statics::{CoverCryptX25519Aes256, EncryptedHeader},
    CoverCrypt, Error,
};
#[cfg(feature = "full_bench")]
use cosmian_crypto_core::bytes_ser_de::Serializable;
use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(feature = "ffi")]
use {
    cosmian_cover_crypt::{
        interfaces::ffi::{
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
    let hybridization = PolicyAxis::new(
        "Hybridization",
        vec![
            ("Hybridized", EncryptionHint::Hybridized),
            ("Classic", EncryptionHint::Classic),
        ],
        false,
    );
    let sec_level = PolicyAxis::new(
        "Security Level",
        vec![
            ("Protected", EncryptionHint::Classic),
            ("Confidential", EncryptionHint::Classic),
            ("Top Secret", EncryptionHint::Classic),
        ],
        true,
    );
    let department = PolicyAxis::new(
        "Department",
        vec![
            ("R&D", EncryptionHint::Classic),
            ("HR", EncryptionHint::Classic),
            ("MKG", EncryptionHint::Classic),
            ("FIN", EncryptionHint::Classic),
        ],
        false,
    );
    let mut policy = Policy::new(100);
    policy.add_axis(hybridization)?;
    policy.add_axis(sec_level)?;
    policy.add_axis(department)?;
    Ok(policy)
}

/// Generate access policies up to 5 partitions along with a user access policy
/// that allows decrypting headers for all these access policies.
///
/// Access policies with more than one partition are generated only if
/// `--features full_bench` is passed.
///
/// Access policies with hybridization hints are generated only if
/// `--features hybridized_bench` is passed
fn get_access_policies() -> (AccessPolicy, Vec<AccessPolicy>) {
    #[cfg(feature = "hybridized_bench")]
    {
        // Access policy with 1 partition
        #[allow(unused_mut)]
        let mut access_policies = vec![AccessPolicy::from_boolean_expression(
            "Hybridization::Hybridized && Department::FIN && Security Level::Protected",
        )
        .unwrap()];

        #[cfg(feature = "full_bench")]
        {
            // Access policy with 2 partition
            access_policies.push(
            AccessPolicy::from_boolean_expression(
                "Hybridization::Hybridized && (Department::FIN || Department::HR) && Security Level::Protected",
            )
            .unwrap(),
        );

            // Access policy with 3 partition
            access_policies.push(AccessPolicy::from_boolean_expression(
            "Hybridization::Hybridized && (Department::FIN || Department::HR || Department::MKG) && Security Level::Protected",
        )
        .unwrap());

            // Access policy with 4 partition
            access_policies.push( AccessPolicy::from_boolean_expression(
                "Hybridization::Hybridized && (Department::FIN || Department::HR || Department::MKG || Department::R&D) && Security \
                Level::Protected",
        )
            .unwrap());

            // Access policy with 5 partition
            access_policies.push(AccessPolicy::from_boolean_expression( "Hybridization::Hybridized && (((Department::FIN || Department::HR || Department::MKG || Department::R&D) && Security Level::Protected) || (Department::HR && Security Level::Top Secret))",
    )
    .unwrap());
        }

        let user_access_policy = AccessPolicy::from_boolean_expression(
            "Hybridization::Hybridized && Department::FIN && Security Level::Protected",
        )
        .unwrap();

        (user_access_policy, access_policies)
    }
    #[cfg(not(feature = "hybridized_bench"))]
    {
        // Access policy with 1 partition
        #[allow(unused_mut)]
        let mut access_policies = vec![AccessPolicy::from_boolean_expression(
            "Hybridization::Classic && Department::FIN && Security Level::Protected",
        )
        .unwrap()];

        #[cfg(feature = "full_bench")]
        {
            // Access policy with 2 partition
            access_policies.push(
            AccessPolicy::from_boolean_expression(
                "Hybridization::Classic && (Department::FIN || Department::HR) && Security Level::Protected",
            )
            .unwrap(),
        );

            // Access policy with 3 partition
            access_policies.push(AccessPolicy::from_boolean_expression(
            "Hybridization::Classic && (Department::FIN || Department::HR || Department::MKG) && Security Level::Protected",
        )
        .unwrap());

            // Access policy with 4 partition
            access_policies.push( AccessPolicy::from_boolean_expression(
                "Hybridization::Classic && (Department::FIN || Department::HR || Department::MKG || Department::R&D) && Security \
                Level::Protected",
        )
            .unwrap());

            // Access policy with 5 partition
            access_policies.push(AccessPolicy::from_boolean_expression( "Hybridization::Classic && (((Department::FIN || Department::HR || Department::MKG || Department::R&D) && Security Level::Protected) || (Department::HR && Security Level::Top Secret))",
    )
    .unwrap());
        }

        let user_access_policy = AccessPolicy::from_boolean_expression(
            "Hybridization::Classic && Department::FIN && Security Level::Protected",
        )
        .unwrap();

        (user_access_policy, access_policies)
    }
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

#[cfg(feature = "full_bench")]
fn bench_serialization(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");
    let (user_access_policy, access_policies) = get_access_policies();
    let cover_crypt = CoverCryptX25519Aes256::default();
    let (msk, mpk) = cover_crypt
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");

    println!("bench header encryption size: ");

    for (i, access_policy) in access_policies.iter().enumerate() {
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, access_policy, None, None)
                .expect("cannot encrypt header 1");
        println!(
            "{} partition(s): {} bytes",
            i + 1,
            encrypted_header.try_to_bytes().unwrap().len(),
        );
    }

    let usk = cover_crypt
        .generate_user_secret_key(&msk, &user_access_policy, &policy)
        .unwrap();

    let mut group = c.benchmark_group("Key serialization");
    group.bench_function("MSK", |b| {
        b.iter(|| msk.try_to_bytes().expect("cannot serialize msk"))
    });
    group.bench_function("MPK", |b| {
        b.iter(|| mpk.try_to_bytes().expect("cannot serialize mpk"))
    });
    group.bench_function("USK", |b| {
        b.iter(|| usk.try_to_bytes().expect("cannot serialize usk"))
    });

    // removes borrow checker warning about several mutable reference on `c`
    drop(group);

    let mut group = c.benchmark_group("Header serialization");
    for (n_partition, access_policy) in access_policies.iter().enumerate() {
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, access_policy, None, None)
                .expect("cannot encrypt header 1");
        group.bench_function(&format!("{} partition(s)", n_partition + 1), |b| {
            b.iter(|| {
                encrypted_header.try_to_bytes().unwrap_or_else(|_| {
                    panic!(
                        "cannot serialize header for {} partition(s)",
                        n_partition + 1
                    )
                })
            })
        });
    }
}

fn bench_header_encryption(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");
    let (_, access_policies) = get_access_policies();
    let cover_crypt = CoverCryptX25519Aes256::default();
    let (_, mpk) = cover_crypt
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");

    let mut group = c.benchmark_group("Header encryption");
    for (n_partition, access_policy) in access_policies.iter().enumerate() {
        group.bench_function(
            &format!("{} partition(s), 1 access", n_partition + 1),
            |b| {
                b.iter(|| {
                    EncryptedHeader::generate(
                        &cover_crypt,
                        &policy,
                        &mpk,
                        access_policy,
                        None,
                        None,
                    )
                    .unwrap_or_else(|_| {
                        panic!("cannot encrypt header for {} partition(s)", n_partition + 1)
                    })
                })
            },
        );
    }

    #[cfg(feature = "full_bench")]
    {
        // Do not bench encryption with metadata if a full benchmark is not running
        let header_metadata = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let authenticated_data = vec![10, 11, 12, 13, 14];
        group.bench_function("1 partition, 1 access + metadata", |b| {
            b.iter(|| {
                EncryptedHeader::generate(
                    &cover_crypt,
                    &policy,
                    &mpk,
                    &access_policies[0],
                    Some(&header_metadata),
                    Some(&authenticated_data),
                )
                .expect("cannot encrypt header 1")
            })
        });
    }
}

#[cfg(feature = "ffi")]
fn bench_ffi_header_encryption(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");

    let cover_crypt = CoverCryptX25519Aes256::default();
    let (_msk, public_key) = cover_crypt
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");

    let target_access_policy = "Department::FIN && Security Level::Confidential";

    let header_metadata = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
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
                header_metadata.as_ptr().cast::<i8>(),
                header_metadata.len() as i32,
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
    let header_metadata = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
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
                header_metadata.as_ptr().cast::<i8>(),
                header_metadata.len() as i32,
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
    let (user_access_policy, access_policies) = get_access_policies();
    let cover_crypt = CoverCryptX25519Aes256::default();
    let (msk, mpk) = cover_crypt
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");
    let user_decryption_key = cover_crypt
        .generate_user_secret_key(&msk, &user_access_policy, &policy)
        .expect("cannot generate user private key");

    let mut group = c.benchmark_group("Header encryption + decryption");
    for (n_partition, access_policy) in access_policies.iter().enumerate() {
        group.bench_function(
            &format!("{} partition(s), 1 access", n_partition + 1),
            |b| {
                b.iter(|| {
                    let (_, encrypted_header) = EncryptedHeader::generate(
                        &cover_crypt,
                        &policy,
                        &mpk,
                        access_policy,
                        None,
                        Some(&authenticated_data),
                    )
                    .unwrap_or_else(|_| {
                        panic!("cannot encrypt header for {} partition(s)", n_partition + 1)
                    });
                    encrypted_header
                        .decrypt(
                            &cover_crypt,
                            &user_decryption_key,
                            Some(&authenticated_data),
                        )
                        .unwrap_or_else(|_| {
                            panic!("cannot decrypt header for {} partition(s)", n_partition + 1)
                        });
                })
            },
        );
    }

    #[cfg(feature = "full_bench")]
    {
        // Do not bench decryption with metadata if a full benchmark is not running
        let header_metadata = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        group.bench_function("1 partition, 1 access + metadata", |b| {
            b.iter(|| {
                let (_, encrypted_header) = EncryptedHeader::generate(
                    &cover_crypt,
                    &policy,
                    &mpk,
                    &access_policies[0],
                    Some(&header_metadata),
                    Some(&authenticated_data),
                )
                .expect("cannot encrypt header with metadata");
                encrypted_header
                    .decrypt(
                        &cover_crypt,
                        &user_decryption_key,
                        Some(&authenticated_data),
                    )
                    .expect("cannot decrypt hybrid header")
            })
        });
    }
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

    let mut header_metadata = vec![0u8; 4096];
    let header_metadata_ptr = header_metadata.as_mut_ptr().cast::<i8>();
    let mut header_metadata_len = header_metadata.len() as c_int;

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
                header_metadata_ptr,
                &mut header_metadata_len,
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

    let mut header_metadata = vec![0u8; 4096];
    let header_metadata_ptr = header_metadata.as_mut_ptr().cast::<i8>();
    let mut header_metadata_len = header_metadata.len() as c_int;

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
                header_metadata_ptr,
                &mut header_metadata_len,
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

#[cfg(feature = "full_bench")]
criterion_group!(
    name = benches_serialization;
    config = Criterion::default().sample_size(5000);
    targets = bench_serialization
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

#[cfg(all(feature = "ffi", feature = "full_bench"))]
criterion_main!(benches, benches_serialization, benches_ffi);

#[cfg(all(feature = "ffi", not(feature = "full_bench")))]
criterion_main!(benches, benches_ffi);

#[cfg(all(not(feature = "ffi"), feature = "full_bench"))]
criterion_main!(benches, benches_serialization);

#[cfg(all(not(feature = "ffi"), not(feature = "full_bench")))]
criterion_main!(benches);
