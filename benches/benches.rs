use cosmian_cover_crypt::{
    abe_policy::{AccessPolicy, EncryptionHint, Policy, PolicyAxis},
    statics::{CoverCryptX25519Aes256, EncryptedHeader},
    CoverCrypt, Error,
};
use criterion::{criterion_group, criterion_main, Criterion};

// Policy settings
fn policy() -> Result<Policy, Error> {
    #[cfg(not(feature = "hybridized_bench"))]
    let (security_level, department) = {
        (
            PolicyAxis::new(
                "Security Level",
                vec![
                    ("Protected", EncryptionHint::Classic),
                    ("Confidential", EncryptionHint::Classic),
                    ("Top Secret", EncryptionHint::Classic),
                ],
                true,
            ),
            PolicyAxis::new(
                "Department",
                vec![
                    ("R&D", EncryptionHint::Classic),
                    ("HR", EncryptionHint::Classic),
                    ("MKG", EncryptionHint::Classic),
                    ("FIN", EncryptionHint::Classic),
                    ("CYBER", EncryptionHint::Classic),
                ],
                false,
            ),
        )
    };
    #[cfg(feature = "hybridized_bench")]
    let (security_level, department) = {
        (
            PolicyAxis::new(
                "Security Level",
                vec![
                    ("Protected", EncryptionHint::Hybridized),
                    ("Confidential", EncryptionHint::Hybridized),
                    ("Top Secret", EncryptionHint::Hybridized),
                ],
                true,
            ),
            PolicyAxis::new(
                "Department",
                vec![
                    ("R&D", EncryptionHint::Hybridized),
                    ("HR", EncryptionHint::Hybridized),
                    ("MKG", EncryptionHint::Hybridized),
                    ("FIN", EncryptionHint::Hybridized),
                    ("CYBER", EncryptionHint::Hybridized),
                ],
                false,
            ),
        )
    };
    let mut policy = Policy::new(100);
    policy.add_axis(security_level)?;
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
fn get_access_policies() -> (Vec<AccessPolicy>, Vec<AccessPolicy>) {
    // Access policy with 1 partition
    #[allow(unused_mut)]
    let mut access_policies =
        vec![
            AccessPolicy::from_boolean_expression("Department::FIN && Security Level::Protected")
                .unwrap(),
        ];

    #[cfg(feature = "full_bench")]
    {
        // Access policy with 2 partition
        access_policies.push(
            AccessPolicy::from_boolean_expression(
                "(Department::FIN && Security Level::Protected) || (Department::HR && Security \
                 Level::Confidential)",
            )
            .unwrap(),
        );

        // Access policy with 3 partition
        access_policies.push(
            AccessPolicy::from_boolean_expression(
                "(Department::FIN && Security Level::Protected) || ((Department::HR || \
                 Department::MKG) && Security Level::Confidential)",
            )
            .unwrap(),
        );

        // Access policy with 4 partition
        access_policies.push(
            AccessPolicy::from_boolean_expression(
                "(Department::FIN && Security Level::Protected) || ((Department::HR || \
                 Department::MKG || Department::R&D) && Security Level::Confidential)",
            )
            .unwrap(),
        );

        // Access policy with 5 partition
        access_policies.push(
            AccessPolicy::from_boolean_expression(
                "(Department::FIN && Security Level::Protected) || ((Department::HR || \
                 Department::MKG || Department::R&D) && Security Level::Confidential) || \
                 (Department::HR && Security Level::Top Secret)",
            )
            .unwrap(),
        );
    }

    // The intersection between the user access policies and the encryption
    // policies is always "Department::FIN && Security Level::Protected" only.
    #[allow(unused_mut)]
    let mut user_access_policies =
        vec![
            AccessPolicy::from_boolean_expression("Department::FIN && Security Level::Protected")
                .unwrap(),
        ];

    #[cfg(feature = "full_bench")]
    {
        user_access_policies.push(
            AccessPolicy::from_boolean_expression(
                "(Department::FIN && Department::MKG) && Security Level::Protected",
            )
            .unwrap(),
        );
        user_access_policies.push(
            AccessPolicy::from_boolean_expression(
                "(Department::FIN && Department::MKG && Department::HR) && Security \
                 Level::Protected",
            )
            .unwrap(),
        );
        user_access_policies.push(
            AccessPolicy::from_boolean_expression(
                "(Department::R&D && Department::FIN && Department::MKG && Department::HR) && \
                 Security Level::Protected",
            )
            .unwrap(),
        );
        user_access_policies.push(
            AccessPolicy::from_boolean_expression(
                "(Department::R&D && Department::FIN && Department::MKG && Department::HR && \
                 Department::CYBER) && Security Level::Protected",
            )
            .unwrap(),
        );
    }

    (user_access_policies, access_policies)
}

#[cfg(feature = "full_bench")]
fn bench_serialization(c: &mut Criterion) {
    use cosmian_crypto_core::bytes_ser_de::Serializable;

    let policy = policy().expect("cannot generate policy");
    let (user_access_policies, access_policies) = get_access_policies();
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

    for (i, ap) in user_access_policies.iter().enumerate() {
        let usk = cover_crypt
            .generate_user_secret_key(&msk, ap, &policy)
            .unwrap();
        println!(
            "{} usk partition(s): {} bytes",
            i + 1,
            usk.try_to_bytes().unwrap().len(),
        );
    }

    let mut group = c.benchmark_group("Key serialization");
    group.bench_function("MSK", |b| {
        b.iter(|| msk.try_to_bytes().expect("cannot serialize msk"))
    });
    group.bench_function("MPK", |b| {
        b.iter(|| mpk.try_to_bytes().expect("cannot serialize mpk"))
    });

    let usk = cover_crypt
        .generate_user_secret_key(&msk, &user_access_policies[0], &policy)
        .unwrap();
    group.bench_function("USK 1 partition", |b| {
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
}

fn bench_header_decryption(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");
    let authenticated_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
    let (user_access_policy, access_policies) = get_access_policies();
    let cover_crypt = CoverCryptX25519Aes256::default();
    let (msk, mpk) = cover_crypt
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");
    let user_decryption_keys: Vec<_> = user_access_policy
        .iter()
        .map(|ap| {
            cover_crypt
                .generate_user_secret_key(&msk, ap, &policy)
                .expect("cannot generate user private key")
        })
        .collect();
    let mut group = c.benchmark_group("Header encryption and decryption");
    for (n_partitions_usk, usk) in user_decryption_keys.iter().enumerate() {
        for (n_partition_ct, access_policy) in access_policies.iter().enumerate() {
            group.bench_function(
                &format!(
                    "ciphertexts with {} partition(s), usk with {} partitions",
                    n_partition_ct + 1,
                    n_partitions_usk + 1
                ),
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
                            panic!(
                                "cannot encrypt header for {} ciphertext partition(s), {} usk \
                                 partition(s)",
                                n_partition_ct + 1,
                                n_partitions_usk
                            )
                        });
                        encrypted_header
                            .decrypt(&cover_crypt, usk, Some(&authenticated_data))
                            .unwrap_or_else(|_| {
                                panic!(
                                    "cannot decrypt header for {} ciphertext partition(s), {} usk \
                                     partition(s)",
                                    n_partition_ct + 1,
                                    n_partitions_usk
                                )
                            });
                    })
                },
            );
        }
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

#[cfg(feature = "full_bench")]
criterion_main!(benches, benches_serialization);

#[cfg(not(feature = "full_bench"))]
criterion_main!(benches);
