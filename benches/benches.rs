use cosmian_cover_crypt::{
    abe_policy::{AccessPolicy, Attribute, DimensionBuilder, EncryptionHint, Policy},
    Covercrypt, EncryptedHeader, Error,
};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

// Policy settings
fn policy() -> Result<Policy, Error> {
    let (security_level, department) = {
        (
            DimensionBuilder::new(
                "Security",
                vec![
                    ("Classic", EncryptionHint::Classic),
                    ("Hybridized", EncryptionHint::Hybridized),
                ],
                false,
            ),
            DimensionBuilder::new(
                "Department",
                vec![
                    ("R&D", EncryptionHint::Classic),
                    ("HR", EncryptionHint::Classic),
                    ("MKG", EncryptionHint::Classic),
                    ("FIN", EncryptionHint::Classic),
                    ("CYB", EncryptionHint::Classic),
                ],
                false,
            ),
        )
    };
    let mut policy = Policy::new();
    policy.add_dimension(security_level)?;
    policy.add_dimension(department)?;
    Ok(policy)
}

fn bench_policy_editing(c: &mut Criterion) {
    let cover_crypt = Covercrypt::default();
    let new_dep_attr = Attribute::new("Department", "Tech");
    let new_dep_name = "IT".to_string();
    let remove_dep_attr = Attribute::new("Department", "FIN");
    let old_sl_attr = Attribute::new("Security Level", "Protected");
    let new_sl_name = "Open".to_string();
    let disable_sl_attr = Attribute::new("Security Level", "Confidential");

    let mut group = c.benchmark_group("Edit Policy");
    //for (n_partition, access_policy) in access_policies.iter().enumerate() {
    group.bench_function("edit policy", |b| {
        b.iter_batched(
            || {
                let policy = policy().expect("cannot generate policy");

                let (msk, mpk) = cover_crypt
                    .generate_master_keys(&policy)
                    .expect("cannot generate master keys");
                (policy, msk, mpk)
            },
            |(mut policy, mut msk, mut mpk)| {
                policy
                    .add_attribute(new_dep_attr.clone(), EncryptionHint::Classic)
                    .unwrap();
                policy
                    .rename_attribute(&new_dep_attr, new_dep_name.clone())
                    .unwrap();
                policy.remove_attribute(&remove_dep_attr).unwrap();

                policy
                    .rename_attribute(&old_sl_attr, new_sl_name.clone())
                    .unwrap();
                policy.disable_attribute(&disable_sl_attr).unwrap();

                cover_crypt
                    .update_master_keys(&policy, &mut msk, &mut mpk)
                    .unwrap();
            },
            BatchSize::SmallInput,
        );
    });
}

/// Generates encryption policies up to 5 partitions, Hybridized if `is_hybridized` is set to
/// `true`.
fn get_encryption_policy(n_coordinates: usize, is_hybridized: bool) -> AccessPolicy {
    let base_ap = if is_hybridized {
        AccessPolicy::from_boolean_expression("Security::Hybridized").unwrap()
    } else {
        AccessPolicy::from_boolean_expression("Security::Classic").unwrap()
    };
    match n_coordinates {
        1 => base_ap,
        2 => AccessPolicy::from_boolean_expression("Department::FIN").unwrap() & base_ap.clone() | base_ap,
        3 => AccessPolicy::from_boolean_expression(
                "Department::FIN || Department::MKG || Department::HR",
            )
            .unwrap()
            & base_ap,
        4 => AccessPolicy::from_boolean_expression(
                "Department::FIN || Department::MKG || Department::HR || Department::R&D",
            )
            .unwrap()
            & base_ap,
        5 => AccessPolicy::from_boolean_expression(
                "Department::FIN || Department::MKG || Department::HR || Department::R&D || Department::CYB",
            )
            .unwrap()
            & base_ap,
        _ => panic!("cannot generate encryption policy for {n_coordinates} coordinates"),
    }
}

fn get_user_policy(n_coordinates: usize, is_hybridized: bool) -> AccessPolicy {
    let base_ap = if is_hybridized {
        AccessPolicy::from_boolean_expression("Security::Hybridized").unwrap()
    } else {
        AccessPolicy::from_boolean_expression("Security::Classic").unwrap()
    };
    match n_coordinates {
        2 => AccessPolicy::from_boolean_expression("Department::FIN || Department::MKG").unwrap()
            | base_ap,
        3 => AccessPolicy::from_boolean_expression(
                "Department::FIN || Department::MKG || Department::HR",
            )
            .unwrap()
            | base_ap,
        4 => AccessPolicy::from_boolean_expression(
                "Department::FIN || Department::MKG || Department::HR || Department::R&D",
            )
            .unwrap()
            | base_ap,
        5 => AccessPolicy::from_boolean_expression(
                "Department::FIN || Department::MKG || Department::HR || Department::R&D || Department::CYB",
            )
            .unwrap()
            | base_ap,
        _ => panic!("cannot generate encryption policy for {n_coordinates} coordinates"),
    }
}

#[cfg(feature = "full_bench")]
fn bench_serialization(c: &mut Criterion) {
    use cosmian_crypto_core::bytes_ser_de::Serializable;

    let policy = policy().expect("cannot generate policy");
    let cover_crypt = Covercrypt::default();
    let (msk, mpk) = cover_crypt
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");

    println!("bench header encryption size: ");

    #[cfg(feature = "hybridized_bench")]
    let is_hybridized = true;
    #[cfg(not(feature = "hybridized_bench"))]
    let is_hybridized = false;

    for n_coordinates in 1..=5 {
        let (_, encrypted_header) = EncryptedHeader::generate(
            &cover_crypt,
            &policy,
            &mpk,
            &get_encryption_policy(n_coordinates, is_hybridized),
            None,
            None,
        )
        .expect("cannot encrypt header 1");
        println!(
            "{} coordinate(s): {} bytes",
            n_coordinates + 1,
            encrypted_header.serialize().unwrap().len(),
        );
    }

    for n_coordinates in 1..=5 {
        let usk = cover_crypt
            .generate_user_secret_key(
                &msk,
                &get_user_policy(n_coordinates, is_hybridized),
                &policy,
            )
            .unwrap();
        println!(
            "{} usk coordinate(s): {} bytes",
            n_coordinates + 1,
            usk.serialize().unwrap().len(),
        );
    }

    // Bench the serialization of the MSK, MPK and a USK with only one coordinate.
    {
        let usk = cover_crypt
            .generate_user_secret_key(&msk, &get_user_policy(1, is_hybridized), &policy)
            .unwrap();
        let mut group = c.benchmark_group("Key serialization");
        group.bench_function("MSK", |b| {
            b.iter(|| msk.serialize().expect("cannot serialize msk"));
        });
        group.bench_function("MPK", |b| {
            b.iter(|| mpk.serialize().expect("cannot serialize mpk"));
        });
        group.bench_function("USK 1 coordinate", |b| {
            b.iter(|| usk.serialize().expect("cannot serialize usk"));
        });
    }

    // Bench the serialization of the header for two to five coordinates.
    {
        let mut group = c.benchmark_group("Header serialization");
        for n_coordinates in 2..=5 {
            let (_, encrypted_header) = EncryptedHeader::generate(
                &cover_crypt,
                &policy,
                &mpk,
                &get_encryption_policy(n_coordinates, is_hybridized),
                None,
                None,
            )
            .expect("cannot encrypt header 1");
            group.bench_function(
                &format!("Header serialization with {} coordinate(s)", n_coordinates),
                |b| {
                    b.iter(|| {
                        encrypted_header.serialize().unwrap_or_else(|_| {
                            panic!("cannot serialize header for {} partition(s)", n_coordinates)
                        })
                    });
                },
            );
        }
    }

    // Bench the serialization of the USK for two to five coordinates.
    {
        let mut group = c.benchmark_group("USK serialization");
        for n_coordinates in 2..=5 {
            let usk = cover_crypt
                .generate_user_secret_key(
                    &msk,
                    &get_user_policy(n_coordinates, is_hybridized),
                    &policy,
                )
                .unwrap();
            group.bench_function(&format!("USK with {} coordinate(s)", n_coordinates), |b| {
                b.iter(|| {
                    usk.serialize().unwrap_or_else(|_| {
                        panic!("cannot serialize header for {} partition(s)", n_coordinates)
                    })
                });
            });
        }
    }
}

fn bench_header_encryption(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");
    let cover_crypt = Covercrypt::default();
    let (_, mpk) = cover_crypt
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");

    #[cfg(feature = "hybridized_bench")]
    let is_hybridized = true;
    #[cfg(not(feature = "hybridized_bench"))]
    let is_hybridized = false;

    let mut group = c.benchmark_group("Header encryption");
    for n_coordinates in 1..=5 {
        group.bench_function(&format!("{} coordinates(s)", n_coordinates), |b| {
            b.iter(|| {
                EncryptedHeader::generate(
                    &cover_crypt,
                    &policy,
                    &mpk,
                    &get_encryption_policy(n_coordinates, is_hybridized),
                    None,
                    None,
                )
                .unwrap_or_else(|_| {
                    panic!("cannot encrypt header for {} partition(s)", n_coordinates)
                })
            });
        });
    }
}

fn bench_header_decryption(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");
    let authenticated_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
    let cover_crypt = Covercrypt::default();
    let (msk, mpk) = cover_crypt
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");

    #[cfg(feature = "hybridized_bench")]
    let is_hybridized = true;
    #[cfg(not(feature = "hybridized_bench"))]
    let is_hybridized = false;

    let mut group = c.benchmark_group("Header encryption and decryption");
    for n_user_coordinates in 1..=5 {
        for n_encapsulations in 1..=5 {
            group.bench_function(
                &format!(
                    "Encpasulations with {} coordinates(s), USK with {} coordinate(s)",
                    n_encapsulations, n_user_coordinates
                ),
                |b| {
                    b.iter_batched(
                        || {
                            // Setup: creates the USK and encapsulation with the correct number of
                            // coordinates.
                            let usk = cover_crypt
                                .generate_user_secret_key(
                                    &msk,
                                    &get_user_policy(n_user_coordinates, is_hybridized),
                                    &policy,
                                )
                                .expect("cannot generate user private key");
                            let (_, encrypted_header) = EncryptedHeader::generate(
                                &cover_crypt,
                                &policy,
                                &mpk,
                                &get_encryption_policy(n_encapsulations, is_hybridized),
                                None,
                                Some(&authenticated_data),
                            )
                            .unwrap_or_else(|_| {
                                panic!(
                                    "cannot encrypt header for {} ciphertext coordinate(s)",
                                    n_encapsulations,
                                )
                            });
                            encrypted_header
                                .decrypt(&cover_crypt, &usk, Some(&authenticated_data))
                                .unwrap_or_else(|_| {
                                    panic!(
                                        "cannot decrypt header for {} ciphertext partition(s), {} usk partition(s)",
                                        n_encapsulations, n_user_coordinates
                                    )
                                });
                            (usk, encrypted_header)
                        },

                        |(usk, encrypted_header)| {
                            encrypted_header
                                .decrypt(&cover_crypt, &usk, Some(&authenticated_data))
                                .unwrap();
                        },

                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(5000);
    targets =
        bench_policy_editing,
        bench_header_encryption,
        bench_header_decryption
);

#[cfg(feature = "full_bench")]
criterion_group!(
name = benches_serialization;
config = Criterion::default().sample_size(5000);
targets = bench_serialization,
);

#[cfg(feature = "full_bench")]
criterion_main!(benches, benches_serialization);

#[cfg(not(feature = "full_bench"))]
criterion_main!(benches);
