use cosmian_cover_crypt::{
    Covercrypt, EncryptedHeader, Error,
    abe_policy::{AccessPolicy, DimensionBuilder, EncryptionHint, Policy},
};
use criterion::{Criterion, criterion_group, criterion_main};

// Policy settings
fn policy() -> Result<Policy, Error> {
    #[cfg(not(feature = "hybridized_bench"))]
    let (security_level, department) = {
        (
            DimensionBuilder::new(
                "S",
                vec![
                    ("S1", EncryptionHint::Classic),
                    ("S2", EncryptionHint::Classic),
                    ("S3", EncryptionHint::Classic),
                    ("S4", EncryptionHint::Classic),
                    ("S5", EncryptionHint::Classic),
                ],
                true,
            ),
            DimensionBuilder::new(
                "D",
                vec![
                    ("D1", EncryptionHint::Hybridized),
                    ("D2", EncryptionHint::Hybridized),
                    ("D3", EncryptionHint::Hybridized),
                    ("D4", EncryptionHint::Hybridized),
                    ("D5", EncryptionHint::Hybridized),
                    ("D6", EncryptionHint::Hybridized),
                    ("D7", EncryptionHint::Hybridized),
                    ("D8", EncryptionHint::Hybridized),
                    ("D9", EncryptionHint::Hybridized),
                    ("D10", EncryptionHint::Hybridized),
                    ("D11", EncryptionHint::Hybridized),
                    ("D12", EncryptionHint::Hybridized),
                    ("D13", EncryptionHint::Hybridized),
                ],
                false,
            ),
        )
    };
    #[cfg(feature = "hybridized_bench")]
    let (security_level, department) = {
        (
            DimensionBuilder::new(
                "S",
                vec![
                    ("S1", EncryptionHint::Classic),
                    ("S2", EncryptionHint::Classic),
                    ("S3", EncryptionHint::Classic),
                    ("S4", EncryptionHint::Classic),
                    ("S5", EncryptionHint::Classic),
                ],
                true,
            ),
            DimensionBuilder::new(
                "D",
                vec![
                    ("D1", EncryptionHint::Hybridized),
                    ("D2", EncryptionHint::Hybridized),
                    ("D3", EncryptionHint::Hybridized),
                    ("D4", EncryptionHint::Hybridized),
                    ("D5", EncryptionHint::Hybridized),
                    ("D6", EncryptionHint::Hybridized),
                    ("D7", EncryptionHint::Hybridized),
                    ("D8", EncryptionHint::Hybridized),
                    ("D9", EncryptionHint::Hybridized),
                    ("D10", EncryptionHint::Hybridized),
                    ("D11", EncryptionHint::Hybridized),
                    ("D12", EncryptionHint::Hybridized),
                    ("D13", EncryptionHint::Hybridized),
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

// fn bench_policy_editing(c: &mut Criterion) {
//     let cover_crypt = Covercrypt::default();
//     let new_dep_attr = Attribute::new("Department", "Tech");
//     let new_dep_name = "IT".to_string();
//     let remove_dep_attr = Attribute::new("Department", "FIN");
//     let old_sl_attr = Attribute::new("Security Level", "Protected");
//     let new_sl_name = "Open".to_string();
//     let disable_sl_attr = Attribute::new("Security Level", "Confidential");

//     let mut group = c.benchmark_group("Edit Policy");
//     //for (n_partition, access_policy) in access_policies.iter().enumerate() {
//     group.bench_function("edit policy", |b| {
//         b.iter_batched(
//             || {
//                 let policy = policy().expect("cannot generate policy");

//                 let (msk, mpk) = cover_crypt
//                     .generate_master_keys(&policy)
//                     .expect("cannot generate master keys");
//                 (policy, msk, mpk)
//             },
//             |(mut policy, mut msk, mut mpk)| {
//                 policy
//                     .add_attribute(new_dep_attr.clone(), EncryptionHint::Classic)
//                     .unwrap();
//                 policy
//                     .rename_attribute(&new_dep_attr, new_dep_name.clone())
//                     .unwrap();
//                 policy.remove_attribute(&remove_dep_attr).unwrap();

//                 policy
//                     .rename_attribute(&old_sl_attr, new_sl_name.clone())
//                     .unwrap();
//                 policy.disable_attribute(&disable_sl_attr).unwrap();

//                 cover_crypt
//                     .update_master_keys(&policy, &mut msk, &mut mpk)
//                     .unwrap();
//             },
//             BatchSize::SmallInput,
//         );
//     });
// }

/// Generate access policies up to 5 partitions along with a user access policy
/// that allows decrypting headers for all these access policies.
///
/// Access policies with more than one partition are generated only if
/// `--features full_bench` is passed.
///
/// Access policies with hybridization hints are generated only if
/// `--features hybridized_bench` is passed
fn get_access_policies() -> (Vec<AccessPolicy>, Vec<AccessPolicy>) {
    let access_policies = vec![
        AccessPolicy::from_boolean_expression("S::S1 && D::D1").unwrap(),
        AccessPolicy::from_boolean_expression("(S::S1 || S::S2) && D::D1").unwrap(),
        AccessPolicy::from_boolean_expression("(S::S1 || S::S2 || S::S3) && D::D1").unwrap(),
        AccessPolicy::from_boolean_expression("(S::S1 || S::S2 || S::S3 || S::S4) && D::D1")
            .unwrap(),
        AccessPolicy::from_boolean_expression(
            "(S::S1 || S::S2 || S::S3 || S::S4 || S::S5) && D::D1",
        )
        .unwrap(),
    ];

    let user_access_policies = vec![
        AccessPolicy::from_boolean_expression(
            "S::S1 && (D::D1
                       || D::D2
                       || D::D3
                       || D::D4
                       || D::D5
                       || D::D6
                       || D::D7
                       || D::D8
                       || D::D9
                       || D::D10
                       || D::D11
                       || D::D12)",
        )
        .unwrap(),
    ];

    (user_access_policies, access_policies)
}

#[cfg(feature = "full_bench")]
fn bench_serialization(c: &mut Criterion) {
    use cosmian_crypto_core::bytes_ser_de::Serializable;

    let policy = policy().expect("cannot generate policy");
    let (user_access_policies, access_policies) = get_access_policies();
    let cover_crypt = Covercrypt::default();
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
            encrypted_header.serialize().unwrap().len(),
        );
    }

    for (i, ap) in user_access_policies.iter().enumerate() {
        let usk = cover_crypt
            .generate_user_secret_key(&msk, ap, &policy)
            .unwrap();
        println!(
            "{} usk partition(s): {} bytes",
            i + 1,
            usk.serialize().unwrap().len(),
        );
    }

    {
        let mut group = c.benchmark_group("Key serialization");
        group.bench_function("MSK", |b| {
            b.iter(|| msk.serialize().expect("cannot serialize msk"));
        });
        group.bench_function("MPK", |b| {
            b.iter(|| mpk.serialize().expect("cannot serialize mpk"));
        });

        let usk = cover_crypt
            .generate_user_secret_key(&msk, &user_access_policies[0], &policy)
            .unwrap();
        group.bench_function("USK 1 partition", |b| {
            b.iter(|| usk.serialize().expect("cannot serialize usk"));
        });
    }

    let mut group = c.benchmark_group("Header serialization");
    for (n_partition, access_policy) in access_policies.iter().enumerate() {
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, access_policy, None, None)
                .expect("cannot encrypt header 1");
        group.bench_function(&format!("{} partition(s)", n_partition + 1), |b| {
            b.iter(|| {
                encrypted_header.serialize().unwrap_or_else(|_| {
                    panic!(
                        "cannot serialize header for {} partition(s)",
                        n_partition + 1
                    )
                })
            });
        });
    }
}

// fn bench_header_encryption(c: &mut Criterion) {
//     let policy = policy().expect("cannot generate policy");
//     let (_, access_policies) = get_access_policies();
//     let cover_crypt = Covercrypt::default();
//     let (_, mpk) = cover_crypt
//         .generate_master_keys(&policy)
//         .expect("cannot generate master keys");

//     let mut group = c.benchmark_group("Header encryption");
//     for (n_partition, access_policy) in access_policies.iter().enumerate() {
//         group.bench_function(
//             &format!("{} partition(s), 1 access", n_partition + 1),
//             |b| {
//                 b.iter(|| {
//                     EncryptedHeader::generate(
//                         &cover_crypt,
//                         &policy,
//                         &mpk,
//                         access_policy,
//                         None,
//                         None,
//                     )
//                     .unwrap_or_else(|_| {
//                         panic!("cannot encrypt header for {} partition(s)", n_partition + 1)
//                     })
//                 });
//             },
//         );
//     }
// }

fn bench_header_decryption(c: &mut Criterion) {
    let policy = policy().expect("cannot generate policy");
    let (user_access_policies, access_policies) = get_access_policies();
    let cover_crypt = Covercrypt::default();
    let (msk, mpk) = cover_crypt
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");
    let mut group = c.benchmark_group("Header encryption and decryption");
    for user_access_policy in user_access_policies.iter() {
        for access_policy in access_policies.iter() {
            let usk = cover_crypt
                .generate_user_secret_key(&msk, user_access_policy, &policy)
                .expect("cannot generate user private key");
            let (_, enc) = cover_crypt.encaps(&policy, &mpk, access_policy).unwrap();
            group.bench_function(
                format!(
                    "ciphertexts with {} partition(s), usk with {} partitions",
                    enc.encs.len(),
                    usk.subkeys.len()
                ),
                |b| b.iter(|| cover_crypt.decaps(&usk, &enc).unwrap()),
            );
        }
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(5000);
    targets =
    bench_header_decryption,
        // bench_policy_editing,
        // bench_header_encryption,
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
