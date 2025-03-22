use cosmian_cover_crypt::{
    Covercrypt, Error,
    abe_policy::{AccessPolicy, DimensionBuilder, EncryptionHint, Policy},
    core::SYM_KEY_LENGTH,
};
use cosmian_crypto_core::{
    CsRng, FixedSizeCBytes, R25519PrivateKey, R25519PublicKey, kdf256,
    reexport::rand_core::{RngCore, SeedableRng},
};
use criterion::{Criterion, criterion_group, criterion_main};
use pqc_kyber::{
    KYBER_INDCPA_BYTES, KYBER_INDCPA_PUBLICKEYBYTES, KYBER_INDCPA_SECRETKEYBYTES, KYBER_SYMBYTES,
    indcpa::{indcpa_dec, indcpa_enc, indcpa_keypair},
};
use zeroize::Zeroizing;

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

fn xor_in_place<const LENGTH: usize>(a: &mut [u8; LENGTH], b: &[u8; LENGTH]) {
    for (a_i, b_i) in a.iter_mut().zip(b.iter()) {
        *a_i ^= b_i;
    }
}

fn bench_hashing(c: &mut Criterion) {
    const TAG_LENGTH: usize = 16;
    const KEY_GEN_INFO: &[u8] = b"key generation info";

    let mut rng = CsRng::from_entropy();
    let a = R25519PrivateKey::new(&mut rng);
    let g_a = R25519PublicKey::from(&a);
    let mut e = [0; SYM_KEY_LENGTH];
    rng.fill_bytes(&mut e);

    c.bench_function("Hashing", |b| b.iter(||
        {
            let mut seed = Zeroizing::new([0; SYM_KEY_LENGTH]);
            kdf256!(&mut *seed, &g_a.to_bytes());
            xor_in_place(&mut seed, &e);
            let mut hasher = cosmian_cover_crypt::core::macros::Shake::v256();
            <cosmian_cover_crypt::core::macros::Shake as cosmian_cover_crypt::core::macros::Hasher>::update(&mut hasher,&*seed);
            <cosmian_cover_crypt::core::macros::Shake as cosmian_cover_crypt::core::macros::Hasher>::update(&mut hasher,KEY_GEN_INFO);
            let mut tag = [0; TAG_LENGTH];
            let mut key =
                cosmian_cover_crypt::core::macros::SymmetricKey::try_from_bytes([0; SYM_KEY_LENGTH])
                    .unwrap();
            <cosmian_cover_crypt::core::macros::Shake as cosmian_cover_crypt::core::macros::Xof>::squeeze(&mut hasher, &mut tag);
            <cosmian_cover_crypt::core::macros::Shake as cosmian_cover_crypt::core::macros::Hasher>::finalize(hasher, &mut *key);
            (tag, key)
        }
    ));
}

fn bench_elgamal(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let a = R25519PrivateKey::new(&mut rng);
    let b = R25519PrivateKey::new(&mut rng);
    let g_a = R25519PublicKey::from(&a);
    c.bench_function("ElGamal", |bencher| bencher.iter(|| &g_a * &b));
}

fn bench_kyber(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let (mut sk, mut pk) = (
        [0; KYBER_INDCPA_SECRETKEYBYTES],
        [0; KYBER_INDCPA_PUBLICKEYBYTES],
    );
    indcpa_keypair(&mut pk, &mut sk, None, &mut rng);
    let mut enc = [0; KYBER_INDCPA_BYTES];
    let mut coin = Zeroizing::new([0; KYBER_SYMBYTES]);
    rng.fill_bytes(&mut *coin);
    indcpa_enc(&mut enc, &sk, &pk, &*coin);
    c.bench_function("Kyber", |bencher| {
        bencher.iter(|| {
            let mut ptx = [0; SYM_KEY_LENGTH];
            indcpa_dec(&mut ptx, &enc, &sk);
        })
    });
}

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
    bench_hashing,
    bench_elgamal,
    bench_kyber,
    bench_header_decryption,
);

criterion_main!(benches);
