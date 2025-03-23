#![allow(non_snake_case)]

use cosmian_cover_crypt::{
    api::Covercrypt, core::{kem::MlKem, nike::{r25519::{R25519Point, R25519Scalar}, ElGamal}, Encapsulations}, traits::{Kem, KemAc, Nike, Sampling}, AccessPolicy, AccessStructure, EncryptionHint, Error, MasterPublicKey, MasterSecretKey
};
use cosmian_crypto_core::{
    bytes_ser_de::Serializable, reexport::rand_core::SeedableRng, shuffle, CsRng, Secret,
};
use criterion::{criterion_group, criterion_main, Criterion};
use tiny_keccak::{Hasher, Sha3};

pub fn gen_structure(policy: &mut AccessStructure, complete: bool) -> Result<(), Error> {
    policy.add_hierarchy("SEC".to_string())?;

    policy.add_attribute(
        cosmian_cover_crypt::abe_policy::QualifiedAttribute {
            dimension: "SEC".to_string(),
            name: "LOW".to_string(),
        },
        EncryptionHint::Hybridized,
        None,
    )?;
    policy.add_attribute(
        cosmian_cover_crypt::abe_policy::QualifiedAttribute {
            dimension: "SEC".to_string(),
            name: "TOP".to_string(),
        },
        EncryptionHint::Hybridized,
        Some("LOW"),
    )?;

    policy.add_anarchy("DPT".to_string())?;
    [
        ("RD", EncryptionHint::Hybridized),
        ("HR", EncryptionHint::Hybridized),
        ("MKG", EncryptionHint::Hybridized),
        ("FIN", EncryptionHint::Hybridized),
        ("DEV", EncryptionHint::Hybridized),
    ]
    .into_iter()
    .try_for_each(|(attribute, hint)| {
        policy.add_attribute(
            cosmian_cover_crypt::abe_policy::QualifiedAttribute {
                dimension: "DPT".to_string(),
                name: attribute.to_string(),
            },
            hint,
            None,
        )
    })?;

    if complete {
        policy.add_anarchy("CTR".to_string())?;
        [
            ("EN", EncryptionHint::Hybridized),
            ("DE", EncryptionHint::Hybridized),
            ("IT", EncryptionHint::Hybridized),
            ("FR", EncryptionHint::Hybridized),
            ("SP", EncryptionHint::Hybridized),
        ]
        .into_iter()
        .try_for_each(|(attribute, hint)| {
            policy.add_attribute(
                cosmian_cover_crypt::abe_policy::QualifiedAttribute {
                    dimension: "CTR".to_string(),
                    name: attribute.to_string(),
                },
                hint,
                None,
            )
        })?;
    }

    Ok(())
}

pub fn cc_keygen(
    cc: &Covercrypt,
    complete: bool,
) -> Result<(MasterSecretKey, MasterPublicKey), Error> {
    let (mut msk, _) = cc.setup()?;
    gen_structure(&mut msk.access_structure, complete)?;
    let mpk = cc.update_msk(&mut msk)?;
    Ok((msk, mpk))
}

const H_ENC_APS: [(&str, usize); 5] = [
    ("SEC::TOP && (DPT::MKG) ", 1),
    ("SEC::TOP && (DPT::MKG || DPT::FIN) ", 2),
    ("SEC::TOP && (DPT::MKG || DPT::FIN || DPT::DEV) ", 3),
    (
        "SEC::TOP && (DPT::MKG || DPT::FIN || DPT::DEV || DPT::HR) ",
        4,
    ),
    (
        "SEC::TOP && (DPT::MKG || DPT::FIN || DPT::DEV || DPT::HR || DPT::RD) ",
        5,
    ),
];

const H_USK_APS: [(&str, usize); 5] = [
    ("SEC::TOP && CTR::FR && DPT::MKG", 12),
    ("SEC::TOP && CTR::FR && (DPT::MKG || DPT::FIN)", 18),
    (
        "SEC::TOP && CTR::FR && (DPT::MKG || DPT::FIN || DPT::DEV)",
        24,
    ),
    (
        "SEC::TOP && CTR::FR && (DPT::MKG || DPT::FIN || DPT::DEV || DPT::HR)",
        30,
    ),
    (
        "SEC::TOP && CTR::FR && (DPT::MKG || DPT::FIN || DPT::DEV || DPT::HR || DPT::RD)",
        36,
    ),
];

macro_rules! gen_enc {
    ($cc:ident, $mpk:ident, $ap:ident, $cnt:ident) => {{
        let (k, enc) = $cc
            .encaps(&$mpk, &AccessPolicy::parse($ap).unwrap())
            .unwrap();
        assert_eq!(enc.count(), $cnt);
        (k, enc)
    }};
}

macro_rules! gen_usk {
    ($cc:ident, $msk:ident, $ap:ident, $cnt:ident) => {{
        let usk = $cc
            .generate_user_secret_key(&mut $msk, &AccessPolicy::parse($ap).unwrap())
            .unwrap();
        assert_eq!(usk.count(), $cnt);
        usk
    }};
}

fn bench_hybridized_encapsulation(c: &mut Criterion) {
    let cc = Covercrypt::default();
    let (_, mpk) = cc_keygen(&cc, true).unwrap();

    {
        let mut group = c.benchmark_group("Hybridized encapsulation");
        for (enc_ap, cnt_enc) in H_ENC_APS {
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            let _ = gen_enc!(cc, mpk, enc_ap, cnt_enc);
            group.bench_function(format!("{:?} encs", cnt_enc), |b| {
                b.iter(|| cc.encaps(&mpk, &eap).unwrap())
            });
        }
    }
}

fn bench_hybridized_decapsulation(c: &mut Criterion) {
    let cc = Covercrypt::default();
    let (mut msk, mpk) = cc_keygen(&cc, true).unwrap();

    {
        let mut group = c.benchmark_group("Hybridized Decapsulation");
        for (enc_ap, enc_cnt) in H_ENC_APS {
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            for (usk_ap, usk_cnt) in H_USK_APS {
                // Generate USK and encapsulation for later use in bench.
                let uap = AccessPolicy::parse(usk_ap).unwrap();
                let usk = gen_usk!(cc, msk, usk_ap, usk_cnt);
                let (k, enc) = gen_enc!(cc, mpk, enc_ap, enc_cnt);
                assert_eq!(Some(k), cc.decaps(&usk, &enc).unwrap());

                // Count the number of rights in common.
                let usk_rights = msk.access_structure.ap_to_usk_rights(&uap).unwrap();
                let enc_rights = msk.access_structure.ap_to_enc_rights(&eap).unwrap();
                let common_rights = usk_rights.intersection(&enc_rights).count();

                group.bench_function(
                    format!(
                        "{} encapsulations vs {} secrets, {} rights in common",
                        enc.count(),
                        usk.count(),
                        common_rights
                    ),
                    |b| b.iter(|| cc.decaps(&usk, &enc).unwrap()),
                );
            }
        }
    }
}

fn bench_elgamal(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let sk = R25519Scalar::random(&mut rng);
    let (_, pt) = ElGamal::keygen(&mut rng).unwrap();
    let mut group = c.benchmark_group("ElGamal");
    group.bench_function("Session Key", |b| b.iter(|| {
        ElGamal::session_key(&sk, &pt).unwrap();
    }));
}

fn bench_kyber(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let (dk, ek) = MlKem::keygen(&mut rng).unwrap();
    let (_, E) = MlKem::enc(&ek, &mut rng).unwrap();
    let mut group = c.benchmark_group("Kyber");
    group.bench_function("Encapsulation",|b| b.iter(|| {
        MlKem::enc(&ek, &mut rng).unwrap()
    }));
    group.bench_function("Decapsulation",|b| b.iter(|| {
        MlKem::dec(&dk, &E).unwrap()
    }));
}

fn bench_decapsulation_constant_cost(c: &mut Criterion) {
    pub const SHARED_SECRET_LENGTH: usize = 32;

    let mut rng = CsRng::from_entropy();
    let cc = Covercrypt::default();
    let (mut msk, mpk) = cc_keygen(&cc, true).unwrap();

    let (enc_ap, enc_cnt) = H_ENC_APS[0];
    let (usk_ap, usk_cnt) = H_USK_APS[0];

    let usk = gen_usk!(cc, msk, usk_ap, usk_cnt);
    let (_, enc) = gen_enc!(cc, mpk, enc_ap, enc_cnt);

    c.bench_function("Decapsulation constant cost", |b| {
        b.iter(|| {
            let Encapsulations::HEncs(encs) = &enc.encapsulations else {
                panic!("not an hybridized encapsulation")
            };

            // A = ⊙ _i (α_i. c_i)
            let _A = usk
                .id
                .iter()
                .zip(enc.c.iter())
                .map(|(marker, trap)| trap * marker)
                .sum::<R25519Point>();

            let T = {
                let mut hasher = Sha3::v256();
                let mut T = Secret::<SHARED_SECRET_LENGTH>::new();
                enc.c
                    .iter()
                    .try_for_each(|ck| {
                        hasher.update(&ck.serialize()?);
                        Ok::<_, Error>(())
                    })
                    .unwrap();
                encs.iter()
                    .try_for_each(|(E, _)| {
                        hasher.update(&E.serialize()?);
                        Ok::<_, Error>(())
                    })
                    .unwrap();
                hasher.finalize(&mut *T);
                T
            };

            let _U = {
                let mut U = Secret::<SHARED_SECRET_LENGTH>::new();
                let mut hasher = Sha3::v256();
                hasher.update(&*T);
                encs.iter().for_each(|(_, F)| hasher.update(F));
                hasher.finalize(&mut *U);
                U
            };

            // Shuffle encapsulation to counter timing attacks attempting to determine
            // which right was used to open an encapsulation.
            let mut encs = encs.iter().collect::<Vec<_>>();
            shuffle(&mut encs, &mut rng);
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(5000);
    targets =
    bench_elgamal,
    bench_kyber,
    bench_decapsulation_constant_cost,
    bench_hybridized_decapsulation,
    bench_hybridized_encapsulation,
);

criterion_main!(benches);
