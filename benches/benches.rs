#![allow(non_snake_case)]

use cosmian_cover_crypt::{
    api::Covercrypt, cc_keygen, core::{kem::MlKem, nike::{r25519::{R25519Point, R25519Scalar}, ElGamal}, Encapsulations}, traits::{Kem, KemAc, Nike, Sampling}, AccessPolicy, Error,
};
use cosmian_crypto_core::{
    bytes_ser_de::Serializable, reexport::rand_core::SeedableRng, shuffle, CsRng, Secret,
};
use criterion::{criterion_group, criterion_main, Criterion};
use tiny_keccak::{Hasher, Sha3};

const C_ENC_APS: [(&str, usize); 5] = [
    ("SEC::LOW && (DPT::MKG) ", 1),
    ("SEC::LOW && (DPT::MKG || DPT::FIN) ", 2),
    ("SEC::LOW && (DPT::MKG || DPT::FIN || DPT::DEV) ", 3),
    (
        "SEC::LOW && (DPT::MKG || DPT::FIN || DPT::DEV || DPT::HR) ",
        4,
    ),
    (
        "SEC::LOW && (DPT::MKG || DPT::FIN || DPT::DEV || DPT::HR || DPT::RD) ",
        5,
    ),
];

const C_USK_APS: [(&str, usize); 5] = [
    ("SEC::LOW && CTR::FR && DPT::MKG", 8),
    ("SEC::LOW && CTR::FR && (DPT::MKG || DPT::FIN)", 12),
    (
        "SEC::LOW && CTR::FR && (DPT::MKG || DPT::FIN || DPT::DEV)",
        16,
    ),
    (
        "SEC::LOW && CTR::FR && (DPT::MKG || DPT::FIN || DPT::DEV || DPT::HR)",
        20,
    ),
    (
        "SEC::LOW && CTR::FR && (DPT::MKG || DPT::FIN || DPT::DEV || DPT::HR || DPT::RD)",
        24,
    ),
];

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

fn bench_classical_encapsulation(c: &mut Criterion) {
    let cc = Covercrypt::default();
    let (_, mpk) = cc_keygen(&cc, true).unwrap();

    {
        let mut group = c.benchmark_group("Classic encapsulation");
        for (enc_ap, cnt_enc) in C_ENC_APS {
            let _ = gen_enc!(cc, mpk, enc_ap, cnt_enc);
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            group.bench_function(format!("{:?} encs", cnt_enc), |b| {
                b.iter(|| cc.encaps(&mpk, &eap).unwrap())
            });
        }
    }
}

fn bench_classical_decapsulation(c: &mut Criterion) {
    let cc = Covercrypt::default();
    let (mut msk, mpk) = cc_keygen(&cc, true).unwrap();

    {
        let mut group = c.benchmark_group("Decapsulation");
        for (enc_ap, enc_cnt) in C_ENC_APS {
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            for (usk_ap, usk_cnt) in C_USK_APS {
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
    c.bench_function("ElGamal", |b| b.iter(|| {
        ElGamal::session_key(&sk, &pt).unwrap();
    }));
}

fn bench_kyber(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let (dk, ek) = MlKem::keygen(&mut rng).unwrap();
    let (_, E) = MlKem::enc(&ek, &mut rng).unwrap();
    c.bench_function("Kyber",|b| b.iter(|| {
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
    bench_classical_decapsulation,
    bench_classical_encapsulation,
);

criterion_main!(benches);
