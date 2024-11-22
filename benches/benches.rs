#![allow(dead_code)]

use cosmian_cover_crypt::{api::Covercrypt, cc_keygen, traits::KemAc, AccessPolicy};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

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

fn bench_encapsulation(c: &mut Criterion) {
    let cc = Covercrypt::default();

    let (mut msk, mpk) = cc_keygen(&cc, true).unwrap();

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

    {
        let mut group = c.benchmark_group("Decapsulation");
        for (enc_ap, cnt_enc) in C_ENC_APS {
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            for (usk_ap, cnt_secret) in C_USK_APS {
                let uap = AccessPolicy::parse(usk_ap).unwrap();

                let usk = gen_usk!(cc, msk, usk_ap, cnt_secret);
                let (k, enc) = gen_enc!(cc, mpk, enc_ap, cnt_enc);
                assert_eq!(Some(k), cc.decaps(&usk, &enc).unwrap());

                group.bench_function(
                    format!("{:?} encs vs {:?} secrets", cnt_enc, cnt_secret),
                    |b| {
                        b.iter_batched(
                            || {
                                (
                                    cc.generate_user_secret_key(&mut msk, &uap).unwrap(),
                                    cc.encaps(&mpk, &eap).unwrap(),
                                )
                            },
                            |(usk, (_, enc))| cc.decaps(&usk, &enc).unwrap(),
                            BatchSize::SmallInput,
                        )
                    },
                );
            }
        }
    }

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

    // Note that there should be no more attempt to decapsulate the encapsulation than is performed
    // for classic ones since the classic secrets should be ignored (thus only a test and
    // negligible in front of the decapsulation time of hybridized secrets).
    {
        let mut group = c.benchmark_group("Hybridiezd Decapsulation");
        for (enc_ap, cnt_enc) in H_ENC_APS {
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            for (usk_ap, cnt_secret) in H_USK_APS {
                let uap = AccessPolicy::parse(usk_ap).unwrap();

                let usk = gen_usk!(cc, msk, usk_ap, cnt_secret);
                let (k, enc) = gen_enc!(cc, mpk, enc_ap, cnt_enc);
                assert_eq!(Some(k), cc.decaps(&usk, &enc).unwrap());

                group.bench_function(
                    format!("{:?} encs vs {:?} secrets", cnt_enc, cnt_secret),
                    |b| {
                        b.iter_batched(
                            || {
                                (
                                    cc.generate_user_secret_key(&mut msk, &uap).unwrap(),
                                    cc.encaps(&mpk, &eap).unwrap(),
                                )
                            },
                            |(usk, (_, enc))| cc.decaps(&usk, &enc).unwrap(),
                            BatchSize::SmallInput,
                        )
                    },
                );
            }
        }
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(5000);
    targets = bench_encapsulation,
);

criterion_main!(benches);
