use cosmian_cover_crypt::{
    AccessPolicy, Error, MasterSecretKey, PublicKey, QualifiedAttribute, XEnc,
    api::Covercrypt, omega_size, traits::KemAc,
};
use cosmian_crypto_core::{
    CsRng,
    bytes_ser_de::Serializable,
    reexport::rand_core::{CryptoRngCore, SeedableRng},
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

fn cc_keygen(
    rng: &mut impl CryptoRngCore,
    complete: bool,
) -> Result<(MasterSecretKey, PublicKey), Error> {
    let (mut msk, _) =
        cosmian_cover_crypt::test_utils::cc_keygen(rng, complete)?;
    // Remove the `SEC::MED` attribute to keep using the same access policy as
    // before.
    Covercrypt::edit_msk(&mut msk, |access_structure| {
        access_structure.del_attribute(&QualifiedAttribute::new(
            "SEC".to_owned(),
            "MED".to_owned(),
        ))
    })?;
    let pk = Covercrypt::gen_pk(&msk, None)?;
    Ok((msk, pk))
}

const C_ENC_APS: [(&str, usize); 5] = [
    ("SEC::LOW && CTR::EN && (DPT::MKG) ", 1),
    ("SEC::LOW && CTR::EN && (DPT::MKG || DPT::FIN) ", 2),
    (
        "SEC::LOW && CTR::EN && (DPT::MKG || DPT::FIN || DPT::DEV) ",
        3,
    ),
    (
        "SEC::LOW && CTR::EN && (DPT::MKG || DPT::FIN || DPT::DEV || DPT::HR) ",
        4,
    ),
    (
        "SEC::LOW && CTR::EN && (DPT::MKG || DPT::FIN || DPT::DEV || DPT::HR || DPT::RD) ",
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
    ("SEC::TOP && CTR::EN && (DPT::MKG) ", 1),
    ("SEC::TOP && CTR::EN && (DPT::MKG || DPT::FIN) ", 2),
    (
        "SEC::TOP && CTR::EN && (DPT::MKG || DPT::FIN || DPT::DEV) ",
        3,
    ),
    (
        "SEC::TOP && CTR::EN && (DPT::MKG || DPT::FIN || DPT::DEV || DPT::HR) ",
        4,
    ),
    (
        "SEC::TOP && CTR::EN && (DPT::MKG || DPT::FIN || DPT::DEV || DPT::HR || DPT::RD) ",
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
    ($rng:ident, $pk:ident, $ap:ident, $cnt:ident) => {{
        let (k, enc) = Covercrypt::encaps(
            &mut $rng,
            &$pk,
            &AccessPolicy::parse($ap).unwrap(),
        )
        .unwrap();
        assert_eq!(enc.count(), $cnt);
        (k, enc)
    }};
}

macro_rules! gen_usk {
    ($rng:ident, $msk:ident, $ap:ident, $cnt:ident) => {{
        let usk = Covercrypt::gen_usk(
            &mut $rng,
            &mut $msk,
            AccessPolicy::parse($ap).unwrap(),
        )
        .unwrap();
        assert_eq!(usk.count(), $cnt);
        usk
    }};
}

fn bench_serialization(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let (msk, pk) = cc_keygen(&mut rng, true).unwrap();

    {
        let mut group = c.benchmark_group(format!(
            "MSK serialization ({} rights)",
            omega_size(msk.access_structure()).unwrap()
        ));
        group.bench_function("serialize", |b| {
            b.iter_batched(
                || {},
                |()| msk.serialize().unwrap(),
                BatchSize::SmallInput,
            )
        });
        let bytes = msk.serialize().unwrap();
        group.bench_function("deserialize", |b| {
            b.iter_batched(
                || {},
                |()| MasterSecretKey::deserialize(&bytes).unwrap(),
                BatchSize::SmallInput,
            )
        });
    }

    {
        let mut group = c.benchmark_group(format!(
            "PK serialization ({} rights)",
            omega_size(pk.access_structure()).unwrap()
        ));
        group.bench_function("serialize", |b| {
            b.iter_batched(
                || {},
                |()| pk.serialize().unwrap(),
                BatchSize::SmallInput,
            )
        });
        let bytes = pk.serialize().unwrap();
        group.bench_function("deserialize", |b| {
            b.iter_batched(
                || {},
                |()| PublicKey::deserialize(&bytes).unwrap(),
                BatchSize::SmallInput,
            )
        });
    }

    {
        let mut rng = CsRng::from_entropy();
        let mut group = c.benchmark_group("Hybridized encapsulation");
        for (enc_ap, cnt_enc) in H_ENC_APS {
            let (_, enc) = gen_enc!(rng, pk, enc_ap, cnt_enc);
            group.bench_function(
                format!("serialize ({} rights)", cnt_enc),
                |b| {
                    b.iter_batched(
                        || {},
                        |()| enc.serialize().unwrap(),
                        BatchSize::SmallInput,
                    )
                },
            );
            let bytes = enc.serialize().unwrap();
            group.bench_function(
                format!("deserialize ({} rights)", cnt_enc),
                |b| {
                    b.iter_batched(
                        || {},
                        |()| XEnc::deserialize(&bytes).unwrap(),
                        BatchSize::SmallInput,
                    )
                },
            );
        }
    }
}

fn bench_usk_keygen(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let (msk, _) = cc_keygen(&mut rng, true).unwrap();

    {
        let mut group = c.benchmark_group("USK key generation");
        for (usk_ap, usk_cnt) in H_USK_APS {
            let uap = AccessPolicy::parse(usk_ap).unwrap();
            group.bench_function(format!("{:?} secrets", usk_cnt), |b| {
                b.iter_batched(
                    || {
                        MasterSecretKey::deserialize(&msk.serialize().unwrap())
                            .unwrap()
                    },
                    |mut msk| {
                        Covercrypt::gen_usk(&mut rng, &mut msk, uap.clone())
                            .unwrap()
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
}

fn bench_pre_quantum_encapsulation(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let (_, pk) = cc_keygen(&mut rng, true).unwrap();

    {
        let mut group = c.benchmark_group("Pre-quantum encapsulation");
        for (enc_ap, cnt_enc) in C_ENC_APS {
            let _ = gen_enc!(rng, pk, enc_ap, cnt_enc);
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            group.bench_function(format!("{:?} encs", cnt_enc), |b| {
                b.iter(|| Covercrypt::encaps(&mut rng, &pk, &eap).unwrap())
            });
        }
    }
}

fn bench_pre_quantum_decapsulation(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let (mut msk, pk) = cc_keygen(&mut rng, true).unwrap();

    {
        let mut group = c.benchmark_group("Decapsulation");
        for (enc_ap, cnt_enc) in C_ENC_APS {
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            for (usk_ap, cnt_secret) in C_USK_APS {
                let uap = AccessPolicy::parse(usk_ap).unwrap();

                let usk = gen_usk!(rng, msk, usk_ap, cnt_secret);
                let (_, enc) = gen_enc!(rng, pk, enc_ap, cnt_enc);
                assert_eq!(
                    None,
                    Covercrypt::decaps(&mut rng, &usk, &enc).unwrap()
                );

                group.bench_function(
                    format!("{:?} encs vs {:?} secrets", cnt_enc, cnt_secret),
                    |b| {
                        b.iter_batched(
                            || {
                                let mut rng = CsRng::from_entropy();

                                (
                                    Covercrypt::gen_usk(
                                        &mut rng,
                                        &mut msk,
                                        uap.clone(),
                                    )
                                    .unwrap(),
                                    Covercrypt::encaps(&mut rng, &pk, &eap)
                                        .unwrap(),
                                    rng,
                                )
                            },
                            |(usk, (_, enc), mut rng)| {
                                Covercrypt::decaps(&mut rng, &usk, &enc)
                                    .unwrap()
                            },
                            BatchSize::SmallInput,
                        )
                    },
                );
            }
        }
    }
}

fn bench_hybridized_encapsulation(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let (_, pk) = cc_keygen(&mut rng, true).unwrap();

    {
        let mut group = c.benchmark_group("Hybridized encapsulation");
        for (enc_ap, cnt_enc) in H_ENC_APS {
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            let _ = gen_enc!(rng, pk, enc_ap, cnt_enc);
            group.bench_function(format!("{:?} encs", cnt_enc), |b| {
                b.iter(|| Covercrypt::encaps(&mut rng, &pk, &eap).unwrap())
            });
        }
    }
}

fn bench_hybridized_decapsulation(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let (mut msk, pk) = cc_keygen(&mut rng, true).unwrap();

    {
        let mut group = c.benchmark_group("Hybridized Decapsulation");
        for (enc_ap, enc_cnt) in H_ENC_APS {
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            for (usk_ap, usk_cnt) in H_USK_APS {
                let uap = AccessPolicy::parse(usk_ap).unwrap();
                let usk = gen_usk!(rng, msk, usk_ap, usk_cnt);
                let (_, enc) = gen_enc!(rng, pk, enc_ap, enc_cnt);
                assert_eq!(
                    None,
                    Covercrypt::decaps(&mut rng, &usk, &enc).unwrap()
                );

                group.bench_function(
                    format!(
                        "{:?} encapsulations vs {:?} secrets",
                        enc_cnt, usk_cnt
                    ),
                    |b| {
                        b.iter_batched(
                            || {
                                let mut rng = CsRng::from_entropy();
                                (
                                    Covercrypt::gen_usk(
                                        &mut rng,
                                        &mut msk,
                                        uap.clone(),
                                    )
                                    .unwrap(),
                                    Covercrypt::encaps(&mut rng, &pk, &eap)
                                        .unwrap(),
                                    rng,
                                )
                            },
                            |(usk, (_, enc), mut rng)| {
                                Covercrypt::decaps(&mut rng, &usk, &enc)
                                    .unwrap()
                            },
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
    targets =
    bench_serialization,
    bench_usk_keygen,
    bench_pre_quantum_encapsulation,
    bench_pre_quantum_decapsulation,
    bench_hybridized_encapsulation,
    bench_hybridized_decapsulation
);

criterion_main!(benches);
