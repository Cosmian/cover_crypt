use cosmian_cover_crypt::{api::Covercrypt, cc_keygen, traits::KemAc, AccessPolicy};
use criterion::{criterion_group, criterion_main, Criterion};

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

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(5000);
    targets =
    bench_hybridized_decapsulation,
    bench_hybridized_encapsulation,
    bench_classical_decapsulation,
    bench_classical_encapsulation,
);

criterion_main!(benches);
