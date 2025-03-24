use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::{reexport::rand_core::SeedableRng, Aes256Gcm, CsRng};

use crate::{
    abe_policy::{AccessPolicy, AttributeStatus, EncryptionHint, Right},
    api::Covercrypt,
    core::primitives::{decaps, encaps, refresh, rekey, update_msk},
    test_utils::cc_keygen,
    traits::{KemAc, PkeAc},
};

use super::{
    primitives::{setup, usk_keygen},
    MIN_TRACING_LEVEL,
};

/// This test asserts that it is possible to encapsulate a key for a given
/// coordinate and that different users which key is associated with this
/// coordinate can open the resulting encapsulation.
#[test]
fn test_encapsulation() {
    let mut rng = CsRng::from_entropy();
    let other_coordinate = Right::random(&mut rng);
    let target_coordinate = Right::random(&mut rng);

    let mut msk = setup(MIN_TRACING_LEVEL, &mut rng).unwrap();
    update_msk(
        &mut rng,
        &mut msk,
        HashMap::from_iter([
            (
                other_coordinate.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
            (
                target_coordinate.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
        ]),
    )
    .unwrap();
    let mpk = msk.mpk().unwrap();

    let (key, enc) = encaps(
        &mut rng,
        &mpk,
        &HashSet::from_iter([target_coordinate.clone()]),
    )
    .unwrap();
    assert_eq!(enc.count(), 1);

    for _ in 0..3 {
        let usk = usk_keygen(
            &mut rng,
            &mut msk,
            HashSet::from_iter([target_coordinate.clone()]),
        )
        .unwrap();
        assert_eq!(usk.secrets.len(), 1);
        assert_eq!(Some(&key), decaps(&mut rng, &usk, &enc).unwrap().as_ref());
    }

    let usk = usk_keygen(
        &mut rng,
        &mut msk,
        HashSet::from_iter([other_coordinate.clone()]),
    )
    .unwrap();
    assert_eq!(usk.secrets.len(), 1);
    assert_eq!(None, decaps(&mut rng, &usk, &enc).unwrap().as_ref());
}

/// This test verifies that the correct number of keys is added/removed upon
/// updating the MSK. It also check that the correct number of coordinate keys
/// are given to the MPK, and removed upon deprecation.
#[test]
fn test_update() {
    let mut rng = CsRng::from_entropy();

    let mut msk = setup(MIN_TRACING_LEVEL, &mut rng).unwrap();
    assert_eq!(msk.tsk.users.len(), 0);
    assert_eq!(msk.tsk.tracing_level(), MIN_TRACING_LEVEL);
    assert_eq!(msk.secrets.len(), 0);

    let mpk = msk.mpk().unwrap();
    assert_eq!(mpk.tpk.tracing_level(), MIN_TRACING_LEVEL);
    assert_eq!(mpk.encryption_keys.len(), 0);

    // Add 30 new random coordinates and verifies the correct number of
    // coordinate keys is added to the MSK (and the MPK).
    let mut coordinates = (0..30)
        .map(|_| {
            (
                Right::random(&mut rng),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            )
        })
        .collect::<HashMap<_, _>>();
    update_msk(&mut rng, &mut msk, coordinates.clone()).unwrap();
    assert_eq!(msk.secrets.len(), 30);

    let mpk = msk.mpk().unwrap();
    assert_eq!(mpk.encryption_keys.len(), 30);

    // Deprecate half coordinates.
    //
    // Be careful to iterate on the original structure not to change the
    // iteration order. Otherwise the next test may fail.
    coordinates
        .iter_mut()
        .enumerate()
        .for_each(|(i, (_, (_, status)))| {
            if i % 2 == 0 {
                *status = AttributeStatus::DecryptOnly;
            }
        });
    update_msk(&mut rng, &mut msk, coordinates.clone()).unwrap();
    assert_eq!(msk.secrets.len(), 30);
    let mpk = msk.mpk().unwrap();
    assert_eq!(mpk.encryption_keys.len(), 15);

    // Keep only 10 coordinates.
    let coordinates = coordinates.into_iter().take(10).collect::<HashMap<_, _>>();
    update_msk(&mut rng, &mut msk, coordinates).unwrap();
    assert_eq!(msk.secrets.len(), 10);
    let mpk = msk.mpk().unwrap();
    assert_eq!(mpk.encryption_keys.len(), 5);
}

/// This test asserts that re-keyed coordinates allow creating encapsulations
/// using the new keys: old USK cannot open the new ones and new USK cannot open
/// the old ones.
#[test]
fn test_rekey() {
    let mut rng = CsRng::from_entropy();
    let coordinate_1 = Right::random(&mut rng);
    let coordinate_2 = Right::random(&mut rng);
    let subspace_1 = HashSet::from_iter([coordinate_1.clone()]);
    let subspace_2 = HashSet::from_iter([coordinate_2.clone()]);
    let universe = HashSet::from_iter([coordinate_1.clone(), coordinate_2.clone()]);

    let mut msk = setup(MIN_TRACING_LEVEL, &mut rng).unwrap();
    update_msk(
        &mut rng,
        &mut msk,
        HashMap::from_iter([
            (
                coordinate_1.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
            (
                coordinate_2.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
        ]),
    )
    .unwrap();
    let mpk = msk.mpk().unwrap();
    let mut usk_1 = usk_keygen(&mut rng, &mut msk, subspace_1.clone()).unwrap();
    let mut usk_2 = usk_keygen(&mut rng, &mut msk, subspace_2.clone()).unwrap();

    let (old_key_1, old_enc_1) = encaps(&mut rng, &mpk, &subspace_1).unwrap();
    let (old_key_2, old_enc_2) = encaps(&mut rng, &mpk, &subspace_2).unwrap();

    // Old USK can open encapsulations associated with their coordinate.
    assert_eq!(
        Some(&old_key_1),
        decaps(&mut rng, &usk_1, &old_enc_1).unwrap().as_ref()
    );
    assert_eq!(None, decaps(&mut rng, &usk_1, &old_enc_2).unwrap());
    assert_eq!(
        Some(old_key_2),
        decaps(&mut rng, &usk_2, &old_enc_2).unwrap()
    );
    assert_eq!(None, decaps(&mut rng, &usk_2, &old_enc_1).unwrap());

    // Re-key all space coordinates.
    rekey(&mut rng, &mut msk, universe).unwrap();
    let mpk = msk.mpk().unwrap();

    let (new_key_1, new_enc_1) = encaps(&mut rng, &mpk, &subspace_1).unwrap();
    let (new_key_2, new_enc_2) = encaps(&mut rng, &mpk, &subspace_2).unwrap();

    // Old USK cannot open new encapsulations.
    assert_eq!(None, decaps(&mut rng, &usk_1, &new_enc_1).unwrap());
    assert_eq!(None, decaps(&mut rng, &usk_1, &new_enc_2).unwrap());
    assert_eq!(None, decaps(&mut rng, &usk_2, &new_enc_2).unwrap());
    assert_eq!(None, decaps(&mut rng, &usk_2, &new_enc_1).unwrap());

    // Refresh USK.
    // Only the first one keeps its old rights.
    refresh(&mut rng, &mut msk, &mut usk_1, true).unwrap();
    refresh(&mut rng, &mut msk, &mut usk_2, false).unwrap();

    // Refreshed USK can open the new encapsulation.
    assert_eq!(
        Some(new_key_1),
        decaps(&mut rng, &usk_1, &new_enc_1).unwrap()
    );
    assert_eq!(None, decaps(&mut rng, &usk_1, &new_enc_2).unwrap());
    assert_eq!(
        Some(new_key_2),
        decaps(&mut rng, &usk_2, &new_enc_2).unwrap()
    );
    assert_eq!(None, decaps(&mut rng, &usk_2, &new_enc_1).unwrap());

    // Only USK 1 can still open the old encapsulation.
    assert_eq!(
        Some(old_key_1),
        decaps(&mut rng, &usk_1, &old_enc_1).unwrap()
    );
    assert_eq!(None, decaps(&mut rng, &usk_1, &old_enc_2).unwrap());
    assert_eq!(None, decaps(&mut rng, &usk_2, &old_enc_2).unwrap());
    assert_eq!(None, decaps(&mut rng, &usk_2, &old_enc_1).unwrap());
}

/// This test asserts that forged USK cannot be refreshed.
#[test]
fn test_integrity_check() {
    let mut rng = CsRng::from_entropy();
    let coordinate_1 = Right::random(&mut rng);
    let coordinate_2 = Right::random(&mut rng);
    let subspace_1 = HashSet::from_iter([coordinate_1.clone()]);
    let subspace_2 = HashSet::from_iter([coordinate_2.clone()]);

    let mut msk = setup(MIN_TRACING_LEVEL, &mut rng).unwrap();
    update_msk(
        &mut rng,
        &mut msk,
        HashMap::from_iter([
            (
                coordinate_1.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
            (
                coordinate_2.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
        ]),
    )
    .unwrap();
    let usk_1 = usk_keygen(&mut rng, &mut msk, subspace_1.clone()).unwrap();
    let usk_2 = usk_keygen(&mut rng, &mut msk, subspace_2.clone()).unwrap();

    // Here we are trying to get access to both USK1 and USK2 rights.
    let mut old_forged_usk = usk_1.clone();
    for (key, chain) in usk_2.secrets.iter() {
        old_forged_usk
            .secrets
            .insert_new_chain(key.clone(), chain.clone());
    }
    assert_eq!(
        old_forged_usk.secrets.count_elements(),
        usk_1.secrets.count_elements() + usk_2.secrets.count_elements()
    );

    // The forged key refresh is rejected: no modification is performed on it.
    let mut new_forged_usk = old_forged_usk.clone();
    assert!(refresh(&mut rng, &mut msk, &mut new_forged_usk, true).is_err());
    assert_eq!(new_forged_usk, old_forged_usk);
}

#[test]
fn test_reencrypt_with_msk() {
    let ap = AccessPolicy::parse("DPT::FIN && SEC::TOP").unwrap();
    let cc = Covercrypt::default();

    let mut rng = CsRng::from_entropy();

    let (mut msk, _) = cc_keygen(&cc, false).unwrap();
    let mpk = cc.update_msk(&mut msk).expect("cannot update master keys");
    let mut usk = cc
        .generate_user_secret_key(&mut msk, &ap)
        .expect("cannot generate usk");

    let (old_key, old_enc) = cc.encaps(&mpk, &ap).unwrap();
    assert_eq!(
        Some(&old_key),
        decaps(&mut rng, &usk, &old_enc).unwrap().as_ref()
    );

    cc.rekey(&mut msk, &ap).unwrap();
    let new_mpk = msk.mpk().unwrap();
    let (new_key, new_enc) = cc.recaps(&msk, &new_mpk, &old_enc).unwrap();
    cc.refresh_usk(&mut msk, &mut usk, true).unwrap();
    assert_eq!(Some(new_key), decaps(&mut rng, &usk, &new_enc).unwrap());
    assert_ne!(Some(old_key), decaps(&mut rng, &usk, &new_enc).unwrap());
}

#[test]
fn test_covercrypt_kem() {
    let ap = AccessPolicy::parse("DPT::FIN && SEC::TOP").unwrap();
    let cc = Covercrypt::default();
    let (mut msk, _mpk) = cc_keygen(&cc, false).unwrap();
    let mpk = cc.update_msk(&mut msk).expect("cannot update master keys");
    let usk = cc
        .generate_user_secret_key(&mut msk, &ap)
        .expect("cannot generate usk");
    let (secret, enc) = cc.encaps(&mpk, &ap).unwrap();
    let res = cc.decaps(&usk, &enc).unwrap();
    assert_eq!(secret, res.unwrap());
}

#[test]
fn test_covercrypt_pke() {
    let ap = AccessPolicy::parse("DPT::FIN && SEC::TOP").unwrap();
    let cc = Covercrypt::default();
    let (mut msk, mpk) = cc_keygen(&cc, false).unwrap();

    let ptx = "testing encryption/decryption".as_bytes();

    let ctx = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(&cc, &mpk, &ap, ptx)
        .expect("cannot encrypt!");
    let usk = cc
        .generate_user_secret_key(&mut msk, &ap)
        .expect("cannot generate usk");
    let ptx1 = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(&cc, &usk, &ctx)
        .expect("cannot decrypt the ciphertext");
    assert_eq!(ptx, &*ptx1.unwrap());
}
