//! This is the demo given in `README.md` and `lib.rs`

use cosmian_cover_crypt::{AccessPolicy, EncryptedHeader, api::Covercrypt, test_utils::cc_keygen};

fn main() {
    let cc = Covercrypt::default();
    let (mut msk, mpk) = cc_keygen(&cc, false).unwrap();

    // The user has a security clearance `Security Level::Top Secret`,
    // and belongs to the finance department (`Department::FIN`).
    let access_policy =
        AccessPolicy::parse("Security Level::Top Secret && Department::FIN").unwrap();
    let mut usk = cc
        .generate_user_secret_key(&mut msk, &access_policy)
        .unwrap();

    // Encrypt
    let (_, encrypted_header) =
        EncryptedHeader::generate(&cc, &mpk, &access_policy.clone(), None, None).unwrap();

    // The user is able to decrypt the encrypted header.
    assert!(encrypted_header.decrypt(&cc, &usk, None).unwrap().is_some());

    //
    // Rekey the user access policy.
    let mpk = cc.rekey(&mut msk, &access_policy).unwrap();

    let enc_policy = AccessPolicy::parse("Security Level::Top Secret").unwrap();
    // Encrypt with rotated attribute
    let (_, new_encrypted_header) =
        EncryptedHeader::generate(&cc, &mpk, &enc_policy, None, None).unwrap();

    // user cannot decrypt the newly encrypted header
    assert!(
        new_encrypted_header
            .decrypt(&cc, &usk, None)
            .unwrap()
            .is_none()
    );

    // refresh user secret key, do not grant old encryption access
    cc.refresh_usk(&mut msk, &mut usk, false).unwrap();

    // The user with refreshed key is able to decrypt the newly encrypted header.
    assert!(
        new_encrypted_header
            .decrypt(&cc, &usk, None)
            .unwrap()
            .is_some()
    );

    // But it cannot decrypt old ciphertexts
    assert!(encrypted_header.decrypt(&cc, &usk, None).unwrap().is_none());
}
