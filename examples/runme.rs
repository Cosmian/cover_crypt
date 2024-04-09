//! This is the demo given in `README.md` and `lib.rs`

use cosmian_cover_crypt::api::EncryptedHeaderEnc;
use cosmian_cover_crypt::{
    abe_policy::{AccessPolicy, Attribute, DimensionBuilder, EncryptionHint, Policy},
    api::{Covercrypt, CovercryptKEM, EncryptedHeader},
};
use cosmian_crypto_core::Aes256Gcm;

fn main() {
    // The first attribute axis will be a security level.
    // This axis is hierarchical, i.e. users matching
    // `Security Level::Confidential` can also decrypt
    // messages encrypted for `Security Level::Protected`.
    let sec_level = DimensionBuilder::new(
        "Security Level",
        vec![
            ("Protected", EncryptionHint::Classic),
            ("Confidential", EncryptionHint::Classic),
            ("Top Secret", EncryptionHint::Hybridized),
        ],
        true,
    );

    // Another attribute axis will be department names.
    // This axis is *not* hierarchical.
    let department = DimensionBuilder::new(
        "Department",
        vec![
            ("R&D", EncryptionHint::Classic),
            ("HR", EncryptionHint::Classic),
            ("MKG", EncryptionHint::Classic),
            ("FIN", EncryptionHint::Classic),
        ],
        false,
    );

    // Generate a new `Policy` object with a 100 revocations allowed.
    let mut policy = Policy::new();

    // Add the two generated axes to the policy
    policy.add_dimension(sec_level).unwrap();
    policy.add_dimension(department).unwrap();

    // Setup Covercrypt and generate master keys
    let cover_crypt = Covercrypt::default();
    let (mut msk, _) = CovercryptKEM::setup(&cover_crypt).unwrap();
    let mpk = CovercryptKEM::update_master_keys(&cover_crypt, &policy, &mut msk).unwrap();

    // The user has a security clearance `Security Level::Top Secret`,
    // and belongs to the finance department (`Department::FIN`).
    let access_policy = "Security Level::Top Secret && Department::FIN";
    let access_policy_parsed = AccessPolicy::parse(access_policy).unwrap();
    let mut usk = CovercryptKEM::generate_user_secret_key(
        &cover_crypt,
        &mut msk,
        &access_policy_parsed,
        &policy,
    )
    .unwrap();

    // Encrypt
    let (_, encrypted_header) = EncryptedHeader::<Aes256Gcm>::generate(
        &cover_crypt,
        &policy,
        &mpk,
        access_policy,
        None,
        None,
    )
    .unwrap();

    // The user is able to decrypt the encrypted header.
    assert!(
        EncryptedHeader::<Aes256Gcm>::decrypt(&encrypted_header, &cover_crypt, &usk, None).is_ok()
    );

    //
    // Rekey all keys using the `Security Level::Top Secret` attribute
    let rekey_access_policy = AccessPolicy::Attr(Attribute::from(("Security Level", "Top Secret")));
    let mpk = CovercryptKEM::rekey(&cover_crypt, &rekey_access_policy, &policy, &mut msk).unwrap();

    // Encrypt with rotated attribute
    let (_, new_encrypted_header) = EncryptedHeader::<Aes256Gcm>::generate(
        &cover_crypt,
        &policy,
        &mpk,
        "Security Level::Top Secret",
        None,
        None,
    )
    .unwrap();

    // user cannot decrypt the newly encrypted header
    assert!(
        EncryptedHeader::<Aes256Gcm>::decrypt(&new_encrypted_header, &cover_crypt, &usk, None)
            .expect("must not fail")
            .is_none()
    );

    // refresh user secret key, do not grant old encryption access
    CovercryptKEM::refresh_usk(&cover_crypt, &mut usk, &mut msk, false).unwrap();

    // The user with refreshed key is able to decrypt the newly encrypted header.
    assert!(
        EncryptedHeader::<Aes256Gcm>::decrypt(&new_encrypted_header, &cover_crypt, &usk, None)
            .is_ok()
    );

    // But it cannot decrypt old ciphertexts
    assert!(
        EncryptedHeader::<Aes256Gcm>::decrypt(&encrypted_header, &cover_crypt, &usk, None)
            .expect("must not fail")
            .is_none()
    );
}
