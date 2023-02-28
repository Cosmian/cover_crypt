//! This is the demo given in `README.md` and `lib.rs`

use cosmian_cover_crypt::{
    abe_policy::{AccessPolicy, Attribute, EncryptionHint, Policy, PolicyAxis},
    statics::{CoverCryptX25519Aes256, EncryptedHeader},
    CoverCrypt,
};

fn main() {
    // The first attribute axis will be a security level.
    // This axis is hierarchical, i.e. users matching
    // `Security Level::Confidential` can also decrypt
    // messages encrypted for `Security Level::Protected`.
    let sec_level = PolicyAxis::new(
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
    let department = PolicyAxis::new(
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
    let mut policy = Policy::new(100);

    // Add the two generated axes to the policy
    policy.add_axis(sec_level).unwrap();
    policy.add_axis(department).unwrap();

    // Setup CoverCrypt and generate master keys
    let cover_crypt = CoverCryptX25519Aes256::default();
    let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy).unwrap();

    // The user has a security clearance `Security Level::Top Secret`,
    // and belongs to the finance department (`Department::FIN`).
    let access_policy =
        AccessPolicy::from_boolean_expression("Security Level::Top Secret && Department::FIN")
            .unwrap();
    let mut usk = cover_crypt
        .generate_user_secret_key(&msk, &access_policy, &policy)
        .unwrap();

    // Encrypt
    let (_, encrypted_header) =
        EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy, None, None).unwrap();

    // The user is able to decrypt the encrypted header.
    assert!(encrypted_header.decrypt(&cover_crypt, &usk, None).is_ok());

    //
    // Rotate the `Security Level::Top Secret` attribute
    policy
        .rotate(&Attribute::from(("Security Level", "Top Secret")))
        .unwrap();

    // Master keys need to be updated to take into account the policy rotation
    cover_crypt
        .update_master_keys(&policy, &mut msk, &mut mpk)
        .unwrap();

    // Encrypt with rotated attribute
    let (_, new_encrypted_header) =
        EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &access_policy, None, None).unwrap();

    // user cannot decrypt the newly encrypted header
    assert!(new_encrypted_header
        .decrypt(&cover_crypt, &usk, None)
        .is_err());

    // refresh user secret key, do not grant old encryption access
    cover_crypt
        .refresh_user_secret_key(&mut usk, &access_policy, &msk, &policy, false)
        .unwrap();

    // The user with refreshed key is able to decrypt the newly encrypted header.
    assert!(new_encrypted_header
        .decrypt(&cover_crypt, &usk, None)
        .is_ok());

    // But it cannot decrypt old ciphertexts
    assert!(encrypted_header.decrypt(&cover_crypt, &usk, None).is_err());
}
