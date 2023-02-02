use cosmian_cover_crypt::{
    abe_policy::{AccessPolicy, Attribute, EncryptionHint, Policy, PolicyAxis},
    statics::{CoverCryptX25519Aes256, EncryptedHeader, MasterSecretKey, PublicKey},
    CoverCrypt, Error,
};
#[cfg(feature = "interface")]
use cosmian_crypto_core::bytes_ser_de::Serializable;

/// Policy settings
fn policy() -> Result<Policy, Error> {
    let sec_level = PolicyAxis::new(
        "Security Level",
        vec![
            ("Protected", EncryptionHint::Classic),
            ("Confidential", EncryptionHint::Classic),
            ("Top Secret", EncryptionHint::Hybridized),
        ],
        true,
    );
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
    let mut policy = Policy::new(100);
    policy.add_axis(sec_level)?;
    policy.add_axis(department)?;
    policy.rotate(&Attribute::new("Department", "FIN"))?;
    Ok(policy)
}

fn generate_new(
    cc: &CoverCryptX25519Aes256,
    policy: &Policy,
    _msk: &MasterSecretKey,
    mpk: &PublicKey,
) {
    let access_policy =
        AccessPolicy::from_boolean_expression("Department::FIN && Security Level::Top Secret")
            .unwrap();

    let (_, _header) = EncryptedHeader::generate(cc, policy, mpk, &access_policy, None, None)
        .expect("cannot encrypt header");

    #[cfg(feature = "interface")]
    println!(
        "usk = {}",
        hex::encode(
            cc.generate_user_secret_key(_msk, &access_policy, policy)
                .unwrap()
                .try_to_bytes()
                .unwrap()
        )
    );
    #[cfg(feature = "interface")]
    println!("header = {}", hex::encode(_header.try_to_bytes().unwrap()));
}

fn main() {
    // create policy
    let policy = policy().expect("cannot generate policy");

    let cc = CoverCryptX25519Aes256::default();
    let (_msk, mpk) = cc
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");

    let access_policy =
        AccessPolicy::from_boolean_expression("Department::FIN && Security Level::Top Secret")
            .unwrap();

    //
    // Use the following to update `examples/decrypt.rs` constants.
    //
    generate_new(&cc, &policy, &_msk, &mpk);

    // encrypt header, use loop to add weight in the flamegraph on it
    for _ in 0..100 {
        let _encrypted_header =
            EncryptedHeader::generate(&cc, &policy, &mpk, &access_policy, None, None)
                .expect("cannot encrypt header");
    }
}
