#[cfg(feature = "serialization")]
use base64::{
    alphabet::STANDARD,
    engine::{GeneralPurpose, GeneralPurposeConfig},
    Engine,
};
use cosmian_cover_crypt::{
    abe_policy::{AccessPolicy, Policy},
    statics::{CoverCryptX25519Aes256, EncryptedHeader, MasterSecretKey, PublicKey},
    test_utils::policy,
    CoverCrypt,
};
#[cfg(feature = "serialization")]
use cosmian_crypto_core::bytes_ser_de::Serializable;

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

    #[cfg(feature = "serialization")]
    {
        let config: GeneralPurposeConfig = GeneralPurposeConfig::default();
        let transcoder: GeneralPurpose = GeneralPurpose::new(&STANDARD, config);

        println!(
            "usk = {}",
            transcoder.encode(
                cc.generate_user_secret_key(_msk, &access_policy, policy)
                    .unwrap()
                    .try_to_bytes()
                    .unwrap()
            )
        );
        println!(
            "header = {}",
            transcoder.encode(_header.try_to_bytes().unwrap())
        );
    }
}

fn main() {
    // create policy
    let policy = policy().expect("cannot generate policy");

    let cc = CoverCryptX25519Aes256::default();
    let (_msk, mpk) = cc
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");

    // Encryption of a hybridized ciphertext
    let access_policy =
        AccessPolicy::from_boolean_expression("Department::FIN && Security Level::Top Secret")
            .unwrap();

    //
    // Use the following to update `examples/decrypt.rs` constants.
    //
    generate_new(&cc, &policy, &_msk, &mpk);

    // encrypt header, use loop to add weight in the flamegraph on it
    for _ in 0..1000 {
        let _encrypted_header =
            EncryptedHeader::generate(&cc, &policy, &mpk, &access_policy, None, None)
                .expect("cannot encrypt header");
    }
}
