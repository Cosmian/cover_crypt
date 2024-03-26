use cosmian_cover_crypt::{
    abe_policy::{AccessPolicy, Policy},
    test_utils::policy,
    Covercrypt, EncryptedHeader, MasterPublicKey, MasterSecretKey,
};

/// Generates a new USK and encrypted header and prints them.
fn generate_new(
    cc: &Covercrypt,
    policy: &Policy,
    _msk: &mut MasterSecretKey,
    mpk: &MasterPublicKey,
) {
    let access_policy =
        AccessPolicy::parse("Department::FIN && Security Level::Top Secret").unwrap();

    let (_, _header) = EncryptedHeader::generate(cc, policy, mpk, &access_policy, None, None)
        .expect("cannot encrypt header");

    #[cfg(feature = "serialization")]
    {
        use base64::{
            alphabet::STANDARD,
            engine::{GeneralPurpose, GeneralPurposeConfig},
            Engine,
        };

        use cosmian_crypto_core::bytes_ser_de::Serializable;
        let config: GeneralPurposeConfig = GeneralPurposeConfig::default();
        let transcoder: GeneralPurpose = GeneralPurpose::new(&STANDARD, config);
        println!(
            "USK = {}",
            transcoder.encode(
                cc.generate_user_secret_key(_msk, &access_policy, policy)
                    .unwrap()
                    .serialize()
                    .unwrap()
            )
        );
        println!(
            "header = {}",
            transcoder.encode(_header.serialize().unwrap())
        );
    }
}

fn main() {
    let policy = policy().expect("cannot generate policy");
    let ap = AccessPolicy::parse("Department::FIN && Security Level::Top Secret")
        .expect("cannot parse given access policy");

    let cc = Covercrypt::default();
    let (mut msk, _) = cc.setup().expect("cannot generate master keys");
    let mpk = cc
        .update_master_keys(&policy, &mut msk)
        .expect("cannot update master keys");

    generate_new(&cc, &policy, &mut msk, &mpk);

    // Encrypt header, use loop to increase its wight in the flame graph.
    for _ in 0..1000 {
        EncryptedHeader::generate(&cc, &policy, &mpk, &ap, None, None)
            .expect("cannot encrypt header");
    }
}
