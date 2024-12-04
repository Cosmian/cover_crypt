use cosmian_cover_crypt::{
    AccessPolicy, EncryptedHeader, MasterPublicKey, MasterSecretKey, api::Covercrypt,
};

/// Generates a new USK and encrypted header and prints them.
fn generate_new(cc: &Covercrypt, _msk: &mut MasterSecretKey, mpk: &MasterPublicKey) {
    let access_policy =
        AccessPolicy::parse("Department::FIN && Security Level::Top Secret").unwrap();

    let (_, _header) = EncryptedHeader::generate(cc, mpk, &access_policy, None, None)
        .expect("cannot encrypt header");

    {
        use base64::{
            Engine,
            alphabet::STANDARD,
            engine::{GeneralPurpose, GeneralPurposeConfig},
        };

        use cosmian_crypto_core::bytes_ser_de::Serializable;
        let config: GeneralPurposeConfig = GeneralPurposeConfig::default();
        let transcoder: GeneralPurpose = GeneralPurpose::new(&STANDARD, config);
        println!(
            "USK = {}",
            transcoder.encode(
                cc.generate_user_secret_key(_msk, &access_policy)
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
    let ap = AccessPolicy::parse("Department::FIN && Security Level::Top Secret").unwrap();

    let cc = Covercrypt::default();
    let (mut msk, mpk) = cc.setup().expect("cannot generate master keys");

    generate_new(&cc, &mut msk, &mpk);

    // Encrypt header, use loop to increase its wight in the flame graph.
    for _ in 0..100 {
        EncryptedHeader::generate(&cc, &mpk, &ap, None, None).expect("cannot encrypt header");
    }
}
