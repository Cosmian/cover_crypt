fn main() {
    // create policy
    #[cfg(all(feature = "serialization", feature = "test_utils"))]
    {
        use base64::{
            alphabet::STANDARD,
            engine::{GeneralPurpose, GeneralPurposeConfig},
            Engine,
        };
        use cosmian_cover_crypt::{
            abe_policy::{AccessPolicy, Policy},
            test_utils::policy,
            Covercrypt, EncryptedHeader, MasterPublicKey, MasterSecretKey,
        };
        use cosmian_crypto_core::bytes_ser_de::Serializable;

        fn generate_new(
            cc: &Covercrypt,
            policy: &Policy,
            _msk: &MasterSecretKey,
            mpk: &MasterPublicKey,
        ) {
            let access_policy = AccessPolicy::from_boolean_expression(
                "Department::FIN && Security Level::Top Secret",
            )
            .unwrap();

            let (_, _header) =
                EncryptedHeader::generate(cc, policy, mpk, &access_policy, None, None)
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

        let policy = policy().expect("cannot generate policy");

        let cc = Covercrypt::default();
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

    #[cfg(not(all(feature = "test_utils", feature = "serialization")))]
    println!("Use the `serialization` feature to run this example")
}
