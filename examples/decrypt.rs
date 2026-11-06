use std::{fs::File, io::Read};

use cosmian_cover_crypt::{XEnc, traits::PkeAc};
use cosmian_crypto_core::{
    Aes256Gcm, CsRng, bytes_ser_de::Deserializer,
    reexport::rand_core::SeedableRng,
};
use cosmian_openssl_provider::hash::Sha256;

fn main() {
    use cosmian_cover_crypt::UserSecretKey;
    use cosmian_cover_crypt::api::Covercrypt;
    use cosmian_crypto_core::bytes_ser_de::Serializable;

    let mut rng = CsRng::from_entropy();

    let usk = UserSecretKey::deserialize(&{
        let mut bytes = Vec::new();
        File::open("usk.txt")
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        bytes
    })
    .unwrap();

    let ctx = {
        let mut bytes = Vec::new();
        File::open("ctx.txt")
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        let mut de = Deserializer::new(&bytes);
        (de.read::<XEnc>().unwrap(), de.read_vec().unwrap())
    };

    for _ in 0..1_000_000 {
        <Covercrypt as PkeAc<
            { Aes256Gcm::KEY_LENGTH },
            { Aes256Gcm::NONCE_LENGTH },
            { Aes256Gcm::MAC_LENGTH },
            Sha256,
            Aes256Gcm,
        >>::decrypt(&mut rng, &usk, &ctx)
        .expect("cannot decrypt hybrid header");
    }
}
