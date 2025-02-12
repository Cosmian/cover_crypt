use std::{fs::File, io::Read};

use cosmian_cover_crypt::{traits::PkeAc, XEnc};
use cosmian_crypto_core::{bytes_ser_de::Deserializer, Aes256Gcm};

fn main() {
    use cosmian_cover_crypt::api::Covercrypt;
    use cosmian_cover_crypt::UserSecretKey;
    use cosmian_crypto_core::bytes_ser_de::Serializable;

    let cc = Covercrypt::default();

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
        PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(&cc, &usk, &ctx)
            .expect("cannot decrypt hybrid header");
    }
}
