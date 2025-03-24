use std::{
    fs::File,
    io::{Read, Write},
};

use cosmian_cover_crypt::{
    api::Covercrypt, cc_keygen, traits::PkeAc, AccessPolicy, MasterPublicKey, MasterSecretKey,
    UserSecretKey, XEnc,
};
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    Aes256Gcm,
};

#[allow(dead_code)]
/// Generates a new USK and encrypted header and prints them.
fn generate_new(cc: &Covercrypt, msk: &mut MasterSecretKey, mpk: &MasterPublicKey) {
    let ap = AccessPolicy::parse("DPT::FIN && SEC::TOP").unwrap();

    let usk = cc.generate_user_secret_key(msk, &ap).unwrap();
    let ctx = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(cc, mpk, &ap, b"gotcha")
        .expect("cannot encrypt!");

    // Ensure decryption is OK
    PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(cc, &usk, &ctx).unwrap();

    {
        File::create("./usk.txt")
            .unwrap()
            .write_all(&usk.serialize().unwrap())
            .unwrap();

        let usk = UserSecretKey::deserialize(&{
            let mut bytes = Vec::new();
            File::open("usk.txt")
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            bytes
        })
        .unwrap();

        // Ensure decryption is OK
        PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(cc, &usk, &ctx).unwrap();

        File::create("./ctx.txt")
            .unwrap()
            .write_all(&{
                let mut ser = Serializer::new();
                ser.write(&ctx.0).unwrap();
                ser.write_vec(&ctx.1).unwrap();
                ser.finalize()
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

        // Ensure decryption is OK
        PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(cc, &usk, &ctx).unwrap();
    }
}

fn main() {
    let ap = AccessPolicy::parse("DPT::FIN && SEC::TOP").unwrap();
    let cc = Covercrypt::default();
    let (mut _msk, mpk) = cc_keygen(&cc, false).unwrap();

    // Un-comment this line to generate new usk.txt and ctx.txt files.
    //
    // generate_new(&cc, &mut _msk, &mpk);

    let ptx = "testing encryption/decryption".as_bytes();

    for _ in 0..100 {
        PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(&cc, &mpk, &ap, ptx)
            .expect("cannot encrypt!");
    }
}
