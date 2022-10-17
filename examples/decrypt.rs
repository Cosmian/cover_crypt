use cosmian_cover_crypt::{
    api::EncryptedHeader, interfaces::statics::UserSecretKey, CoverCryptStruct, Serializable,
};

const USK: &str = "ab5701818c31f2fbae555ddeaf20e02485b3bad8b747cea4adbd8f43b49e1d09d4fcec90a4fa3b4bf69e7db8e5b4020958213363a193972fe5e23671aaf1460b0302010896d1b550ddac6d65c0f0432500b8726d07204394d92ec215406014b1f4ae9c02020208915b9c11d56fb9933f3b8a69433b1bf00c7494bca971aadf9f599eee0a2c8e0202030860f1270ba190cd49b955ef5b03e39384b674315f5d809e37b9fdde910dc3010e";

const HEADER: &str = "de73e6a31934444ece771d0d963302ecc91c9d7624f92734eff540ec6d0aad5bf29ccc3b4fd4dd2d9e900210dac1260c3f5793c514d01b552b1c15d09818453b01dea28ae632015cacb86ff4aa9e45c8bb88a3564ed118a6975dfa4ec34b298cf61ce17e0459c2ec5bc768000d71f37e0e97cbff196970be46bee1b9ba06";

fn main() {
    let cc = CoverCryptStruct::default();
    let usk = UserSecretKey::try_from_bytes(&hex::decode(USK.as_bytes()).unwrap()).unwrap();
    let encrypted_header =
        EncryptedHeader::try_from_bytes(&hex::decode(HEADER.as_bytes()).unwrap()).unwrap();
    for _ in 0..100 {
        encrypted_header
            .decrypt(&cc, &usk, None)
            .expect("cannot decrypt hybrid header");
    }
}
