use cosmian_cover_crypt::{
    api::EncryptedHeader, interfaces::statics::UserSecretKey, CoverCryptStruct, Serializable,
};

const USK: &str = "6f66df35eee5cabbff488b84fd7c42c947ab69a773ad32fe849506b7ce09c601f71ae4ee445046381dd7e24ae12546ab6749a2fae2de8c52908075ced96e1200030201084f6a28c52be77bcb09c2552f50efe2e7ac75d9fdf9790379e26b1ce7f6c0e70f0202088f8b985e341d8cf58abfea93008bd2ddae8856e3812c1f6a6a45deacc82d490402030845bae75126228b245c250a2b99c371828498b635e6d9a954c333ae1ef2af0609";

const HEADER: &str = "52a42fe78eb999ce9260f341b5eb469c222842751ae08fe9b711565114de6152ac900268869849e612977e11edf623b75663f539412345198a6126893c73fd3e0303be17efd142467ae66c44561ed2e9cbe0cd4a32e8f35906f3b1b53da84be1db867e50d16ef06f0c15a18b3509cb5db36c58621323d7988127a5570e513e2332888426f738e1eceda64864904cffbc0b95de3f8ef00192edf863c39763dea6171cbeb285c045420553fade414ba40e5a729221dfd5747f4e7b4df2b845";

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
