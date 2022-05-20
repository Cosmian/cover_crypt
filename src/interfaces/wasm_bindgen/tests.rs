use crate::{
    api::{self, CoverCrypt},
    error::Error,
    interfaces::{
        statics::{ClearTextHeader, EncryptedHeader},
        wasm_bindgen::hybrid_gpsw_aes::*,
    },
    policy::{AccessPolicy, Attribute, Attributes, Policy, PolicyAxis},
};
use cosmian_crypto_base::{
    asymmetric::ristretto::X25519Crypto, hybrid_crypto::Metadata,
    symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto,
};
use wasm_bindgen_test::*;

fn encrypt_header(
    metadata: &Metadata,
    policy: &Policy,
    attributes: &[Attribute],
    public_key: &api::PublicKey<X25519Crypto>,
) -> Result<EncryptedHeader<Aes256GcmCrypto>, Error> {
    let metadata_bytes = js_sys::Uint8Array::from(serde_json::to_vec(metadata)?.as_slice());
    let policy_bytes = js_sys::Uint8Array::from(serde_json::to_vec(policy)?.as_slice());
    let attributes_bytes = js_sys::Uint8Array::from(serde_json::to_vec(attributes)?.as_slice());
    let public_key_bytes = js_sys::Uint8Array::from(serde_json::to_vec(public_key)?.as_slice());
    let encrypted_header = webassembly_encrypt_hybrid_header(
        metadata_bytes,
        policy_bytes,
        attributes_bytes,
        public_key_bytes,
    )
    .map_err(|e| Error::Other(e.as_string().unwrap()))?;
    serde_json::from_slice(encrypted_header.to_vec().as_slice())
        .map_err(|e| Error::JsonParsing(e.to_string()))
}

fn decrypted_header(
    encrypted_header: &EncryptedHeader<Aes256GcmCrypto>,
    user_decryption_key: &api::PrivateKey<X25519Crypto>,
) -> Result<ClearTextHeader<Aes256GcmCrypto>, Error> {
    let encrypted_header_bytes = js_sys::Uint8Array::from(encrypted_header.header_bytes.as_slice());
    let sk_u = js_sys::Uint8Array::from(serde_json::to_vec(user_decryption_key)?.as_slice());
    let decrypted_header_bytes = webassembly_decrypt_hybrid_header(sk_u, encrypted_header_bytes)
        .map_err(|e| Error::Other(e.as_string().unwrap()))?;
    serde_json::from_slice(&decrypted_header_bytes.to_vec())
        .map_err(|e| Error::JsonParsing(e.to_string()))
}

#[wasm_bindgen_test]
pub fn test_non_reg_decrypt_hybrid_header() {
    //
    // Policy settings
    //
    let sec_level = PolicyAxis::new(
        "Security Level",
        &["Protected", "Confidential", "Top Secret"],
        true,
    );
    let department = PolicyAxis::new("Department", &["R&D", "HR", "MKG", "FIN"], false);
    let mut policy = Policy::new(100);
    policy.add_axis(&sec_level).unwrap();
    policy.add_axis(&department).unwrap();
    policy.rotate(&Attribute::new("Department", "FIN")).unwrap();
    let attributes = Attributes::from(vec![
        Attribute::new("Security Level", "Confidential"),
        Attribute::new("Department", "HR"),
        Attribute::new("Department", "FIN"),
    ]);
    let access_policy = AccessPolicy::from_attribute_list(&attributes).unwrap();

    //
    // CoverCrypt setup
    //
    let cc = CoverCrypt::<X25519Crypto>::default();
    let (msk, mpk) = cc.generate_master_keys(&policy).unwrap();
    let sk_u = cc
        .generate_user_private_key(&msk, &access_policy, &policy)
        .unwrap();
    for autorisation in sk_u.keys() {
        println!("{autorisation}");
    }

    //
    // Encrypt / decrypt
    //
    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };

    let encrypted_header = encrypt_header(&meta_data, &policy, &attributes, &mpk).unwrap();
    let decrypted_header = decrypted_header(&encrypted_header, &sk_u).unwrap();

    assert_eq!(
        encrypted_header.symmetric_key,
        decrypted_header.symmetric_key
    );
    assert_eq!(&meta_data.uid, &decrypted_header.meta_data.uid);
    assert_eq!(
        &meta_data.additional_data,
        &decrypted_header.meta_data.additional_data
    );
}

//#[wasm_bindgen_test]
//pub fn test_non_reg_decrypt_hybrid_block() {
//let symmetric_key_hex = "802de96f19589fbc0eb2f26705dc1ed261e9c80f2fec301ca7d0ecea3176405b";
//let symmetric_key =
//<Aes256GcmCrypto as SymmetricCrypto>::Key::parse(hex::decode(symmetric_key_hex).unwrap())
//.unwrap();
//let uid_hex = "cd8ca2eeb654b5f39f347f4e3f91b3a15c450c1e52c40716237b4c18510f65b4";
//let encrypted_bytes = "e09ba17fdff90afbb18546211268b8aef6517a73b701283ab334c0720372f565c751a311c1ec09a6bbb070f8a1961ca3f048b280ea36a578a0068edea8408f3cf4ab26f5a71933dffed384ea7d33e42c16fe17a1026937a345386bb980917d6d2175a48b6d69e8322689dde0bf99cee9d2da5bbee1f29b2005725b6969021462e6608284a5135677b03d8fcce03563cc4d8988f455d27b95ef62080f4c2f18e7897636ac69e9d216668765d2025f66c805d549c4ef779c32ac3286bee8d35c1b758b51f1686d2aea996cc1f3bfff2aea7d605cce963e5bc69f77f284a1c05b803df08fcdec6a6d4f0c74ad8f6076d9ca692642dcdff64a34d1fbbb4d57aea776ce8032b03d63c9e376377fb95725b6d3ac6be3a29f47d15eb22b5c81bf6168785844da8d22914076415957d9e253142f14c5c68fbe1108d74832e2347425f89b46321ac0c7b939f793e3c39e5dbb83d9e6be29db4aa3df0e645cc859aac9a0324d546b70856e2ae89c77b87a8e25eac90f9265642bbd8c407f0aa307aef613bd79fa8fd6c959c959007791621e5fe047edfcadae2c195bb681b6621a9583c8d51911e39df50331b495b603fbf826eebeffe26cd2bc0287a280801bc54cfa9fed1279a58843bb8ea1262982753481dc61852cca49279d0de5e287f6a43dca38";

//let _clear_text =
//decrypt_hybrid_block::<Gpsw<Bls12_381>, Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(
//&symmetric_key,
//&hex::decode(uid_hex).unwrap(),
//0,
//&hex::decode(encrypted_bytes).unwrap(),
//)
//.unwrap();
//}
