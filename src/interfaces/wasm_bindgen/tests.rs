use cosmian_crypto_base::{
    asymmetric::ristretto::X25519Crypto, hybrid_crypto::Metadata,
    symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto,
};
use serde_json::Value;
use wasm_bindgen_test::*;

use crate::{
    api::{self, CoverCrypt},
    error::Error,
    interfaces::{
        statics::{decrypt_hybrid_header, ClearTextHeader, EncryptedHeader},
        wasm_bindgen::hybrid_cc_aes::*,
    },
    policies::{ap, Attribute, Policy, PolicyAxis},
};

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

fn decrypt_header(
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
pub fn test_decrypt_hybrid_header() {
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
    let attributes = vec![
        Attribute::new("Security Level", "Confidential"),
        Attribute::new("Department", "HR"),
        Attribute::new("Department", "FIN"),
    ];

    //
    // CoverCrypt setup
    //
    let cc = CoverCrypt::<X25519Crypto>::default();
    let (msk, mpk) = cc.generate_master_keys(&policy).unwrap();

    let access_policy = ap("Department", "FIN") & ap("Security Level", "Top Secret");
    let sk_u = cc
        .generate_user_private_key(&msk, &access_policy, &policy)
        .unwrap();

    //
    // Encrypt / decrypt
    //
    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };

    let encrypted_header = encrypt_header(&meta_data, &policy, &attributes, &mpk).unwrap();
    let decrypted_header = decrypt_header(&encrypted_header, &sk_u).unwrap();

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

#[wasm_bindgen_test]
fn test_non_reg_decrypt_hybrid_header() {
    let reg_vector_json: Value =
        serde_json::from_str(include_str!("../regression_vector.json")).unwrap();

    let user_decryption_key =
        hex::decode(reg_vector_json["user_decryption_key"].as_str().unwrap()).unwrap();
    let header_bytes = hex::decode(reg_vector_json["header_bytes"].as_str().unwrap()).unwrap();

    let user_decryption_key_from_file = serde_json::from_slice(&user_decryption_key).unwrap();
    decrypt_hybrid_header::<X25519Crypto, Aes256GcmCrypto>(
        &user_decryption_key_from_file,
        &header_bytes,
    )
    .unwrap();
}
