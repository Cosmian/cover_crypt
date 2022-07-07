use super::generate_cc_keys::{
    webassembly_generate_master_keys, webassembly_generate_user_private_key,
    webassembly_rotate_attributes,
};
use crate::{
    api::CoverCrypt,
    error::Error,
    interfaces::{
        statics::{decrypt_hybrid_header, ClearTextHeader, EncryptedHeader},
        wasm_bindgen::hybrid_cc_aes::*,
    },
    MasterPrivateKey, PublicKey, UserPrivateKey,
};
use abe_policy::{ap, Attribute, Policy, PolicyAxis};
/// Test WASM bindgen functions prerequisites:
/// - `cargo install wasm-bindgen-cli`
/// - `cargo test --target wasm32-unknown-unknown --release --features
///   wasm_bindgen --lib`
use cosmian_crypto_base::{
    hybrid_crypto::Metadata, symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto,
};
use js_sys::Uint8Array;
use serde_json::Value;
use wasm_bindgen_test::*;

fn create_test_policy() -> Policy {
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
    policy
}

fn encrypt_header(
    metadata: &Metadata,
    policy: &Policy,
    attributes: &[Attribute],
    public_key: &PublicKey,
) -> Result<EncryptedHeader<Aes256GcmCrypto>, Error> {
    let metadata_bytes = Uint8Array::from(serde_json::to_vec(metadata)?.as_slice());
    let policy_bytes = Uint8Array::from(serde_json::to_vec(policy)?.as_slice());
    let attributes_bytes = Uint8Array::from(serde_json::to_vec(attributes)?.as_slice());
    let public_key_bytes = Uint8Array::from(public_key.try_to_bytes()?.as_slice());
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
    user_decryption_key: &UserPrivateKey,
) -> Result<ClearTextHeader<Aes256GcmCrypto>, Error> {
    let encrypted_header_bytes = Uint8Array::from(encrypted_header.header_bytes.as_slice());
    let sk_u = Uint8Array::from(user_decryption_key.try_to_bytes()?.as_slice());
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
    let policy = create_test_policy();
    let attributes = vec![
        Attribute::new("Security Level", "Confidential"),
        Attribute::new("Department", "HR"),
        Attribute::new("Department", "FIN"),
    ];

    //
    // CoverCrypt setup
    //
    let cc = CoverCrypt::default();
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
        serde_json::from_str(include_str!("../../../non_regression_vector.json")).unwrap();

    let user_decryption_key =
        hex::decode(reg_vector_json["user_decryption_key"].as_str().unwrap()).unwrap();
    let header_bytes = hex::decode(reg_vector_json["header_bytes"].as_str().unwrap()).unwrap();

    let user_decryption_key_from_file =
        UserPrivateKey::try_from_bytes(&user_decryption_key).unwrap();
    decrypt_hybrid_header::<Aes256GcmCrypto>(&user_decryption_key_from_file, &header_bytes)
        .unwrap();
}

#[wasm_bindgen_test]
fn test_generate_keys() {
    //
    // Policy settings
    //
    let policy = create_test_policy();
    let serialized_policy = serde_json::to_vec(&policy).unwrap();

    //
    // Generate master keys
    let master_keys =
        webassembly_generate_master_keys(Uint8Array::from(serialized_policy.as_slice())).unwrap();

    let master_keys_vec = master_keys.to_vec();
    let private_key_size = u32::from_be_bytes(master_keys_vec[0..4].try_into().unwrap());
    let private_key_bytes = &master_keys_vec[4..4 + private_key_size as usize];

    //
    // Check deserialization
    MasterPrivateKey::try_from_bytes(private_key_bytes).unwrap();
    PublicKey::try_from_bytes(&master_keys_vec[4 + private_key_size as usize..]).unwrap();

    //
    // Generate user private key
    let user_private_key_bytes = webassembly_generate_user_private_key(
        Uint8Array::from(private_key_bytes),
        "Department::FIN && Security Level::Top Secret",
        Uint8Array::from(serialized_policy.as_slice()),
    )
    .unwrap()
    .to_vec();
    let user_private_key = UserPrivateKey::try_from_bytes(&user_private_key_bytes).unwrap();

    let attributes = vec![Attribute::new("Security Level", "Confidential")];
    let serialized_attributes = serde_json::to_vec(&attributes).unwrap();

    let new_policy = webassembly_rotate_attributes(
        Uint8Array::from(serialized_attributes.as_slice()),
        Uint8Array::from(serialized_policy.as_slice()),
    )
    .unwrap();

    //
    // Generate master keys
    let master_keys =
        webassembly_generate_master_keys(Uint8Array::from(new_policy.as_bytes())).unwrap();
    let master_keys_vec = master_keys.to_vec();
    let private_key_size = u32::from_be_bytes(master_keys_vec[0..4].try_into().unwrap());
    let private_key_bytes = &master_keys_vec[4..4 + private_key_size as usize];

    //
    // Check deserialization
    MasterPrivateKey::try_from_bytes(private_key_bytes).unwrap();
    let master_public_key =
        PublicKey::try_from_bytes(&master_keys_vec[4 + private_key_size as usize..]).unwrap();

    //
    // Encrypt / decrypt
    //
    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };

    let encrypted_header =
        encrypt_header(&meta_data, &policy, &attributes, &master_public_key).unwrap();

    //
    // Try to decrypt with a non-refreshed private key (it fails)
    //
    assert!(decrypt_header(&encrypted_header, &user_private_key).is_err());

    //
    // Refresh user private key
    let user_private_key_bytes = webassembly_generate_user_private_key(
        Uint8Array::from(private_key_bytes),
        "Security Level::Confidential",
        Uint8Array::from(serialized_policy.as_slice()),
    )
    .unwrap()
    .to_vec();
    let user_private_key = UserPrivateKey::try_from_bytes(&user_private_key_bytes).unwrap();

    //
    // Decrypt with the refreshed private key (it now works)
    //
    decrypt_header(&encrypted_header, &user_private_key).unwrap();
}
