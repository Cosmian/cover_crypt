use crate::{
    interfaces::wasm_bindgen::{
        generate_cc_keys::{
            webassembly_generate_master_keys, webassembly_generate_user_secret_key,
        },
        hybrid_cc_aes::{
            webassembly_decrypt_hybrid_header, webassembly_encrypt_hybrid_header,
            webassembly_hybrid_decrypt, webassembly_hybrid_encrypt,
        },
    },
    statics::{
        tests::policy, CleartextHeader, CoverCryptX25519Aes256, EncryptedHeader, MasterSecretKey,
        PublicKey, UserSecretKey,
    },
    CoverCrypt, Error,
};
use abe_policy::{
    interfaces::wasm_bindgen::{webassembly_rotate_attributes, Attributes},
    Policy,
};
use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable};
/// Test WASM bindgen functions prerequisites:
/// - `cargo install wasm-bindgen-cli`
/// - `cargo test --target wasm32-unknown-unknown --release --features
///   wasm_bindgen --lib`
use js_sys::{Array, JsString, Uint8Array};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

fn encrypt_header(
    policy: &Policy,
    access_policy_string: String,
    public_key: &PublicKey,
    header_metadata: &[u8],
    authentication_data: &[u8],
) -> Result<EncryptedHeader, Error> {
    let header_metadata = Uint8Array::from(header_metadata);
    let authentication_data = Uint8Array::from(authentication_data);
    let policy_bytes = serde_json::to_vec(&policy)?;
    let public_key_bytes = Uint8Array::from(public_key.try_to_bytes()?.as_slice());
    let encrypted_header = webassembly_encrypt_hybrid_header(
        policy_bytes,
        access_policy_string,
        public_key_bytes,
        header_metadata,
        authentication_data,
    )
    .map_err(|e| Error::Other(e.as_string().unwrap()))?;
    EncryptedHeader::try_from_bytes(
        &encrypted_header.to_vec()[CoverCryptX25519Aes256::SYM_KEY_LENGTH..],
    )
    .map_err(|e| Error::JsonParsing(e.to_string()))
}

fn decrypt_header(
    encrypted_header: &EncryptedHeader,
    user_decryption_key: &UserSecretKey,
    authentication_data: &[u8],
) -> Result<CleartextHeader, Error> {
    let authentication_data = Uint8Array::from(authentication_data);
    let encrypted_header_bytes =
        Uint8Array::from(encrypted_header.try_to_bytes().unwrap().as_slice());
    let sk_u = Uint8Array::from(user_decryption_key.try_to_bytes()?.as_slice());
    let decrypted_header_bytes =
        webassembly_decrypt_hybrid_header(sk_u, encrypted_header_bytes, authentication_data)
            .map_err(|e| Error::Other(e.as_string().unwrap()))?;
    CleartextHeader::try_from_bytes(&decrypted_header_bytes.to_vec())
        .map_err(|e| Error::JsonParsing(e.to_string()))
}

#[wasm_bindgen_test]
fn test_encrypt_decrypt() {
    //
    // Policy settings
    //
    let policy = policy().unwrap();
    let access_policy_string = "Department::FIN && Security Level::Top Secret";

    //
    // CoverCrypt setup
    //

    let policy_bytes = serde_json::to_vec(&policy).unwrap();
    let master_keys = webassembly_generate_master_keys(policy_bytes.clone())
        .unwrap()
        .to_vec();
    let msk_len = u32::from_be_bytes(<[u8; 4]>::try_from(&master_keys[..4]).unwrap()) as usize;
    let usk = webassembly_generate_user_secret_key(
        Uint8Array::from(&master_keys[4..msk_len + 4]),
        access_policy_string,
        policy_bytes.clone(),
    )
    .unwrap()
    .to_vec();

    //
    // Encrypt / decrypt
    //
    let header_metadata = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
    let authentication_data = vec![10, 11, 12, 13, 14];

    let plaintext = "My secret message!";

    let res = webassembly_hybrid_encrypt(
        policy_bytes,
        access_policy_string.to_string(),
        Uint8Array::from(&master_keys[4 + msk_len..]),
        Uint8Array::from(plaintext.as_bytes()),
        Uint8Array::from(header_metadata.as_slice()),
        Uint8Array::from(authentication_data.as_slice()),
    )
    .unwrap();

    let res = webassembly_hybrid_decrypt(
        Uint8Array::from(usk.as_slice()),
        res,
        Uint8Array::from(authentication_data.as_slice()),
    )
    .unwrap()
    .to_vec();

    let mut de = Deserializer::new(res.as_slice());
    let decrypted_header_metadata = de.read_vec().unwrap();
    let decrypted_plaintext = de.finalize();

    assert_eq!(plaintext.as_bytes(), decrypted_plaintext);
    assert_eq!(header_metadata, decrypted_header_metadata);
}

#[wasm_bindgen_test]
fn test_generate_keys() {
    //
    // Policy settings
    //
    let policy = policy().unwrap();
    let policy_bytes = serde_json::to_vec(&policy).unwrap();

    //
    // Generate master keys
    let master_keys = webassembly_generate_master_keys(policy_bytes.clone()).unwrap();
    let master_keys_vec = master_keys.to_vec();
    let msk_size = u32::from_be_bytes(master_keys_vec[0..4].try_into().unwrap()) as usize;
    let msk_bytes = &master_keys_vec[4..4 + msk_size];

    //
    // Check deserialization
    MasterSecretKey::try_from_bytes(msk_bytes).unwrap();
    PublicKey::try_from_bytes(&master_keys_vec[4 + msk_size..]).unwrap();

    //
    // Generate user secret key
    let usk_bytes = webassembly_generate_user_secret_key(
        Uint8Array::from(msk_bytes),
        "Department::FIN && Security Level::Top Secret",
        policy_bytes.clone(),
    )
    .unwrap()
    .to_vec();
    let usk = UserSecretKey::try_from_bytes(&usk_bytes).unwrap();

    let access_policy_string = "Security Level::Confidential".to_string();
    let attributes = Array::new();
    attributes.push(&JsValue::from(JsString::from(access_policy_string.clone())));
    let new_policy = webassembly_rotate_attributes(
        Attributes::from(JsValue::from(attributes)),
        policy_bytes.clone(),
    )
    .unwrap();

    //
    // Generate master keys
    let master_keys = webassembly_generate_master_keys(new_policy).unwrap();
    let master_keys_vec = master_keys.to_vec();
    let secret_key_size = u32::from_be_bytes(master_keys_vec[..4].try_into().unwrap()) as usize;
    let secret_key_bytes = &master_keys_vec[4..4 + secret_key_size];
    MasterSecretKey::try_from_bytes(secret_key_bytes).unwrap();
    let master_public_key =
        PublicKey::try_from_bytes(&master_keys_vec[4 + secret_key_size..]).unwrap();

    //
    // Encrypt / decrypt
    //

    let header_metadata = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
    let authentication_data = vec![10, 11, 12, 13, 14];

    let encrypted_header = encrypt_header(
        &policy,
        access_policy_string,
        &master_public_key,
        &header_metadata,
        &authentication_data,
    )
    .unwrap();

    //
    // Try to decrypt with a non-refreshed secret key (it fails)
    //
    assert!(decrypt_header(&encrypted_header, &usk, &authentication_data).is_err());

    //
    // Refresh user secret key
    let usk_bytes = webassembly_generate_user_secret_key(
        Uint8Array::from(secret_key_bytes),
        "Security Level::Confidential",
        policy_bytes,
    )
    .unwrap()
    .to_vec();
    let usk = UserSecretKey::try_from_bytes(&usk_bytes).unwrap();

    //
    // Decrypt with the refreshed secret key (it now works)
    //
    decrypt_header(&encrypted_header, &usk, &authentication_data).unwrap();
}
