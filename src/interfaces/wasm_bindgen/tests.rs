use abe_policy::{AccessPolicy, Attribute, Policy, PolicyAxis};
use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable};
/// Test WASM bindgen functions prerequisites:
/// - `cargo install wasm-bindgen-cli`
/// - `cargo test --target wasm32-unknown-unknown --release --features
///   wasm_bindgen --lib`
use js_sys::Uint8Array;
use wasm_bindgen_test::wasm_bindgen_test;

use super::generate_cc_keys::webassembly_rotate_attributes;
use crate::{
    api::CoverCrypt,
    error::Error,
    interfaces::{
        statics::{
            ClearTextHeader, CoverCryptX25519Aes256, EncryptedHeader, MasterSecretKey, PublicKey,
            UserSecretKey,
        },
        wasm_bindgen::{
            generate_cc_keys::{
                webassembly_generate_master_keys, webassembly_generate_user_secret_key,
            },
            hybrid_cc_aes::{
                webassembly_decrypt_hybrid_header, webassembly_encrypt_hybrid_header,
                webassembly_hybrid_decrypt, webassembly_hybrid_encrypt,
            },
        },
    },
};

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
    policy: &Policy,
    access_policy_string: String,
    public_key: &PublicKey,
    additional_data: &[u8],
    authentication_data: &[u8],
) -> Result<EncryptedHeader, Error> {
    let additional_data = Uint8Array::from(additional_data);
    let authentication_data = Uint8Array::from(authentication_data);
    let policy_bytes = Uint8Array::from(serde_json::to_vec(policy)?.as_slice());
    let public_key_bytes = Uint8Array::from(public_key.try_to_bytes()?.as_slice());
    let encrypted_header = webassembly_encrypt_hybrid_header(
        policy_bytes,
        access_policy_string,
        public_key_bytes,
        additional_data,
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
) -> Result<ClearTextHeader, Error> {
    let authentication_data = Uint8Array::from(authentication_data);
    let encrypted_header_bytes =
        Uint8Array::from(encrypted_header.try_to_bytes().unwrap().as_slice());
    let sk_u = Uint8Array::from(user_decryption_key.try_to_bytes()?.as_slice());
    let decrypted_header_bytes =
        webassembly_decrypt_hybrid_header(sk_u, encrypted_header_bytes, authentication_data)
            .map_err(|e| Error::Other(e.as_string().unwrap()))?;
    ClearTextHeader::try_from_bytes(&decrypted_header_bytes.to_vec())
        .map_err(|e| Error::JsonParsing(e.to_string()))
}

#[wasm_bindgen_test]
fn test_encrypt_decrypt() {
    //
    // Policy settings
    //
    let policy = create_test_policy();
    let access_policy_string = "Department::FIN && Security Level::Top Secret";

    //
    // CoverCrypt setup
    //

    let serialized_policy = serde_json::to_vec(&policy).unwrap();
    let master_keys =
        webassembly_generate_master_keys(Uint8Array::from(serialized_policy.as_slice()))
            .unwrap()
            .to_vec();
    let msk_len = u32::from_be_bytes(<[u8; 4]>::try_from(&master_keys[..4]).unwrap()) as usize;
    let usk = webassembly_generate_user_secret_key(
        Uint8Array::from(&master_keys[4..msk_len + 4]),
        access_policy_string,
        Uint8Array::from(serialized_policy.as_slice()),
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
        Uint8Array::from(serialized_policy.as_slice()),
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
    let policy = create_test_policy();
    let serialized_policy = serde_json::to_vec(&policy).unwrap();

    //
    // Generate master keys
    let master_keys =
        webassembly_generate_master_keys(Uint8Array::from(serialized_policy.as_slice())).unwrap();
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
        Uint8Array::from(serialized_policy.as_slice()),
    )
    .unwrap()
    .to_vec();
    let usk = UserSecretKey::try_from_bytes(&usk_bytes).unwrap();

    let access_policy_string = "Security Level::Confidential".to_string();
    let serialized_attributes = serde_json::to_vec(
        &AccessPolicy::from_boolean_expression(&access_policy_string)
            .unwrap()
            .attributes(),
    )
    .unwrap();

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
    let secret_key_size = u32::from_be_bytes(master_keys_vec[..4].try_into().unwrap()) as usize;
    let secret_key_bytes = &master_keys_vec[4..4 + secret_key_size];
    MasterSecretKey::try_from_bytes(secret_key_bytes).unwrap();
    let master_public_key =
        PublicKey::try_from_bytes(&master_keys_vec[4 + secret_key_size..]).unwrap();

    //
    // Encrypt / decrypt
    //

    let additional_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
    let authentication_data = vec![10, 11, 12, 13, 14];

    let encrypted_header = encrypt_header(
        &policy,
        access_policy_string,
        &master_public_key,
        &additional_data,
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
        Uint8Array::from(serialized_policy.as_slice()),
    )
    .unwrap()
    .to_vec();
    let usk = UserSecretKey::try_from_bytes(&usk_bytes).unwrap();

    //
    // Decrypt with the refreshed secret key (it now works)
    //
    decrypt_header(&encrypted_header, &usk, &authentication_data).unwrap();
}
