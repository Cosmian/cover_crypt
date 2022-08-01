use abe_policy::{AccessPolicy, Attribute, Policy, PolicyAxis};

use cosmian_crypto_core::symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Metadata};
use cover_crypt::{
    api::CoverCrypt,
    error::Error,
    interfaces::statics::{decrypt_hybrid_header, encrypt_hybrid_header, EncryptedHeader},
    PublicKey,
};

// Policy settings
pub fn policy() -> Result<Policy, Error> {
    let sec_level = PolicyAxis::new(
        "Security Level",
        &["Protected", "Confidential", "Top Secret"],
        true,
    );
    let department = PolicyAxis::new("Department", &["R&D", "HR", "MKG", "FIN"], false);
    let mut policy = Policy::new(100);
    policy.add_axis(&sec_level)?;
    policy.add_axis(&department)?;
    policy.rotate(&Attribute::new("Department", "FIN"))?;
    Ok(policy)
}

/// Generate encrypted header with some metadata
pub fn generate_encrypted_header(public_key: &PublicKey) -> EncryptedHeader<Aes256GcmCrypto> {
    let policy = policy().expect("cannot generate policy");
    let policy_attributes = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ];
    let metadata = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };

    encrypt_hybrid_header::<Aes256GcmCrypto>(
        &policy,
        public_key,
        &policy_attributes,
        Some(&metadata),
    )
    .expect("cannot encrypt header 1")
}

pub fn main() {
    let policy = policy().expect("cannot generate policy");

    let cc = CoverCrypt::default();
    let (msk, public_key) = cc
        .generate_master_keys(&policy)
        .expect("cannot generate master keys");
    let encrypted_header = generate_encrypted_header(&public_key);

    let access_policy =
        AccessPolicy::new("Department", "FIN") & AccessPolicy::new("Security Level", "Top Secret");
    let user_decryption_key = cc
        .generate_user_private_key(&msk, &access_policy, &policy)
        .expect("cannot generate user private key");

    for _i in 0..1000 {
        decrypt_hybrid_header::<Aes256GcmCrypto>(
            &user_decryption_key,
            &encrypted_header.header_bytes,
        )
        .expect("cannot decrypt hybrid header");
    }
}
