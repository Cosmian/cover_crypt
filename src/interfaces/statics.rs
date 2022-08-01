//! Implement hybrid cryptography based on the CoverCrypt KEM and the DEM based
//! on AES 256 GCM from `cosmian_crypto_core`.

use crate::{
    api::CoverCrypt,
    cover_crypt_core::{Encapsulation, PublicKey, UserPrivateKey},
    error::Error,
};
use abe_policy::{Attribute, Policy};
use cosmian_crypto_core::{
    entropy::CsRng,
    symmetric_crypto::{Block, Dem, Metadata},
    KeyTrait,
};
use serde::{Deserialize, Serialize};
use std::ops::DerefMut;

/// An EncryptedHeader returned by the `encrypt_hybrid_header` function
#[derive(Serialize, Deserialize)]
pub struct EncryptedHeader<DEM: Dem> {
    pub symmetric_key: DEM::Key,
    pub header_bytes: Vec<u8>,
}

/// A ClearTextHeader returned by the `decrypt_hybrid_header` function
#[derive(Serialize, Deserialize, Debug)]
pub struct ClearTextHeader<DEM: Dem> {
    pub symmetric_key: DEM::Key,
    pub meta_data: Metadata,
}

/// Generate an encrypted header.
///
/// A header contains the following elements:
///
/// - `encapsulation_size`  : the size of the symmetric key encapsulation (u32)
/// - `encapsulation`       : symmetric key encapsulation using CoverCrypt
/// - `encrypted_metadata`  : Optional metadata encrypted using the DEM
///
/// Parameters:
///
/// - `policy`          : global policy
/// - `public_key`      : CoverCrypt public key
/// - `attributes`      : attributes used for encryption
/// - `meta_data`       : optional meta data
pub fn encrypt_hybrid_header<DEM: Dem>(
    policy: &Policy,
    public_key: &PublicKey,
    attributes: &[Attribute],
    meta_data: Option<&Metadata>,
) -> Result<EncryptedHeader<DEM>, Error> {
    // generate symmetric key and its encapsulation
    let cover_crypt = CoverCrypt::new();
    let (secret_key, encapsulation) =
        cover_crypt.generate_symmetric_key(policy, public_key, attributes, DEM::Key::LENGTH)?;
    let encapsulation = encapsulation.try_to_bytes()?;

    // Allocate enough space to the header bytes
    let mut header_bytes = Vec::with_capacity(
        4 + encapsulation.len() + meta_data.map_or(0, |metadata| metadata.len()),
    );

    header_bytes.extend(
        u32::try_from(encapsulation.len())
            .map_err(|e| Error::InvalidSize(e.to_string()))?
            .to_be_bytes(),
    );
    header_bytes.extend(encapsulation);

    // encrypt metadata
    let meta_data = meta_data
        .map(|metadata| -> Result<Vec<u8>, Error> {
            metadata.try_to_bytes().map_err(|_| Error::ConversionFailed)
        })
        .unwrap_or_else(|| Ok(vec![]))?;

    header_bytes.extend(
        DEM::encaps(
            cover_crypt
                .rng
                .lock()
                .expect("Mutex lock failed!")
                .deref_mut(),
            &secret_key,
            None,
            &meta_data,
        )
        .map_err(Error::CryptoError)?,
    );

    Ok(EncryptedHeader {
        symmetric_key: DEM::Key::try_from_bytes(&secret_key).map_err(Error::CryptoError)?,
        header_bytes,
    })
}

/// Decrypt the given header bytes using a user decryption key.
///
/// - `user_decryption_key` : private key to use for decryption
/// - `header_bytes`        : encrypted header bytes
pub fn decrypt_hybrid_header<DEM: Dem>(
    user_decryption_key: &UserPrivateKey,
    header_bytes: &[u8],
) -> Result<ClearTextHeader<DEM>, Error> {
    // get the encapsulation size (u32)
    let mut index = 4;
    if header_bytes.len() < index {
        return Err(Error::InvalidHeaderSize(header_bytes.len()));
    }
    let encapsulation_size: usize =
        u32::from_be_bytes(header_bytes[..index].try_into()?).try_into()?;
    if header_bytes.len() < encapsulation_size + index {
        return Err(Error::InvalidSize(format!(
            "Invalid Header bytes: the 4 first bytes (big endian encoded) give an u32 value \
             greater than the header size ({encapsulation_size} against {})",
            header_bytes.len() - index
        )));
    }
    // get the encapsulation
    let encapsulation =
        Encapsulation::try_from_bytes(&header_bytes[index..index + encapsulation_size])?;
    index += encapsulation_size;

    // decrypt the symmetric key
    let secret_keys =
        CoverCrypt::default().decaps_symmetric_key(user_decryption_key, &encapsulation)?;

    // decrypt the metadata if any
    for key in &secret_keys {
        if let Ok(plaintext) =
            DEM::decaps(key, None, &header_bytes[index..]).map_err(Error::CryptoError)
        {
            return Ok(ClearTextHeader {
                symmetric_key: DEM::Key::try_from_bytes(key).map_err(Error::CryptoError)?,
                meta_data: Metadata::try_from_bytes(&plaintext)
                    .map_err(|_| Error::ConversionFailed)?,
            });
        }
    }

    Err(Error::InsufficientAccessPolicy)
}

/// The overhead due to symmetric encryption when encrypting a block.
/// This is a constant
pub fn symmetric_encryption_overhead<DEM: Dem, const MAX_CLEAR_TEXT_SIZE: usize>() -> usize {
    Block::<DEM, MAX_CLEAR_TEXT_SIZE>::ENCRYPTION_OVERHEAD
}

/// Encrypt data symmetrically in a block.
///
/// The `uid` should be different for every resource  and `block_number`
/// different for every block. They are part of the AEAD of the symmetric scheme
/// if any.
///
/// The `MAX_CLEAR_TEXT_SIZE` fixes the maximum clear text that can fit in a
/// block. That value should be kept identical for all blocks of a resource.
///
/// The nonce, if any, occupies the first bytes of the encrypted block.
pub fn encrypt_symmetric_block<DEM: Dem, const MAX_CLEAR_TEXT_SIZE: usize>(
    symmetric_key: &DEM::Key,
    uid: &[u8],
    block_number: usize,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut block = Block::<DEM, MAX_CLEAR_TEXT_SIZE>::new();
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }
    if plaintext.len() > MAX_CLEAR_TEXT_SIZE {
        return Err(Error::InvalidSize(format!(
            "The data to encrypt is too large: {} bytes, max size: {} ",
            plaintext.len(),
            MAX_CLEAR_TEXT_SIZE
        )));
    }
    block
        .write(0, plaintext)
        .map_err(|e| Error::InvalidSize(e.to_string()))?;

    block
        .to_encrypted_bytes(&mut CsRng::new(), symmetric_key, uid, block_number)
        .map_err(Error::CryptoError)
}

/// Symmetrically decrypt encrypted block data.
///
/// The `uid` and `block_number` are part of the AEAD
/// of the crypto scheme (when applicable)
pub fn decrypt_symmetric_block<DEM: Dem, const MAX_CLEAR_TEXT_SIZE: usize>(
    symmetric_key: &DEM::Key,
    uid: &[u8],
    block_number: usize,
    encrypted_bytes: &[u8],
) -> Result<Vec<u8>, Error> {
    if encrypted_bytes.is_empty() {
        return Err(Error::EmptyCiphertext);
    }
    if encrypted_bytes.len() > Block::<DEM, MAX_CLEAR_TEXT_SIZE>::MAX_ENCRYPTED_LENGTH {
        return Err(Error::InvalidSize(format!(
            "The encrypted data to decrypt is too large: {} bytes, max size: {} ",
            encrypted_bytes.len(),
            Block::<DEM, MAX_CLEAR_TEXT_SIZE>::MAX_ENCRYPTED_LENGTH
        )));
    }
    let block = Block::<DEM, MAX_CLEAR_TEXT_SIZE>::from_encrypted_bytes(
        encrypted_bytes,
        symmetric_key,
        uid,
        block_number,
    )
    .map_err(Error::CryptoError)?;
    Ok(block.clear_text_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use abe_policy::{AccessPolicy, Attribute, PolicyAxis};
    use cosmian_crypto_core::symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto;

    #[derive(Debug, Serialize, Deserialize)]
    struct NonRegressionTestVector {
        public_key: String,
        private_key: String,
        policy: String,
        user_decryption_key: String,
        user_decryption_key_2: String,
        header_bytes: String,
        encrypted_bytes: String,
        uid: String,
    }

    #[test]
    fn test_hybrid_encryption_decryption() -> Result<(), Error> {
        //
        // Policy settings
        //
        let sec_level = PolicyAxis::new(
            "Security Level",
            &[
                "Protected",
                "Low Secret",
                "Medium Secret",
                "High Secret",
                "Top Secret",
            ],
            true,
        );
        let department = PolicyAxis::new("Department", &["R&D", "HR", "MKG", "FIN"], false);
        let mut policy = Policy::new(100);
        policy.add_axis(&sec_level)?;
        policy.add_axis(&department)?;
        policy.rotate(&Attribute::new("Department", "FIN"))?;
        let attributes = vec![
            Attribute::new("Security Level", "Low Secret"),
            Attribute::new("Department", "HR"),
            Attribute::new("Department", "FIN"),
        ];
        let access_policy = AccessPolicy::new("Security Level", "Top Secret")
            & (AccessPolicy::new("Department", "FIN") | AccessPolicy::new("Department", "MKG"));
        let access_policy_2 = AccessPolicy::new("Security Level", "Medium Secret")
            & AccessPolicy::new("Department", "MKG");

        //
        // CoverCrypt setup
        //
        let cc = CoverCrypt::default();
        let (msk, mpk) = cc.generate_master_keys(&policy)?;
        let top_secret_mkg_fin_user =
            cc.generate_user_private_key(&msk, &access_policy, &policy)?;
        let medium_secret_mkg_user =
            cc.generate_user_private_key(&msk, &access_policy_2, &policy)?;

        //
        // Encrypt/decrypt header
        //
        let metadata = Metadata {
            uid: 1u32.to_be_bytes().to_vec(),
            additional_data: None,
        };
        let encrypted_header =
            encrypt_hybrid_header::<Aes256GcmCrypto>(&policy, &mpk, &attributes, Some(&metadata))?;
        let res = decrypt_hybrid_header::<Aes256GcmCrypto>(
            &top_secret_mkg_fin_user,
            &encrypted_header.header_bytes,
        )?;

        assert_eq!(metadata, res.meta_data);

        let message = b"My secret message";
        const MAX_CLEARTEXT_SIZE: usize = 256;
        let encrypted_block = encrypt_symmetric_block::<Aes256GcmCrypto, MAX_CLEARTEXT_SIZE>(
            &encrypted_header.symmetric_key,
            &metadata.uid,
            0,
            message,
        )?;

        let res = decrypt_symmetric_block::<Aes256GcmCrypto, MAX_CLEARTEXT_SIZE>(
            &encrypted_header.symmetric_key,
            &metadata.uid,
            0,
            &encrypted_block,
        )?;

        assert_eq!(message.to_vec(), res);

        // Generate regression vectors
        let mut encrypted_bytes = (encrypted_header.header_bytes.len() as u32)
            .to_be_bytes()
            .to_vec();
        encrypted_bytes.extend_from_slice(&encrypted_header.header_bytes);
        encrypted_bytes.extend_from_slice(&encrypted_block);

        let reg_vectors = NonRegressionTestVector {
            public_key: hex::encode(mpk.try_to_bytes()?),
            private_key: hex::encode(msk.try_to_bytes()?),
            policy: hex::encode(serde_json::to_vec(&policy)?),
            user_decryption_key: hex::encode(top_secret_mkg_fin_user.try_to_bytes()?),
            user_decryption_key_2: hex::encode(medium_secret_mkg_user.try_to_bytes()?),
            header_bytes: hex::encode(encrypted_header.header_bytes.clone()),
            encrypted_bytes: hex::encode(encrypted_bytes),
            uid: hex::encode(metadata.uid),
        };
        std::fs::write(
            "non_regression_vector.json",
            serde_json::to_string(&reg_vectors).unwrap(),
        )
        .unwrap();

        Ok(())
    }

    #[test]
    fn test_non_reg_decrypt_hybrid_header() {
        let reg_vector: NonRegressionTestVector =
            serde_json::from_str(include_str!("../../non_regression_vector.json")).unwrap();
        let user_decryption_key = UserPrivateKey::try_from_bytes(
            &hex::decode(reg_vector.user_decryption_key.as_bytes()).unwrap(),
        )
        .unwrap();
        let header_bytes = hex::decode(reg_vector.header_bytes.as_bytes()).unwrap();
        assert!(decrypt_hybrid_header::<Aes256GcmCrypto>(
            &user_decryption_key,
            &header_bytes[4..], // provoke InvalidSize error
        )
        .is_err());
    }

    fn policy() -> Result<Policy, Error> {
        let sec_level = PolicyAxis::new(
            "Security Level",
            &["Protected", "Confidential", "Top Secret"],
            true,
        );
        let department = PolicyAxis::new("Department", &["R&D", "HR", "MKG", "FIN"], false);
        let mut policy = Policy::new(100);
        policy.add_axis(&sec_level)?;
        policy.add_axis(&department)?;
        Ok(policy)
    }

    #[test]
    fn test_single_attribute_in_access_policy() -> Result<(), Error> {
        //
        // Declare policy
        let policy = policy()?;

        //
        // Setup CoverCrypt
        let cc = CoverCrypt::default();
        let (master_private_key, _master_public_key) = cc.generate_master_keys(&policy)?;

        //
        // New user private key
        let access_policy = AccessPolicy::from_boolean_expression("Security Level::Top Secret")?;
        let _user_key =
            cc.generate_user_private_key(&master_private_key, &access_policy, &policy)?;

        Ok(())
    }

    #[test]
    fn test_rotate_then_encrypt() -> Result<(), Error> {
        //
        // Declare policy
        let mut policy = policy()?;

        //
        // Setup CoverCrypt
        let cc = CoverCrypt::default();
        let (mut master_private_key, mut master_public_key) = cc.generate_master_keys(&policy)?;

        //
        // New user private key
        let access_policy =
            AccessPolicy::from_boolean_expression("Security Level::Top Secret && Department::FIN")?;
        let user_key =
            cc.generate_user_private_key(&master_private_key, &access_policy, &policy)?;

        //
        // Encrypt
        let encrypted_header = encrypt_hybrid_header::<Aes256GcmCrypto>(
            &policy,
            &master_public_key,
            &[Attribute::from(("Security Level", "Top Secret"))],
            None,
        )?;

        let _cleartext_header =
            decrypt_hybrid_header::<Aes256GcmCrypto>(&user_key, &encrypted_header.header_bytes)?;

        //
        // Rotate argument (must update master keys)
        policy.rotate(&Attribute::from(("Security Level", "Top Secret")))?;
        cc.update_master_keys(&policy, &mut master_private_key, &mut master_public_key)?;

        //
        // Encrypt with new attribute
        let encrypted_header = encrypt_hybrid_header::<Aes256GcmCrypto>(
            &policy,
            &master_public_key,
            &[Attribute::from(("Security Level", "Top Secret"))],
            None,
        )?;

        assert!(decrypt_hybrid_header::<Aes256GcmCrypto>(
            &user_key,
            &encrypted_header.header_bytes,
        )
        .is_err());

        Ok(())
    }
}
