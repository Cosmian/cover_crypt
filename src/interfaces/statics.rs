use crate::{
    api::{CoverCrypt, PrivateKey, PublicKey},
    error::Error,
    policy::{AccessPolicy, Attribute, Policy},
};
use cosmian_crypto_base::{
    entropy::CsRng,
    hybrid_crypto::{Block, Dem, Kem, Metadata},
    KeyTrait,
};
use std::ops::DerefMut;

/// An EncryptedHeader returned by the `encrypt_hybrid_header` function
pub struct EncryptedHeader<DEM: Dem> {
    pub symmetric_key: DEM::Key,
    pub header_bytes: Vec<u8>,
}

/// A ClearTextHeader returned by the `decrypt_hybrid_header` function
pub struct ClearTextHeader<DEM: Dem> {
    pub symmetric_key: DEM::Key,
    pub meta_data: Metadata,
}

/// Generate an encrypted header. A header contains the following elements:
///
/// - `encapsulation_size`  : the size of the symmetric key encapsulation (u32)
/// - `encapsulation`       : symmetric key encapsulation using CoverCrypt
/// - `encrypted_metadata`  : Optional metadata encrypted using the DEM
///
/// Parameters:
///
/// - `policy`          : global policy
/// - `public_key`      : CoverCrypt public key
/// - `access_policy`   : access policy
/// - `meta_data`       : optional meta data
pub fn encrypt_hybrid_header<KEM: Kem, DEM: Dem>(
    policy: &Policy,
    public_key: &PublicKey<KEM>,
    attributes: &[Attribute],
    meta_data: Option<&Metadata>,
) -> Result<EncryptedHeader<DEM>, Error> {
    // generate symmetric key and its encapsulation
    let cover_crypt = CoverCrypt::<KEM>::new();
    let (K, E) = cover_crypt.generate_symmetric_key(
        policy,
        public_key,
        &AccessPolicy::from_attribute_list(attributes)?,
        DEM::Key::LENGTH,
    )?;
    let encapulation = serde_json::to_vec(&E).map_err(|e| Error::JsonParsing(e.to_string()))?;

    // create header
    let mut header_bytes = Vec::new();

    header_bytes.extend(
        u32::try_from(encapulation.len())
            .map_err(|e| Error::InvalidSize(e.to_string()))?
            .to_be_bytes(),
    );
    header_bytes.extend(encapulation);

    // encrypt metadata if it is given
    if let Some(meta_data) = meta_data {
        header_bytes.extend(
            DEM::encaps(
                cover_crypt
                    .rng
                    .lock()
                    .expect("Mutex lock failed!")
                    .deref_mut(),
                &K,
                b"",
                &meta_data.to_bytes().map_err(|_| Error::ConversionFailed)?,
            )
            .map_err(Error::CryptoError)?,
        );
    }

    Ok(EncryptedHeader {
        symmetric_key: DEM::Key::try_from(K).map_err(Error::CryptoError)?,
        header_bytes,
    })
}

/// Decrypt with a user decryption key an encrypted header
/// of a resource encrypted using an hybrid crypto scheme.
pub fn decrypt_hybrid_header<KEM: Kem, DEM: Dem>(
    user_decryption_key: &PrivateKey<KEM>,
    header_bytes: &[u8],
) -> Result<ClearTextHeader<DEM>, Error> {
    // get the encapsulation size (u32)
    let mut index = 4;
    let encapsulation_size = u32::from_be_bytes(header_bytes[..index].try_into()?) as usize;

    // get the encapsulation
    let E = header_bytes[index..index + encapsulation_size].to_owned();
    index += encapsulation_size;

    // decrypt the symmetric key
    let cover_crypt = CoverCrypt::<KEM>::default();
    let K = cover_crypt.decrypt_symmetric_key(
        user_decryption_key,
        &serde_json::from_slice(&E).map_err(|e| Error::JsonParsing(e.to_string()))?,
        DEM::Key::LENGTH,
    )?;

    // decrypt the metadata
    let metadata = DEM::decaps(&K, b"", &header_bytes[index..]).map_err(Error::CryptoError)?;

    Ok(ClearTextHeader {
        symmetric_key: DEM::Key::try_from(K).map_err(Error::CryptoError)?,
        meta_data: Metadata::from_bytes(&metadata).map_err(|_| Error::ConversionFailed)?,
    })
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
pub fn encrypt_hybrid_block<KEM: Kem, DEM: Dem, const MAX_CLEAR_TEXT_SIZE: usize>(
    symmetric_key: &DEM::Key,
    uid: &[u8],
    block_number: usize,
    clear_text: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut block = Block::<DEM, MAX_CLEAR_TEXT_SIZE>::new();
    if clear_text.len() > MAX_CLEAR_TEXT_SIZE {
        return Err(Error::InvalidSize(format!(
            "The data to encrypt is too large: {} bytes, max size: {} ",
            clear_text.len(),
            MAX_CLEAR_TEXT_SIZE
        )));
    }
    block
        .write(0, clear_text)
        .map_err(|e| Error::InvalidSize(e.to_string()))?;

    block
        .to_encrypted_bytes(&mut CsRng::new(), symmetric_key, uid, block_number)
        .map_err(Error::CryptoError)
}

/// Symmetrically Decrypt encrypted data in a block.
///
/// The `uid` and `block_number` are part of the AEAD
/// of the crypto scheme (when applicable)
pub fn decrypt_hybrid_block<KEM: Kem, DEM: Dem, const MAX_CLEAR_TEXT_SIZE: usize>(
    symmetric_key: &DEM::Key,
    uid: &[u8],
    block_number: usize,
    encrypted_bytes: &[u8],
) -> Result<Vec<u8>, Error> {
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
