use cosmian_crypto_base::{
    entropy::CsRng,
    hybrid_crypto::{Dem, Kem},
};
use sha3::{Digest, Sha3_256};
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    sync::Mutex,
};

use crate::{
    cover_crypt_core,
    error::Error,
    policy::{attr, Policy},
};

pub type PrivateKey<KEM> = cover_crypt_core::PrivateKey<Vec<u8>, KEM>;
pub type MasterPrivateKey<KEM> = cover_crypt_core::PrivateKey<Vec<u8>, KEM>;
pub type PublicKey<KEM> = cover_crypt_core::PublicKey<Vec<u8>, KEM>;

/// The engine is the main entry point for the core functionalities.
///
/// It supplies a simple API that lets generate keys, encrypt and decrypt
/// messages.
///
/// In addition, two methods are supplied to generate random symmetric keys and
/// their corresponding cipher texts which are suitable for use in a hybrid
/// encryption scheme.
pub struct CoverCrypt<KEM, DEM> {
    rng: Mutex<CsRng>,
    phantom_kem: PhantomData<KEM>,
    phantom_dem: PhantomData<DEM>,
}

impl<KEM: Kem, DEM: Dem> CoverCrypt<KEM, DEM> {
    /// Instantiate a new ABE engine for the given Policy
    #[must_use]
    pub fn new() -> Self {
        Self {
            rng: Mutex::new(CsRng::new()),
            phantom_kem: PhantomData,
            phantom_dem: PhantomData,
        }
    }

    /// Generate the master authority keys for supplied Policy
    pub fn generate_master_key(
        &self,
        policy: &Policy,
    ) -> Result<(PrivateKey<KEM>, PublicKey<KEM>), Error> {
        // we need to generate all the possible combinations for all the values across all the axes
        // fix the axes list
        let axes: Vec<&str> = policy
            .store()
            .keys()
            .into_iter()
            .map(String::as_str)
            .collect();
        // we walk the hypercube to recover all the locations and hash them to keep them "small"
        let set: HashSet<Vec<u8>> = walk_hypercube(0, &axes, policy)?
            .iter()
            .map(|v| {
                // create a SHA3-256 object
                let mut hasher = Sha3_256::new();
                // write input message
                hasher.update(v);
                // read hash digest
                hasher.finalize().to_vec()
            })
            .collect::<HashSet<Vec<u8>>>();
        Ok(cover_crypt_core::setup::<Vec<u8>, CsRng, KEM>(
            &mut self.rng.lock().expect("a mutex lock failed"),
            &set,
        ))
    }

    // /// Generate a user decryption key
    // /// from the supplied Master Private Key and Access Policy
    // pub fn generate_user_key(
    //     &self,
    //     policy: &Policy,
    //     priv_key: &S::MasterPrivateKey,
    //     access_policy: &AccessPolicy,
    // ) -> Result<S::UserDecryptionKey, Error> {
    //     let msp = policy.to_msp(access_policy)?;
    //     self.sch.key_generation(&msp, priv_key)
    // }

    // /// Allows a user to generate a new key for a more restrictive policy
    // ///
    // /// A more restrictive policy is a policy that must always satisfy
    // /// the original policy when satisfied. In other words, we can only modify a
    // /// policy by changing an `Or` node by either an `And` or replace it by
    // /// one of its child.
    // ///
    // /// Remark: It is also possible to merge 2 keys by `Or` node, this latter
    // /// functionality is not yet supported
    // pub fn delegate_user_key(
    //     &self,
    //     policy: &Policy,
    //     del_key: &S::MasterPublicDelegationKey,
    //     user_key: &S::UserDecryptionKey,
    //     access_policy: &AccessPolicy,
    // ) -> Result<S::UserDecryptionKey, Error> {
    //     let msp = match access_policy {
    //         AccessPolicy::All => None,
    //         _ => Some(policy.to_msp(access_policy)?),
    //     };
    //     self.sch.key_delegation(&msp, user_key, del_key)
    // }

    // /// Generate a random point on GT
    // pub fn random_message(&self) -> Result<S::PlainText, Error> {
    //     self.sch.generate_random_plaintext()
    // }

    // /// Encrypt a plain text (a point on GT)
    // /// with the given list of policy attributes
    // pub fn encrypt(
    //     &self,
    //     policy: &Policy,
    //     public_key: &S::MasterPublicKey,
    //     attributes: &[Attribute],
    //     plain_text: &S::PlainText,
    // ) -> Result<S::CipherText, Error> {
    //     let int_attributes = policy.attributes_values(attributes)?;
    //     self.sch.encrypt(plain_text, &int_attributes, public_key)
    // }

    // /// Decrypt a cipher text returning the point on GT
    // pub fn decrypt(
    //     &self,
    //     enc: &S::CipherText,
    //     key: &S::UserDecryptionKey,
    // ) -> Result<Option<S::PlainText>, Error> {
    //     self.sch.decrypt(enc, key)
    // }

    // /// Generate a random symmetric key of `symmetric_key_len` to be used in an
    // /// hybrid encryption scheme and generate its ABE encrypted version with the
    // /// supplied policy `attributes`
    // pub fn generate_symmetric_key(
    //     &self,
    //     policy: &Policy,
    //     public_key: &S::MasterPublicKey,
    //     attrs: &[Attribute],
    //     symmetric_key_len: usize,
    // ) -> Result<(Vec<u8>, Vec<u8>), Error> {
    //     let random = self.random_message()?;
    //     let enc_sym_key = self
    //         .encrypt(policy, public_key, attrs, &random)?
    //         .as_bytes()?;
    //     // Use a hash of the plaintext bytes as the symmetric key
    //     let sym_key = Shake256::default()
    //         .chain(&random.as_bytes()?)
    //         .finalize_xof()
    //         .read_boxed(symmetric_key_len)
    //         .into_vec();
    //     Ok((sym_key, enc_sym_key))
    // }

    // /// Decrypt a symmetric key generated with `generate_symmetric_key()`
    // pub fn decrypt_symmetric_key(
    //     &self,
    //     decryption_key: &S::UserDecryptionKey,
    //     encrypted_symmetric_key: &[u8],
    //     symmetric_key_len: usize,
    // ) -> Result<Vec<u8>, Error> {
    //     let random = self
    //         .decrypt(
    //             &S::CipherText::from_bytes(encrypted_symmetric_key)?,
    //             decryption_key,
    //         )?
    //         .ok_or(Error::InvalidEncryptedData)?;
    //     // Use a hash of the plaintext bytes as the symmetric key
    //     Ok(Shake256::default()
    //         .chain(&random.as_bytes()?)
    //         .finalize_xof()
    //         .read_boxed(symmetric_key_len)
    //         .into_vec())
    // }
}

fn walk_hypercube(
    current_axis: usize,
    axes: &[&str],
    policy: &Policy,
) -> Result<Vec<Vec<u8>>, Error> {
    // for all attributes in this axis, return combination with values of all other remaining axes
    // the combination is made by concatenating the Big Endian bytes of th attributes values
    let axis_name = axes[current_axis];
    let last_axis = current_axis == axes.len() - 1;
    let (attribute_names, _hierarchical) = &policy.store()[axis_name];
    let mut res: Vec<Vec<u8>> = vec![];
    for attribute_name in attribute_names {
        let values: Vec<Vec<u8>> = policy
            .attribute_values(&attr(&axis_name, &attribute_name))?
            .iter()
            .map(|u| u.to_be_bytes().to_vec())
            .collect();
        res.extend(values);
    }
    if last_axis {
        return Ok(res);
    }
    let mut combinations: Vec<Vec<u8>> = vec![];
    for v in &res {
        let other_values = walk_hypercube(current_axis + 1, axes, policy)?;
        for ov in other_values {
            let mut combined = v.clone();
            combined.extend(ov);
            combinations.push(combined);
        }
    }
    Ok(combinations)
}

impl<KEM: Kem, DEM: Dem> Default for CoverCrypt<KEM, DEM> {
    fn default() -> Self {
        Self::new()
    }
}
