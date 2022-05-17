use crate::{
    cover_crypt_core,
    error::Error,
    policy::{self, AccessPolicy, Policy},
};
use cosmian_crypto_base::{asymmetric::KeyPair, entropy::CsRng, hybrid_crypto::Kem};
use std::{collections::HashSet, marker::PhantomData, ops::DerefMut, sync::Mutex};

const KDF_INFO: &[u8] = b"Need to extend generated secret key.";

pub type PlainText<KEM> = <<KEM as Kem>::KeyPair as KeyPair>::PublicKey;
pub type CipherText = cover_crypt_core::Encapsulation<Vec<u8>>;
pub type PrivateKey<KEM> = cover_crypt_core::PrivateKey<Vec<u8>, KEM>;
pub type PublicKey<KEM> = cover_crypt_core::PublicKey<Vec<u8>, KEM>;

#[derive(Clone, PartialEq)]
pub struct CCKeyPair<KEM: Kem> {
    pub(crate) pk: PublicKey<KEM>,
    pub(crate) sk: PrivateKey<KEM>,
}

impl<KEM: Kem> CCKeyPair<KEM> {
    pub fn public_key(&self) -> &PublicKey<KEM> {
        &self.pk
    }

    pub fn private_key(&self) -> &PrivateKey<KEM> {
        &self.sk
    }
}

/// The engine is the main entry point for the core functionalities.
///
/// It supplies a simple API that lets generate keys, encrypt and decrypt
/// messages.
///
/// In addition, two methods are supplied to generate random symmetric keys and
/// their corresponding cipher texts which are suitable for use in a hybrid
/// encryption scheme.
pub struct CoverCrypt<KEM> {
    rng: Mutex<CsRng>,
    phantom_kem: PhantomData<KEM>,
}

impl<KEM: Kem> CoverCrypt<KEM> {
    /// Instantiate a new ABE engine for the given Policy
    pub fn new() -> Self {
        Self {
            rng: Mutex::new(CsRng::new()),
            phantom_kem: PhantomData,
        }
    }

    /// Generate the master authority keys for supplied Policy
    ///
    ///  - `policy` : Policy to use to generate the keys
    pub fn generate_master_keys(
        &self,
        policy: &Policy,
    ) -> Result<(PrivateKey<KEM>, PublicKey<KEM>), Error> {
        // walk the hypercube to recover all the combinations and hash them
        let axes: Vec<&String> = policy.store().keys().collect();
        let keys: HashSet<Vec<u8>> = policy::walk_hypercube(0, axes.as_slice(), policy)?
            .iter()
            .map(|combination| policy::get_key_hash(combination))
            .collect::<HashSet<Vec<u8>>>();
        Ok(cover_crypt_core::setup::<_, CsRng, KEM>(
            &mut self.rng.lock().expect("a mutex lock failed"),
            &keys,
        ))
    }

    /// Generate a user private key.
    ///
    /// - `msk`             : master secret key
    /// - `access_policy`   : user access policy
    /// - `policy`          : global policy
    pub fn generate_user_private_key(
        &self,
        msk: &PrivateKey<KEM>,
        access_policy: &AccessPolicy,
        policy: &Policy,
    ) -> Result<PrivateKey<KEM>, Error> {
        // get the key hash associated with the given access policy
        let keys = access_policy
            .to_attribute_combinations(policy)?
            .iter()
            .map(|comb| policy::get_key_hash(comb))
            .collect::<HashSet<Vec<u8>>>();
        // generate the corresponding user key
        cover_crypt_core::join::<_, KEM>(msk, &keys)
    }

    /// Generate a user public key.
    ///
    /// - `mpk`             : master public key
    /// - `access_policy`   : user access policy
    /// - `policy`          : global policy
    pub fn generate_user_public_key(
        &self,
        mpk: &PublicKey<KEM>,
        access_policy: &AccessPolicy,
        policy: &Policy,
    ) -> Result<PublicKey<KEM>, Error> {
        // get the key hash associated with the given access policy
        let keys = access_policy
            .to_attribute_combinations(policy)?
            .iter()
            .map(|comb| policy::get_key_hash(comb))
            .collect::<HashSet<Vec<u8>>>();
        // generate the corresponding user key

        keys.iter()
            .map(
                |authorisation| -> Result<(Vec<u8>, <KEM::KeyPair as KeyPair>::PublicKey), Error> {
                    match mpk.get(authorisation) {
                        Some(key) => Ok((authorisation.to_owned(), key.to_owned())),
                        None => Err(Error::UnknownAuthorisation(format!("{:?}", authorisation))),
                    }
                },
            )
            .collect::<Result<PublicKey<KEM>, Error>>()
    }

    /// Generate a random symmetric key of `symmetric_key_len` to be used in an
    /// hybrid encryption scheme and generate its ABE encrypted version with the
    /// supplied policy `attributes`.
    ///
    /// - `policy`          : global policy
    /// - `pk`              : public key
    /// - `access_policy`   : access policy to use for key encryption
    /// - `sym_key_len`     : length of the symmetric key to generate
    pub fn generate_symmetric_key(
        &self,
        policy: &Policy,
        pk: &PublicKey<KEM>,
        access_policy: &AccessPolicy,
        sym_key_len: usize,
    ) -> Result<(Vec<u8>, CipherText), Error> {
        // get the key hash associated with the given access policy
        let keys = access_policy
            .to_attribute_combinations(policy)?
            .iter()
            .map(|comb| policy::get_key_hash(comb))
            .collect::<HashSet<Vec<u8>>>();
        let (mut key, encaps) = cover_crypt_core::encaps::<_, _, KEM>(
            &mut self.rng.lock().expect("Mutex lock failed!").deref_mut(),
            pk,
            &keys,
        )?;
        if sym_key_len > KEM::SECRET_KEY_LENGTH {
            key = cosmian_crypto_base::kdf::hkdf_256(&key, sym_key_len, KDF_INFO)
                .map_err(Error::CryptoError)?;
        }
        Ok((key, encaps))
    }

    /// Decrypt a symmetric key generated with `generate_symmetric_key()`
    ///
    /// - `sk_u`        : user secret key
    /// - `c`           : encrypted symmetric key
    /// - `sym_key_len` : length of the symmetric key to generate
    pub fn decrypt_symmetric_key(
        &self,
        sk_u: &PrivateKey<KEM>,
        c: &CipherText,
        sym_key_len: usize,
    ) -> Result<Vec<u8>, Error> {
        match cover_crypt_core::decaps::<_, KEM>(sk_u, c)? {
            None => Err(Error::InsufficientAccessPolicy),
            Some(key) => {
                if sym_key_len > KEM::SECRET_KEY_LENGTH {
                    cosmian_crypto_base::kdf::hkdf_256(&key, sym_key_len, KDF_INFO)
                        .map_err(Error::CryptoError)
                } else {
                    Ok(key)
                }
            }
        }
    }
}

impl<KEM: Kem> Default for CoverCrypt<KEM> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Attribute;
    use cosmian_crypto_base::asymmetric::ristretto::X25519Crypto;
    use eyre::Result;

    #[test]
    fn encrypt_decrypt_sym_key() -> Result<()> {
        const KEY_LENGTH: usize = 256;
        let sec_level_attributes = vec!["Protected", "Confidential", "Top Secret"];
        let dept_attributes = vec!["R&D", "HR", "MKG", "FIN"];
        let mut policy = Policy::new(100)
            .add_axis("Security Level", &sec_level_attributes, true)?
            .add_axis("Department", &dept_attributes, false)?;
        let access_policy = AccessPolicy::new("Department", "R&D")
            & AccessPolicy::new("Security Level", "Top Secret");
        // rotate an attributes
        policy.rotate(&Attribute::new("Department", "FIN"))?;
        let cc = CoverCrypt::<X25519Crypto>::default();
        let (msk, mpk) = cc.generate_master_keys(&policy)?;
        let sk_u = cc.generate_user_private_key(&msk, &access_policy, &policy)?;
        print!("there");
        let (key, encrypted_key) =
            cc.generate_symmetric_key(&policy, &mpk, &access_policy, KEY_LENGTH)?;
        let recovered_key = cc.decrypt_symmetric_key(&sk_u, &encrypted_key, KEY_LENGTH)?;
        eyre::ensure!(key == recovered_key, "Wrong decryption of the key!");
        Ok(())
    }
}
