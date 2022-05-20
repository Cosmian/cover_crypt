use crate::{
    cover_crypt_core,
    error::Error,
    policy::{self, AccessPolicy, Policy},
};
use cosmian_crypto_base::{entropy::CsRng, hybrid_crypto::Kem};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt::Display, marker::PhantomData, ops::DerefMut, sync::Mutex};

const KDF_INFO: &[u8] = b"Need to extend generated secret key.";

/// Authorisation associated to a KEM keypair. It corresponds to a combination
/// of attributes.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Hash)]
#[serde(try_from = "String", into = "String")]
pub struct Authorisation(Vec<u8>);

impl Display for Authorisation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl From<Authorisation> for String {
    fn from(a: Authorisation) -> Self {
        format!("{a}")
    }
}

impl TryFrom<String> for Authorisation {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let res = hex::decode(&value).map_err(|_e| Error::ConversionFailed)?;
        Ok(Authorisation(res))
    }
}

/// Ciphertext of the CoverCrypt algorithm. This is a `HashMap` of the KEM
/// encapsulations for some authorisations.
pub type CipherText = cover_crypt_core::Encapsulation<Authorisation>;

/// Private key of the CoverCrypt algorithm. This is a `HashMap` of the KEM
/// private keys for some authorisations.
pub type PrivateKey<KEM> = cover_crypt_core::PrivateKey<Authorisation, KEM>;

/// Public key of the CoverCrypt algorithm. This is a `HashMap` of the KEM
/// public keys for some authorisations.
pub type PublicKey<KEM> = cover_crypt_core::PublicKey<Authorisation, KEM>;

/// CoverCrypt public and private key pair.
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
    pub(crate) rng: Mutex<CsRng>,
    phantom_kem: PhantomData<KEM>,
}

impl<KEM: Kem> CoverCrypt<KEM> {
    /// Instantiate a new CoverCrypt object.
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
        let keys = policy::walk_hypercube(0, axes.as_slice(), policy)?
            .iter()
            .map(|combination| Authorisation(policy::get_key_hash(combination)))
            .collect();
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
            .map(|comb| Authorisation(policy::get_key_hash(comb)))
            .collect();
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
        access_policy
            .to_attribute_combinations(policy)?
            .iter()
            .map(|comb| {
                let authorisation = Authorisation(policy::get_key_hash(comb));
                // authorisation should be contained in the master key in
                // order to generate a valid user key
                let kem_public_key = mpk
                    .get(&authorisation)
                    .ok_or_else(|| Error::UnknownAuthorisation(format!("{:?}", authorisation)))?;
                Ok((authorisation.to_owned(), kem_public_key.to_owned()))
            })
            // `PublicKey` is an alias to a `HashMap` which is collected here
            .collect()
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
        // get the authorisations associated to the given access policy
        let authorisations = access_policy
            .to_attribute_combinations(policy)?
            .iter()
            .map(|comb| Authorisation(policy::get_key_hash(comb)))
            .collect();
        let (mut K, E) = cover_crypt_core::encaps::<_, _, KEM>(
            &mut self.rng.lock().expect("Mutex lock failed!").deref_mut(),
            pk,
            &authorisations,
        )?;
        // expend keying data if needed
        if sym_key_len > K.len() {
            K = cosmian_crypto_base::kdf::hkdf_256(&K, sym_key_len, KDF_INFO)
                .map_err(Error::CryptoError)?;
        } else {
            K = K[..sym_key_len].to_owned();
        }
        Ok((K, E))
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
        let key =
            cover_crypt_core::decaps::<_, KEM>(sk_u, c)?.ok_or(Error::InsufficientAccessPolicy)?;
        if sym_key_len > key.len() {
            cosmian_crypto_base::kdf::hkdf_256(&key, sym_key_len, KDF_INFO)
                .map_err(Error::CryptoError)
        } else {
            Ok(key[..sym_key_len].to_owned())
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
    use crate::policy::{Attribute, PolicyAxis};
    use cosmian_crypto_base::asymmetric::ristretto::X25519Crypto;
    use eyre::Result;

    #[test]
    fn encrypt_decrypt_sym_key() -> Result<()> {
        const KEY_LENGTH: usize = 256;
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
        let access_policy = (AccessPolicy::new("Department", "R&D")
            | AccessPolicy::new("Department", "FIN"))
            & AccessPolicy::new("Security Level", "Top Secret");
        let cc = CoverCrypt::<X25519Crypto>::default();
        let (msk, mpk) = cc.generate_master_keys(&policy)?;
        let sk_u = cc.generate_user_private_key(&msk, &access_policy, &policy)?;
        let (key, encrypted_key) =
            cc.generate_symmetric_key(&policy, &mpk, &access_policy, KEY_LENGTH)?;
        let recovered_key = cc.decrypt_symmetric_key(&sk_u, &encrypted_key, KEY_LENGTH)?;
        eyre::ensure!(key == recovered_key, "Wrong decryption of the key!");
        Ok(())
    }
}
