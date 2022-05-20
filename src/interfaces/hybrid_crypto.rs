#![allow(dead_code)]

use crate::{
    api::{self, CoverCrypt},
    error::Error,
    policy::{AccessPolicy, Policy},
};
use cosmian_crypto_base::{
    hybrid_crypto::{Dem, Kem},
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, SymmetricCrypto},
    KeyTrait,
};

/// Implement methods similar to HybridCrypto in order to use CoverCrypt to
/// encrypt messages.
impl<KEM: Kem> CoverCrypt<KEM> {
    /// Generate a user key pair.
    ///
    /// - `policy`          : global policy
    /// - `access_policy`   : user accesspolicy
    /// - `msk`             : master secret key
    /// - `mpk`             : master public key
    pub(crate) fn key_gen<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        msk: &api::PrivateKey<KEM>,
        mpk: &api::PublicKey<KEM>,
        policy: &Policy,
        access_policy: &AccessPolicy,
    ) -> Result<api::CCKeyPair<KEM>, Error> {
        Ok(api::CCKeyPair {
            sk: self.generate_user_private_key(msk, access_policy, policy)?,
            pk: self.generate_user_public_key(mpk, access_policy, policy)?,
        })
    }

    /// Encrypt the given message using the use public key.
    ///
    /// - `rng` : secure random number generator
    /// - `pk`  : user public key used for encryption
    /// - `L`   : label to use for encryption
    /// - `m`   : message to encrypt
    /// - `policy`          : global policy
    /// - `access_policy`   : user accesspolicy
    pub(crate) fn encrypt<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        pk: &api::PublicKey<KEM>,
        l: &[u8],
        m: &[u8],
        policy: &Policy,
        access_policy: &AccessPolicy,
    ) -> Result<(api::CipherText, Vec<u8>), Error> {
        let (K, E1) = self.generate_symmetric_key(
            policy,
            pk,
            access_policy,
            <Aes256GcmCrypto as SymmetricCrypto>::Key::LENGTH,
        )?;
        let E2 = Aes256GcmCrypto::encaps(rng, &K, l, m).map_err(Error::CryptoError)?;
        Ok((E1, E2))
    }

    /// Decrypt the given ciphertext using the user private key.
    ///
    /// - `sk`  : user private key used for encryption
    /// - `L`   : label used for encryption
    /// - `c`   : ciphertext
    pub(crate) fn decrypt(
        &self,
        sk: &api::PrivateKey<KEM>,
        l: &[u8],
        //C: &[u8],
        c: &(api::CipherText, Vec<u8>),
    ) -> Result<Vec<u8>, Error> {
        let K = self.decrypt_symmetric_key(
            sk,
            &c.0,
            <Aes256GcmCrypto as SymmetricCrypto>::Key::LENGTH,
        )?;
        <Aes256GcmCrypto>::decaps(&K, l, &c.1).map_err(Error::CryptoError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Attribute;
    use cosmian_crypto_base::{asymmetric::ristretto::X25519Crypto, entropy::CsRng};

    #[test]
    fn test_encrypt_decrypt() -> Result<(), Error> {
        //
        // Setup policy
        //
        let sec_level_attributes = vec!["Protected", "Confidential", "Top Secret"];
        let dept_attributes = vec!["R&D", "HR", "MKG", "FIN"];
        let mut policy = Policy::new(100)
            .add_axis("Security Level", &sec_level_attributes, true)?
            .add_axis("Department", &dept_attributes, false)?;
        let access_policy = AccessPolicy::new("Department", "R&D")
            & AccessPolicy::new("Security Level", "Top Secret");
        policy.rotate(&Attribute::new("Department", "FIN"))?;

        //
        // Setup CoverCrypt
        //
        let cc = CoverCrypt::<X25519Crypto>::default();
        let (msk, mpk) = cc.generate_master_keys(&policy)?;
        let key_pair = cc.key_gen::<CsRng>(&msk, &mpk, &policy, &access_policy)?;

        //
        // Encrypt / Decrypt
        //
        let m = b"My secret message";
        let l = b"My public label";
        let mut rng = CsRng::new();
        let c = cc.encrypt(
            &mut rng,
            key_pair.public_key(),
            l,
            m,
            &policy,
            &access_policy,
        )?;
        assert_eq!(m.to_vec(), cc.decrypt(key_pair.private_key(), l, &c)?);
        Ok(())
    }
}
