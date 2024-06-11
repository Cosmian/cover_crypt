use cosmian_crypto_core::{
    reexport::rand_core::CryptoRngCore, Aes256Gcm, Dem, FixedSizeCBytes, Instantiable, Nonce,
    RandomFixedSizeCBytes, SymmetricKey,
};
use zeroize::Zeroizing;

use crate::Error;

/// Authenticated Encryption trait
pub trait AE<const KEY_LENGTH: usize> {
    /// Encrypts the given plaintext `ptx` using the given `key`.
    fn encrypt(
        rng: &mut impl CryptoRngCore,
        key: &SymmetricKey<KEY_LENGTH>,
        ptx: &[u8],
    ) -> Result<Vec<u8>, Error>;

    /// Decrypts the given ciphertext `ctx` using the given `key`.
    ///
    /// # Error
    ///
    /// Returns an error if the integrity of the ciphertext could not be verified.
    fn decrypt(key: &SymmetricKey<KEY_LENGTH>, ctx: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>;
}

impl AE<{ Self::KEY_LENGTH }> for Aes256Gcm {
    fn encrypt(
        rng: &mut impl CryptoRngCore,
        key: &SymmetricKey<{ Self::KEY_LENGTH }>,
        ptx: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let nonce = Nonce::<{ Self::NONCE_LENGTH }>::new(&mut *rng);
        let ciphertext = Self::new(key).encrypt(&nonce, ptx, None)?;
        Ok([nonce.as_bytes(), &ciphertext].concat())
    }

    fn decrypt(
        key: &SymmetricKey<{ Self::KEY_LENGTH }>,
        ctx: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if ctx.len() < Self::NONCE_LENGTH {
            return Err(Error::CryptoCoreError(
                cosmian_crypto_core::CryptoCoreError::DecryptionError,
            ));
        }
        let nonce = Nonce::try_from_slice(&ctx[..Self::NONCE_LENGTH])?;
        Self::new(key)
            .decrypt(&nonce, &ctx[Self::NONCE_LENGTH..], None)
            .map_err(Error::CryptoCoreError)
            .map(Zeroizing::new)
    }
}
