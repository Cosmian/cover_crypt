use cosmian_crypto_core::{
    reexport::{rand_core::CryptoRngCore, zeroize::Zeroizing},
    Aes256Gcm, Dem, FixedSizeCBytes, Instantiable, Nonce, RandomFixedSizeCBytes, SymmetricKey,
};

use crate::{traits::AE, Error};

impl AE<{ Self::KEY_LENGTH }> for Aes256Gcm {
    type Error = Error;

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
