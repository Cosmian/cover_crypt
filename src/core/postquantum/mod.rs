mod kyber;
mod traits;

use cosmian_crypto_core::{reexport::rand_core::CryptoRngCore, Aes256Gcm, SymmetricKey};
pub use kyber::{PublicKey, SecretKey};
pub use traits::{KemTrait, PkeTrait};

use crate::Error;

use super::ae::AE;

#[derive(Debug, Default)]
pub struct MlKemAesPke;

impl PkeTrait<{ Aes256Gcm::KEY_LENGTH }> for MlKemAesPke {
    type Kem = kyber::Kyber;
    type Ae = Aes256Gcm;
    type Ciphertext = Vec<u8>;
    type Error = Error;

    fn keygen(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        (
            <Self::Kem as KemTrait>::SecretKey,
            <Self::Kem as KemTrait>::PublicKey,
        ),
        Self::Error,
    > {
        kyber::Kyber.keygen(rng)
    }

    fn encrypt(
        &self,
        rng: &mut impl CryptoRngCore,
        pk: &<Self::Kem as KemTrait>::PublicKey,
        ptx: &[u8],
    ) -> Result<Self::Ciphertext, Self::Error> {
        let (secret, enc) = kyber::Kyber.encaps(rng, pk)?;
        let key = SymmetricKey::derive(&secret, &enc)?;
        let ctx = Aes256Gcm::encrypt(rng, &key, ptx)?;
        Ok([&*enc, &ctx].concat())
    }

    fn decrypt(
        &self,
        sk: &<Self::Kem as KemTrait>::SecretKey,
        ctx: &Self::Ciphertext,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
        // A ciphertext contains at least a Kyber encapsulation, an AES MAC and a nonce.
        const EXPECTED_LENGTH: usize =
            kyber::Ciphertext::LENGTH + Aes256Gcm::MAC_LENGTH + Aes256Gcm::NONCE_LENGTH;

        if ctx.len() < EXPECTED_LENGTH {
            return Err(Error::ConversionFailed(format!(
                "ML-KEM/AES PKE ciphertext size too small: {} (should be at least {})",
                ctx.len(),
                EXPECTED_LENGTH
            )));
        }

        let encapsulation = kyber::Ciphertext::try_from(&ctx[..kyber::Ciphertext::LENGTH])?;
        let aes_ctx = &ctx[kyber::Ciphertext::LENGTH..];
        let secret = kyber::Kyber.decaps(sk, &encapsulation)?;
        let key = SymmetricKey::derive(&secret, &encapsulation)?;
        Aes256Gcm::decrypt(&key, aes_ctx)
    }
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};

    use super::{MlKemAesPke, PkeTrait};

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = CsRng::from_entropy();
        let pke = MlKemAesPke;
        let ptx = b"a secret text";
        let (sk, pk) = pke.keygen(&mut rng).unwrap();
        let ctx = pke.encrypt(&mut rng, &pk, ptx).unwrap();
        let res = pke.decrypt(&sk, &ctx).unwrap();
        assert_eq!(ptx, &**res);
    }

    #[test]
    fn test_pk_from_sk() {
        let mut rng = CsRng::from_entropy();
        let (sk, pk) = MlKemAesPke.keygen(&mut rng).unwrap();
        assert_eq!(pk, sk.pk());
    }
}
