//! Exposes a post-quantum PKE for use in the Covercrypt scheme.
//!
//! Current implementation only uses Krystal Kyber, but support for more
//! algorithms may be developed in the future.

use std::ops::{Deref, DerefMut};

use crate::Error;
use cosmian_crypto_core::{bytes_ser_de::Serializable, reexport::rand_core::CryptoRngCore, Secret};
use pqc_kyber::{
    indcpa::{indcpa_dec, indcpa_enc, indcpa_keypair},
    KYBER_INDCPA_BYTES, KYBER_INDCPA_PUBLICKEYBYTES, KYBER_INDCPA_SECRETKEYBYTES, KYBER_SYMBYTES,
};

/// Kyber public key length
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey(Box<[u8; Self::LENGTH]>);

impl PublicKey {
    pub const LENGTH: usize = KYBER_INDCPA_PUBLICKEYBYTES;
}

impl Deref for PublicKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl DerefMut for PublicKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.0
    }
}

impl Serializable for PublicKey {
    type Error = Error;

    fn length(&self) -> usize {
        Self::LENGTH
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        ser.write_array(self).map_err(Self::Error::from)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        de.read_array()
            .map(Box::new)
            .map(Self)
            .map_err(Self::Error::from)
    }
}

/// Kyber secret key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey(Secret<{ Self::LENGTH }>);

impl SecretKey {
    pub const LENGTH: usize = KYBER_INDCPA_SECRETKEYBYTES;
}

impl Deref for SecretKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecretKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Serializable for SecretKey {
    type Error = Error;

    fn length(&self) -> usize {
        Self::LENGTH
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        ser.write_array(self).map_err(Self::Error::from)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let mut bytes = de.read_array()?;
        let secret = Secret::from_unprotected_bytes(&mut bytes);
        Ok(Self(secret))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ciphertext(Box<[u8; Self::LENGTH]>);

impl Deref for Ciphertext {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl DerefMut for Ciphertext {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.0
    }
}

impl Default for Ciphertext {
    fn default() -> Self {
        Self(Box::new([0; Self::LENGTH]))
    }
}

impl Ciphertext {
    pub const LENGTH: usize = KYBER_INDCPA_BYTES;
}

impl Serializable for Ciphertext {
    type Error = Error;

    fn length(&self) -> usize {
        Self::LENGTH
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        ser.write_array(self).map_err(Self::Error::from)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        de.read_array::<{ Self::LENGTH }>()
            .map(|bytes| Self(Box::new(bytes)))
            .map_err(Self::Error::from)
    }
}

/// Generates a new Kyber key pair.
pub fn keygen(rng: &mut impl CryptoRngCore) -> (SecretKey, PublicKey) {
    let (mut sk, mut pk) = (
        SecretKey(Secret::new()),
        PublicKey(Box::new([0; PublicKey::LENGTH])),
    );
    indcpa_keypair(&mut pk, &mut sk, None, rng);
    (sk, pk)
}

/// Encrypts the given secret using a post-quantum secure PKE.
///
/// # Security
///
/// The current implementation uses IND-CPA-Kyber 768, but plan for generalizing
/// it is on the way. It provides TODO bits of post-quantum security.
pub fn encrypt(
    rng: &mut impl CryptoRngCore,
    postquantum_pk: &PublicKey,
    ptx: &[u8],
) -> Result<Ciphertext, Error> {
    if KYBER_SYMBYTES != ptx.len() {
        return Err(Error::OperationNotPermitted(format!(
            "Kyber plaintext needs to be {KYBER_SYMBYTES} bytes: {} given",
            ptx.len()
        )));
    }
    let mut ctx = Ciphertext::default();
    let coin = Secret::<KYBER_SYMBYTES>::random(rng);
    indcpa_enc(&mut ctx, ptx, postquantum_pk, &coin);
    Ok(ctx)
}

/// Decrypts the given secret using a post-quantum secure PKE.
///
/// # Security
///
/// The current implementation uses IND-CPA-Kyber 768, but plan for generalizing
/// it is on the way. It provides TODO bits of post-quantum security.
pub fn decrypt(postquantum_sk: &SecretKey, ctx: &Ciphertext) -> Secret<KYBER_SYMBYTES> {
    let mut secret = Secret::<KYBER_SYMBYTES>::default();
    indcpa_dec(&mut secret, ctx, postquantum_sk);
    secret
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng, Secret};

    use super::{decrypt, encrypt, keygen, KYBER_SYMBYTES};

    #[test]
    fn test_kyber() {
        let mut rng = CsRng::from_entropy();
        let ptx = Secret::<KYBER_SYMBYTES>::random(&mut rng);
        let keypair = keygen(&mut rng);
        let ctx = encrypt(&mut rng, &keypair.1, &ptx)
            .expect("failed encryption with keypair {keypair:#?} and plaintext {ptx:#?}");
        let res = decrypt(&keypair.0, &ctx);
        assert_eq!(
            ptx, res,
            "wrong decryption with keypair {keypair:#?} and plaintext {ptx:#?}"
        )
    }
}
