//! Exposes a post-quantum PKE for use in the Covercrypt scheme.
//!
//! Current implementation only uses Krystal Kyber, but support for more
//! algorithms may be developed in the future.

use std::ops::{Deref, DerefMut};

use crate::Error;
use cosmian_crypto_core::{bytes_ser_de::Serializable, reexport::rand_core::CryptoRngCore, Secret};
use pqc_kyber::{
    public, KYBER_CIPHERTEXTBYTES, KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES, KYBER_SSBYTES,
};

use super::KemTrait;

/// Kyber public key length
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey(Box<[u8; Self::LENGTH]>);

impl PublicKey {
    pub const LENGTH: usize = KYBER_PUBLICKEYBYTES;
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

impl From<[u8; Self::LENGTH]> for PublicKey {
    fn from(bytes: [u8; Self::LENGTH]) -> Self {
        Self(Box::new(bytes))
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
    pub const LENGTH: usize = KYBER_SECRETKEYBYTES;

    pub fn pk(&self) -> PublicKey {
        public(self).into()
    }
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

impl From<&mut [u8; Self::LENGTH]> for SecretKey {
    fn from(bytes: &mut [u8; Self::LENGTH]) -> Self {
        Self(Secret::from_unprotected_bytes(bytes))
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

impl Ciphertext {
    pub const LENGTH: usize = KYBER_CIPHERTEXTBYTES;
}

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

impl From<[u8; Self::LENGTH]> for Ciphertext {
    fn from(bytes: [u8; Self::LENGTH]) -> Self {
        Self(Box::new(bytes))
    }
}

impl TryFrom<&[u8]> for Ciphertext {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = <[u8; Self::LENGTH]>::try_from(bytes)
            .map_err(|e| Error::ConversionFailed(e.to_string()))?;
        Ok(Self::from(bytes))
    }
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

pub type SharedSecret = Secret<KYBER_SSBYTES>;

#[derive(Debug, Default)]
pub struct Kyber;

impl KemTrait for Kyber {
    type Error = Error;

    type Encapsulation = Ciphertext;

    type SecretKey = SecretKey;

    type PublicKey = PublicKey;

    type SharedSecret = SharedSecret;

    fn keygen(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SecretKey, Self::PublicKey), Self::Error> {
        let mut keypair = pqc_kyber::keypair(rng)?;
        Ok((
            SecretKey::from(&mut keypair.secret),
            PublicKey::from(keypair.public),
        ))
    }

    fn encaps(
        &self,
        rng: &mut impl CryptoRngCore,
        pk: &Self::PublicKey,
    ) -> Result<(Self::SharedSecret, Self::Encapsulation), Self::Error> {
        let (enc, mut secret) = pqc_kyber::encapsulate(pk, rng)?;
        Ok((
            Secret::from_unprotected_bytes(&mut secret),
            Ciphertext::from(enc),
        ))
    }

    fn decaps(
        &self,
        sk: &Self::SecretKey,
        encapsulation: &Self::Encapsulation,
    ) -> Result<Self::SharedSecret, Self::Error> {
        let mut secret = pqc_kyber::decapsulate(encapsulation, sk)?;
        Ok(Secret::from_unprotected_bytes(&mut secret))
    }
}
