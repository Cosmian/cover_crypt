mod kyber;

use cosmian_crypto_core::{bytes_ser_de::Serializable, reexport::rand_core::CryptoRngCore};
pub use kyber::{decrypt, encrypt, keygen, Ciphertext, PublicKey, SecretKey};

use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keypair(SecretKey, PublicKey);

impl Keypair {
    /// Returns a new random keypair.
    #[must_use]
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let (sk, pk) = keygen(rng);
        Self(sk, pk)
    }

    /// Returns a reference on the secret key.
    #[must_use]
    pub fn sk(&self) -> &SecretKey {
        &self.0
    }

    /// Returns a reference on the public key.
    #[must_use]
    pub fn pk(&self) -> &PublicKey {
        &self.1
    }

    /// Returns true if the given secret key is contained in this keypair.
    pub fn contains(&self, sk: &SecretKey) -> bool {
        &self.0 == sk
    }
}

impl Serializable for Keypair {
    type Error = Error;

    fn length(&self) -> usize {
        self.0.length() + self.1.length()
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        let mut n = ser.write(&self.0)?;
        n += ser.write(&self.1)?;
        Ok(n)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let sk = de.read()?;
        let pk = de.read()?;
        Ok(Self(sk, pk))
    }
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{
        bytes_ser_de::Serializable, reexport::rand_core::SeedableRng, CsRng,
    };

    use super::Keypair;

    #[test]
    fn test_postquantum_keypair_serialization() {
        let mut rng = CsRng::from_entropy();
        let keypair = Keypair::random(&mut rng);
        let bytes = keypair.serialize().unwrap();
        assert_eq!(bytes.len(), keypair.length());
        let keypair_ = Keypair::deserialize(&bytes).unwrap();
        assert_eq!(keypair, keypair_);
    }
}
