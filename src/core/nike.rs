use std::ops::Add;
use std::ops::Mul;

use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;

pub use cosmian_crypto_core::R25519PrivateKey as Scalar;
pub use cosmian_crypto_core::R25519PublicKey as EcPoint;

use crate::Error;

pub trait Nike {
    type SecretKey;
    type PublicKey;
    type SessionKey;
    type Error: std::error::Error;

    /// Generates a new keypair.
    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SecretKey, Self::PublicKey), Self::Error>;

    /// Generates the session key associated to the given keypair.
    fn session_key(
        sk: &Self::SecretKey,
        pk: &Self::PublicKey,
    ) -> Result<Self::SessionKey, Self::Error>;
}

#[allow(dead_code)]
pub trait KhNike<S, G>: Nike<SecretKey = S, PublicKey = G, SessionKey = G>
where
    for<'a> &'a G: Mul<&'a S, Output = G> + Add<&'a G, Output = G>,
{
}

pub struct R25519;

impl Nike for R25519 {
    type SecretKey = Scalar;
    type PublicKey = EcPoint;
    type SessionKey = EcPoint;
    type Error = Error;

    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SecretKey, Self::PublicKey), Self::Error> {
        let sk = Scalar::new(rng);
        let pk = EcPoint::from(&sk);
        Ok((sk, pk))
    }

    fn session_key(
        sk: &Self::SecretKey,
        pk: &Self::PublicKey,
    ) -> Result<Self::SessionKey, Self::Error> {
        Ok(pk * sk)
    }
}

impl KhNike<Scalar, EcPoint> for R25519 {}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{
        bytes_ser_de::test_serialization, reexport::rand_core::SeedableRng, CsRng,
    };

    use super::*;

    #[test]
    fn test_r25519() {
        let mut rng = CsRng::from_entropy();
        let (sk1, pk1) = R25519::keygen(&mut rng).unwrap();
        let (sk2, pk2) = R25519::keygen(&mut rng).unwrap();
        test_serialization(&sk1).unwrap();
        test_serialization(&pk1).unwrap();
        test_serialization(&sk2).unwrap();
        test_serialization(&pk2).unwrap();
        let ss1 = R25519::session_key(&sk1, &pk2).unwrap();
        let ss2 = R25519::session_key(&sk2, &pk1).unwrap();
        assert_eq!(ss1, ss2);
    }
}
