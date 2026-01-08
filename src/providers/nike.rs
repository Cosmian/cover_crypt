#[cfg(all(feature = "curve25519", feature = "p-256"))]
compile_error!("only one elliptic curve can be chosen at a time");

use crate::traits::{Group, Ring};
use cosmian_crypto_core::{reexport::rand_core::CryptoRngCore, Sampling};
use std::ops::{Add, Div, Mul, Sub};

#[cfg(all(feature = "curve25519", not(feature = "p-256")))]
mod r25519;

#[cfg(all(feature = "curve25519", not(feature = "p-256")))]
pub use r25519::R25519 as ElGamal;

#[cfg(all(feature = "p-256", not(feature = "curve25519")))]
mod p256;

#[cfg(all(feature = "p-256", not(feature = "curve25519")))]
pub use p256::P256 as ElGamal;

pub trait Nike {
    type SecretKey: Sampling;
    type PublicKey: for<'a> From<&'a Self::SecretKey>;
    type SessionKey;
    type Error: std::error::Error;

    /// Generates a new random keypair.
    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SecretKey, Self::PublicKey), Self::Error>;

    /// Generates the session key associated to the given keypair.
    fn session_key(
        sk: &Self::SecretKey,
        pk: &Self::PublicKey,
    ) -> Result<Self::SessionKey, Self::Error>;
}

pub trait KeyHomomorphicNike: Nike
where
    Self::PublicKey: Group,
    Self::SecretKey: Ring,
    Self::PublicKey: Mul<Self::SecretKey, Output = Self::PublicKey>,
    for<'a> Self::PublicKey: Mul<&'a Self::SecretKey, Output = Self::PublicKey>,
    for<'a, 'b> &'a Self::PublicKey: Add<&'b Self::PublicKey, Output = Self::PublicKey>,
    for<'a, 'b> &'a Self::PublicKey: Sub<&'b Self::PublicKey, Output = Self::PublicKey>,
    for<'a, 'b> &'a Self::SecretKey: Add<&'b Self::SecretKey, Output = Self::SecretKey>,
    for<'a, 'b> &'a Self::SecretKey: Sub<&'b Self::SecretKey, Output = Self::SecretKey>,
    for<'a, 'b> &'a Self::SecretKey: Mul<&'b Self::SecretKey, Output = Self::SecretKey>,
    for<'a, 'b> &'a Self::SecretKey: Div<
        &'b Self::SecretKey,
        Output = Result<Self::SecretKey, <Self::SecretKey as Ring>::DivError>,
    >,
{
}
