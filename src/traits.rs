use cosmian_crypto_core::{reexport::rand_core::CryptoRngCore, Secret, SymmetricKey};
use std::ops::Add;
use std::ops::AddAssign;
use std::ops::Div;
use std::ops::Mul;
use std::ops::MulAssign;
use std::ops::Sub;
use std::ops::SubAssign;
use zeroize::Zeroizing;

use crate::AccessPolicy;

pub trait KemAc<const LENGTH: usize> {
    type EncapsulationKey;
    type DecapsulationKey;
    type Encapsulation;
    type Error: std::error::Error;

    /// Generates a new encapsulation for the given access policy.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is not valid.
    fn encaps(
        &self,
        ek: &Self::EncapsulationKey,
        ap: &AccessPolicy,
    ) -> Result<(Secret<LENGTH>, Self::Encapsulation), Self::Error>;

    /// Attempts opening the given encapsulation with the given key. Returns the encapsulated
    /// secret upon success or `None` if this key was not authorized to open this encapsulation.
    fn decaps(
        &self,
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<Option<Secret<LENGTH>>, Self::Error>;
}

pub trait AE<const KEY_LENGTH: usize> {
    type Error: std::error::Error;

    /// Encrypts the given plaintext using the given key.
    fn encrypt(
        rng: &mut impl CryptoRngCore,
        key: &SymmetricKey<KEY_LENGTH>,
        ptx: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Decrypts the given ciphertext using the given key.
    ///
    /// # Error
    ///
    /// Returns an error if the integrity of the ciphertext could not be verified.
    fn decrypt(
        key: &SymmetricKey<KEY_LENGTH>,
        ctx: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error>;
}

pub trait PkeAc<const KEY_LENGTH: usize, E: AE<KEY_LENGTH>> {
    type EncryptionKey;
    type DecryptionKey;
    type Ciphertext;
    type Error: std::error::Error;

    /// Encrypts the given plaintext under the given access policy.
    ///
    /// # Error
    ///
    /// Returns an error if the access policy is not valid.
    fn encrypt(
        &self,
        ek: &Self::EncryptionKey,
        ap: &AccessPolicy,
        ptx: &[u8],
    ) -> Result<Self::Ciphertext, Self::Error>;

    /// Attempts decrypting the given ciphertext with the given key. Returns the
    /// plaintext upon success, or `None` if this key was not authorized to
    /// decrypt this ciphertext.
    fn decrypt(
        &self,
        usk: &Self::DecryptionKey,
        ctx: &Self::Ciphertext,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error>;
}

pub trait Kem {
    type EncapsulationKey;
    type DecapsulationKey;
    type SessionKey;
    type Encapsulation;
    type Error: std::error::Error;

    /// Generates a new random keypair.
    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error>;

    /// Generates an encapsulation of a random session key, and returns both the
    /// key and its encapsulation.
    fn enc(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SessionKey, Self::Encapsulation), Self::Error>;

    /// Attempts opening the given encapsulation. Upon failure to decapsulate,
    /// returns a random session key.
    fn dec(
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<Self::SessionKey, Self::Error>;
}

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

pub trait Sampling {
    fn random(rng: &mut impl CryptoRngCore) -> Self;
    fn hash(seed: &[u8]) -> Self;
}

pub trait Zero {
    fn zero() -> Self;
    fn is_zero(&self) -> bool;
}

pub trait One {
    fn one() -> Self;
    fn is_one(&self) -> bool;
}

pub trait Group:
    Sized
    + Zero
    + Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
where
    for<'a, 'b> &'a Self: Add<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Sub<&'b Self, Output = Self>,
{
}

pub trait Ring:
    Group
    + Zero
    + Mul<Output = Self>
    + MulAssign
    + Div<Output = Result<Self, Self::DivError>>
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> Div<&'a Self, Output = Result<Self, Self::DivError>>
where
    for<'a, 'b> &'a Self: Add<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Sub<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Mul<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Div<&'b Self, Output = Result<Self, Self::DivError>>,
{
    type DivError;
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
