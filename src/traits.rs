use cosmian_crypto_core::{
    reexport::{rand_core::CryptoRngCore, zeroize::Zeroizing},
    SymmetricKey,
};
use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Sub, SubAssign};

pub trait Zero {
    fn zero() -> Self;
    fn is_zero(&self) -> bool;
}

pub trait One {
    fn one() -> Self;
    fn is_one(&self) -> bool;
}

pub trait Seedable<const LENGTH: usize> {
    fn from_seed(seed: &[u8; LENGTH]) -> Self;
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
