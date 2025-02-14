use std::iter::Sum;
use std::ops::Add;
use std::ops::AddAssign;
use std::ops::Deref;
use std::ops::Div;
use std::ops::DivAssign;
use std::ops::Mul;
use std::ops::MulAssign;
use std::ops::Sub;
use std::ops::SubAssign;

use cosmian_crypto_core::bytes_ser_de::Deserializer;
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_crypto_core::bytes_ser_de::Serializer;
use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;

pub use cosmian_crypto_core::R25519PrivateKey as Scalar;
pub use cosmian_crypto_core::R25519PublicKey as EcPoint;
use tiny_keccak::Hasher;
use tiny_keccak::Sha3;
use zeroize::Zeroize;

use crate::traits::Group;
use crate::traits::KeyHomomorphicNike;
use crate::traits::Nike;
use crate::traits::One;
use crate::traits::Ring;
use crate::traits::Sampling;
use crate::traits::Zero;
use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct R25519Point(EcPoint);

impl One for R25519Point {
    fn one() -> Self {
        Self(EcPoint::generator())
    }

    fn is_one(&self) -> bool {
        self.0 == EcPoint::generator()
    }
}

impl Zero for R25519Point {
    fn zero() -> Self {
        Self(EcPoint::identity())
    }

    fn is_zero(&self) -> bool {
        self == &Self::zero()
    }
}

impl Add for R25519Point {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + &rhs.0)
    }
}

impl Add<&R25519Point> for R25519Point {
    type Output = Self;

    fn add(self, rhs: &R25519Point) -> Self::Output {
        Self(self.0 + &rhs.0)
    }
}

impl Add<&R25519Point> for &R25519Point {
    type Output = R25519Point;

    fn add(self, rhs: &R25519Point) -> Self::Output {
        R25519Point(&self.0 + &rhs.0)
    }
}

impl AddAssign for R25519Point {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = &self.0 + &rhs.0;
    }
}

impl Sub for R25519Point {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(&self.0 - &rhs.0)
    }
}

impl SubAssign for R25519Point {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = &self.0 - &rhs.0
    }
}

impl Sub<&R25519Point> for R25519Point {
    type Output = Self;

    fn sub(self, rhs: &R25519Point) -> Self::Output {
        Self(&self.0 - &rhs.0)
    }
}

impl Sub<&R25519Point> for &R25519Point {
    type Output = R25519Point;

    fn sub(self, rhs: &R25519Point) -> Self::Output {
        R25519Point(&self.0 - &rhs.0)
    }
}

impl Group for R25519Point {}

impl Serializable for R25519Point {
    type Error = Error;

    fn length(&self) -> usize {
        self.0.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        self.0.write(ser).map_err(Self::Error::from)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        de.read().map(Self).map_err(Self::Error::from)
    }
}

impl Sum for R25519Point {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |a, p| a + p)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct R25519Scalar(Scalar);

impl Deref for R25519Scalar {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_bytes()
    }
}

impl Zero for R25519Scalar {
    fn zero() -> Self {
        Self(Scalar::zero())
    }

    fn is_zero(&self) -> bool {
        self == &Self::zero()
    }
}

impl One for R25519Scalar {
    fn one() -> Self {
        Self(Scalar::one())
    }

    fn is_one(&self) -> bool {
        self == &Self::one()
    }
}

impl Add for R25519Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign for R25519Scalar {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = &self.0 + &rhs.0;
    }
}

impl Add<&R25519Scalar> for R25519Scalar {
    type Output = Self;

    fn add(self, rhs: &R25519Scalar) -> Self::Output {
        Self(&self.0 + &rhs.0)
    }
}

impl Add<&R25519Scalar> for &R25519Scalar {
    type Output = R25519Scalar;

    fn add(self, rhs: &R25519Scalar) -> Self::Output {
        R25519Scalar(&self.0 + &rhs.0)
    }
}

impl Sub for R25519Scalar {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(&self.0 - &rhs.0)
    }
}

impl SubAssign for R25519Scalar {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = &self.0 - &rhs.0
    }
}

impl Sub<&R25519Scalar> for R25519Scalar {
    type Output = Self;

    fn sub(self, rhs: &R25519Scalar) -> Self::Output {
        Self(&self.0 - &rhs.0)
    }
}

impl Sub<&R25519Scalar> for &R25519Scalar {
    type Output = R25519Scalar;

    fn sub(self, rhs: &R25519Scalar) -> Self::Output {
        R25519Scalar(&self.0 - &rhs.0)
    }
}

impl Mul for R25519Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(&self.0 * &rhs.0)
    }
}

impl MulAssign for R25519Scalar {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = &self.0 * &rhs.0
    }
}

impl Mul<&R25519Scalar> for R25519Scalar {
    type Output = Self;

    fn mul(self, rhs: &R25519Scalar) -> Self::Output {
        Self(&self.0 * &rhs.0)
    }
}

impl Mul<&R25519Scalar> for &R25519Scalar {
    type Output = R25519Scalar;

    fn mul(self, rhs: &R25519Scalar) -> Self::Output {
        R25519Scalar(&self.0 * &rhs.0)
    }
}

impl Div for R25519Scalar {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        Self(&self.0 / &rhs.0)
    }
}

impl DivAssign for R25519Scalar {
    fn div_assign(&mut self, rhs: Self) {
        self.0 = &self.0 / &rhs.0
    }
}

impl Div<&R25519Scalar> for R25519Scalar {
    type Output = Self;

    fn div(self, rhs: &R25519Scalar) -> Self::Output {
        Self(&self.0 / &rhs.0)
    }
}

impl Div<&R25519Scalar> for &R25519Scalar {
    type Output = R25519Scalar;

    fn div(self, rhs: &R25519Scalar) -> Self::Output {
        R25519Scalar(&self.0 / &rhs.0)
    }
}

impl Sum for R25519Scalar {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |a, s| a + s)
    }
}

impl Group for R25519Scalar {}

impl Ring for R25519Scalar {}

impl Serializable for R25519Scalar {
    type Error = Error;

    fn length(&self) -> usize {
        self.0.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        self.0.write(ser).map_err(Self::Error::from)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        de.read().map(Self).map_err(Self::Error::from)
    }
}

impl Sampling for R25519Scalar {
    fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(Scalar::new(rng))
    }

    fn hash(seed: &[u8]) -> Self {
        let mut hasher = Sha3::v512();
        let mut bytes = [0; 512 / 8];
        hasher.update(seed);
        hasher.finalize(&mut bytes);
        let s = Self(Scalar::from_raw_bytes(&bytes));
        bytes.zeroize();
        s
    }
}

impl From<&R25519Scalar> for R25519Point {
    fn from(s: &R25519Scalar) -> Self {
        Self(EcPoint::from(&s.0))
    }
}

impl Mul<R25519Scalar> for R25519Point {
    type Output = Self;

    fn mul(self, rhs: R25519Scalar) -> Self::Output {
        Self(&self.0 * &rhs.0)
    }
}

impl MulAssign<R25519Scalar> for R25519Point {
    fn mul_assign(&mut self, rhs: R25519Scalar) {
        self.0 = &self.0 * &rhs.0
    }
}

impl Mul<&R25519Scalar> for R25519Point {
    type Output = Self;

    fn mul(self, rhs: &R25519Scalar) -> Self::Output {
        Self(&self.0 * &rhs.0)
    }
}

impl Mul<&R25519Scalar> for &R25519Point {
    type Output = R25519Point;

    fn mul(self, rhs: &R25519Scalar) -> Self::Output {
        R25519Point(&self.0 * &rhs.0)
    }
}

pub struct R25519;

impl Nike for R25519 {
    type SecretKey = R25519Scalar;
    type PublicKey = R25519Point;
    type SessionKey = R25519Point;
    type Error = Error;

    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SecretKey, Self::PublicKey), Self::Error> {
        let sk = Self::SecretKey::random(rng);
        let pk = Self::PublicKey::from(&sk);
        Ok((sk, pk))
    }

    fn session_key(
        sk: &Self::SecretKey,
        pk: &Self::PublicKey,
    ) -> Result<Self::SessionKey, Self::Error> {
        Ok(pk * sk)
    }
}

impl KeyHomomorphicNike for R25519 {}

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
