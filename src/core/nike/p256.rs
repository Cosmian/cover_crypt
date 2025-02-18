use std::hash::Hash;
use std::iter::Sum;
use std::ops::Add;
use std::ops::AddAssign;
use std::ops::Div;
use std::ops::Mul;
use std::ops::MulAssign;
use std::ops::Sub;
use std::ops::SubAssign;

use cosmian_crypto_core::bytes_ser_de::Deserializer;
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_crypto_core::bytes_ser_de::Serializer;
use cosmian_crypto_core::CryptoCoreError;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::rand_core::CryptoRngCore;
use elliptic_curve::Field;
use elliptic_curve::PrimeField;
use p256::{ProjectivePoint, Scalar};
use subtle::ConstantTimeEq;
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
pub struct P256Point(ProjectivePoint);

impl One for P256Point {
    fn one() -> Self {
        Self(ProjectivePoint::GENERATOR)
    }

    fn is_one(&self) -> bool {
        self.0.ct_eq(&ProjectivePoint::GENERATOR).into()
    }
}

impl Zero for P256Point {
    fn zero() -> Self {
        Self(ProjectivePoint::IDENTITY)
    }

    fn is_zero(&self) -> bool {
        self.0.ct_eq(&ProjectivePoint::IDENTITY).into()
    }
}

impl Add for P256Point {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

impl Add<&P256Point> for P256Point {
    type Output = Self;

    fn add(self, rhs: &P256Point) -> Self::Output {
        &self + rhs
    }
}

impl Add<&P256Point> for &P256Point {
    type Output = P256Point;

    fn add(self, rhs: &P256Point) -> Self::Output {
        P256Point(&self.0 + &rhs.0)
    }
}

impl AddAssign for P256Point {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = &self.0 + &rhs.0;
    }
}

impl Sub for P256Point {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        &self - &rhs
    }
}

impl SubAssign for P256Point {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = &self.0 - &rhs.0
    }
}

impl Sub<&P256Point> for P256Point {
    type Output = Self;

    fn sub(self, rhs: &P256Point) -> Self::Output {
        &self - rhs
    }
}

impl Sub<&P256Point> for &P256Point {
    type Output = P256Point;

    fn sub(self, rhs: &P256Point) -> Self::Output {
        P256Point(&self.0 - &rhs.0)
    }
}

impl Group for P256Point {}

impl Serializable for P256Point {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        33
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write_array(&self.0.to_bytes())
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let bytes = de.read_array::<33>()?;
        let point = ProjectivePoint::from_bytes(&bytes.into())
            .into_option()
            .ok_or_else(|| {
                CryptoCoreError::GenericDeserializationError("cannot deserialize point".to_string())
            })?;
        Ok(Self(point))
    }
}

impl Sum for P256Point {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |a, p| a + p)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct P256Scalar(Scalar);

impl Hash for P256Scalar {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0.to_bytes());
    }
}

impl Zero for P256Scalar {
    fn zero() -> Self {
        Self(Scalar::ZERO)
    }

    fn is_zero(&self) -> bool {
        self.0.ct_eq(&Scalar::ZERO).into()
    }
}

impl One for P256Scalar {
    fn one() -> Self {
        Self(Scalar::ONE)
    }

    fn is_one(&self) -> bool {
        self.0.ct_eq(&Scalar::ONE).into()
    }
}

impl Add for P256Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

impl AddAssign for P256Scalar {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self.0 + rhs.0;
    }
}

impl Add<&P256Scalar> for P256Scalar {
    type Output = Self;

    fn add(self, rhs: &P256Scalar) -> Self::Output {
        &self + rhs
    }
}

impl Add<&P256Scalar> for &P256Scalar {
    type Output = P256Scalar;

    fn add(self, rhs: &P256Scalar) -> Self::Output {
        P256Scalar(self.0 + rhs.0)
    }
}

impl Sub for P256Scalar {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        &self - &rhs
    }
}

impl SubAssign for P256Scalar {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = &self.0 - &rhs.0
    }
}

impl Sub<&P256Scalar> for P256Scalar {
    type Output = Self;

    fn sub(self, rhs: &P256Scalar) -> Self::Output {
        &self - rhs
    }
}

impl Sub<&P256Scalar> for &P256Scalar {
    type Output = P256Scalar;

    fn sub(self, rhs: &P256Scalar) -> Self::Output {
        P256Scalar(&self.0 - &rhs.0)
    }
}

impl Mul for P256Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        &self * &rhs
    }
}

impl MulAssign for P256Scalar {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = &self.0 * &rhs.0
    }
}

impl Mul<&P256Scalar> for P256Scalar {
    type Output = Self;

    fn mul(self, rhs: &P256Scalar) -> Self::Output {
        &self * rhs
    }
}

impl Mul<&P256Scalar> for &P256Scalar {
    type Output = P256Scalar;

    fn mul(self, rhs: &P256Scalar) -> Self::Output {
        P256Scalar(&self.0 * &rhs.0)
    }
}

impl Div for P256Scalar {
    type Output = Result<Self, Error>;

    fn div(self, rhs: Self) -> Self::Output {
        &self / &rhs
    }
}

impl Div<&P256Scalar> for P256Scalar {
    type Output = Result<Self, Error>;

    fn div(self, rhs: &P256Scalar) -> Self::Output {
        &self / rhs
    }
}

impl Div<&P256Scalar> for &P256Scalar {
    type Output = Result<P256Scalar, Error>;

    fn div(self, rhs: &P256Scalar) -> Self::Output {
        rhs.0
            .invert()
            .map(|rhs| self.0 * rhs)
            .map(P256Scalar)
            .into_option()
            .ok_or_else(|| Error::OperationNotPermitted("Division by zero".to_string()))
    }
}

impl Sum for P256Scalar {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |a, s| a + s)
    }
}

impl Group for P256Scalar {}

impl Ring for P256Scalar {
    type DivError = Error;
}

impl Serializable for P256Scalar {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        32
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write_array(&self.0.to_bytes())
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let bytes = de.read_array::<32>()?;
        let scalar = Scalar::from_repr(bytes.into())
            .into_option()
            .ok_or_else(|| {
                CryptoCoreError::GenericDeserializationError(
                    "cannot deserialize scalar".to_string(),
                )
            })?;
        Ok(Self(scalar))
    }
}

impl Sampling for P256Scalar {
    fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(Scalar::random(rng))
    }

    fn hash(seed: &[u8]) -> Self {
        let mut i = 0u32;
        loop {
            let mut hasher = Sha3::v256();
            let mut bytes = [0; 32];
            hasher.update(seed);
            hasher.update(&i.to_be_bytes());
            hasher.finalize(&mut bytes);
            let s = Self::deserialize(&bytes);
            bytes.zeroize();
            if let Ok(s) = s {
                return s;
            } else {
                i += 1;
            }
        }
    }
}

impl From<&P256Scalar> for P256Point {
    fn from(s: &P256Scalar) -> Self {
        P256Point::one() * s
    }
}

impl Mul<P256Scalar> for P256Point {
    type Output = Self;

    fn mul(self, rhs: P256Scalar) -> Self::Output {
        &self * &rhs
    }
}

impl MulAssign<P256Scalar> for P256Point {
    fn mul_assign(&mut self, rhs: P256Scalar) {
        self.0 = &self.0 * &rhs.0
    }
}

impl Mul<&P256Scalar> for P256Point {
    type Output = Self;

    fn mul(self, rhs: &P256Scalar) -> Self::Output {
        &self * rhs
    }
}

impl Mul<&P256Scalar> for &P256Point {
    type Output = P256Point;

    fn mul(self, rhs: &P256Scalar) -> Self::Output {
        P256Point(&self.0 * &rhs.0)
    }
}

pub struct P256;

impl Nike for P256 {
    type SecretKey = P256Scalar;
    type PublicKey = P256Point;
    type SessionKey = P256Point;
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

impl KeyHomomorphicNike for P256 {}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{
        bytes_ser_de::test_serialization, reexport::rand_core::SeedableRng, CsRng,
    };

    use super::*;

    #[test]
    fn test_p256() {
        let mut rng = CsRng::from_entropy();
        let (sk1, pk1) = P256::keygen(&mut rng).unwrap();
        let (sk2, pk2) = P256::keygen(&mut rng).unwrap();
        test_serialization(&sk1).unwrap();
        test_serialization(&pk1).unwrap();
        test_serialization(&sk2).unwrap();
        test_serialization(&pk2).unwrap();
        let ss1 = P256::session_key(&sk1, &pk2).unwrap();
        let ss2 = P256::session_key(&sk2, &pk1).unwrap();
        assert_eq!(ss1, ss2);
    }
}
