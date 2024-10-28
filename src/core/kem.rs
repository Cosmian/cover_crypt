use cosmian_crypto_core::{bytes_ser_de::Serializable, reexport::rand_core::CryptoRngCore, Secret};
use ml_kem::{
    array::Array,
    kem::{Decapsulate, Encapsulate},
    EncodedSizeUser, KemCore,
};
use zeroize::Zeroize;

use crate::{core::SHARED_SECRET_LENGTH, Error};

pub trait Kem {
    type EncapsulationKey;
    type DecapsulationKey;
    type SessionKey;
    type Encapsulation;
    type Error: std::error::Error;

    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error>;

    fn enc(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SessionKey, Self::Encapsulation), Self::Error>;

    fn dec(
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<Self::SessionKey, Self::Error>;
}

#[derive(Debug, PartialEq, Clone)]
pub struct EncapsulationKey512(Box<<ml_kem::MlKem512 as KemCore>::EncapsulationKey>);

impl Serializable for EncapsulationKey512 {
    type Error = Error;

    fn length(&self) -> usize {
        800
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        let mut bytes = self.0.as_bytes();
        let n = ser.write_array(&bytes)?;
        bytes.zeroize();
        Ok(n)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let mut bytes = Array::from(de.read_array::<800>()?);
        let ek = <<ml_kem::MlKem512 as KemCore>::EncapsulationKey>::from_bytes(&bytes);
        bytes.zeroize();
        Ok(Self(Box::new(ek)))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecapsulationKey512(Box<<ml_kem::MlKem512 as KemCore>::DecapsulationKey>);

impl DecapsulationKey512 {
    pub fn ek(&self) -> EncapsulationKey512 {
        EncapsulationKey512(Box::new(self.0.encapsulation_key().clone()))
    }
}

impl Serializable for DecapsulationKey512 {
    type Error = Error;

    fn length(&self) -> usize {
        1632
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        let mut bytes = self.0.as_bytes();
        let n = ser.write_array(&bytes)?;
        bytes.zeroize();
        Ok(n)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let mut bytes = Array::from(de.read_array::<1632>()?);
        let dk = <<ml_kem::MlKem512 as KemCore>::DecapsulationKey>::from_bytes(&bytes);
        bytes.zeroize();
        Ok(Self(Box::new(dk)))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Encapsulation512(Box<Array<u8, <ml_kem::MlKem512 as KemCore>::CiphertextSize>>);

impl Serializable for Encapsulation512 {
    type Error = Error;

    fn length(&self) -> usize {
        768
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        Ok(ser.write_array(&self.0)?)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        Ok(Self(Box::new(Array::<
            u8,
            <ml_kem::MlKem512 as KemCore>::CiphertextSize,
        >::from(de.read_array::<768>()?))))
    }
}

pub struct MlKem512;

impl Kem for MlKem512 {
    type EncapsulationKey = EncapsulationKey512;
    type DecapsulationKey = DecapsulationKey512;
    type SessionKey = Secret<SHARED_SECRET_LENGTH>;

    type Encapsulation = Encapsulation512;

    type Error = Error;

    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error> {
        let (dk, ek) = <ml_kem::MlKem512 as KemCore>::generate(rng);
        Ok((
            DecapsulationKey512(Box::new(dk)),
            EncapsulationKey512(Box::new(ek)),
        ))
    }

    fn enc(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SessionKey, Self::Encapsulation), Self::Error> {
        let (enc, mut ss) =
            ek.0.encapsulate(rng)
                .map_err(|e| Error::Kem(format!("{:?}", e)))?;
        let ss = Secret::from_unprotected_bytes(ss.as_mut());
        Ok((ss, Encapsulation512(Box::new(enc))))
    }

    fn dec(
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<Self::SessionKey, Self::Error> {
        let mut ss =
            dk.0.decapsulate(&enc.0)
                .map_err(|e| Self::Error::Kem(format!("{e:?}")))?;
        let ss = Secret::from_unprotected_bytes(ss.as_mut());
        Ok(ss)
    }
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{
        bytes_ser_de::test_serialization, reexport::rand_core::SeedableRng, CsRng,
    };

    use super::*;

    #[test]
    fn test_mlkem() {
        let mut rng = CsRng::from_entropy();
        let (dk, ek) = MlKem512::keygen(&mut rng).unwrap();
        test_serialization(&dk).unwrap();
        test_serialization(&ek).unwrap();
        let (ss1, enc) = MlKem512::enc(&ek, &mut rng).unwrap();
        test_serialization(&enc).unwrap();
        let ss2 = MlKem512::dec(&dk, &enc).unwrap();
        assert_eq!(ss1, ss2);
    }
}
