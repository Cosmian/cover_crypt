use crate::Error;
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    reexport::{rand_core::CryptoRngCore, zeroize::Zeroize},
    traits::KEM,
    CryptoCoreError, Secret, SymmetricKey,
};
use ml_kem::{
    array::Array,
    kem::{Decapsulate, Encapsulate},
    EncodedSizeUser, KemCore,
};

const SHARED_SECRET_LENGTH: usize = 32;

macro_rules! make_mlkem {
    ($base: ident, $ek: ident, $ek_len: literal, $dk: ident, $dk_len: literal, $enc: ident, $enc_len:literal) => {
        #[derive(Debug, PartialEq, Clone)]
        pub struct $ek(Box<<ml_kem::$base as KemCore>::EncapsulationKey>);

        impl Serializable for $ek {
            type Error = CryptoCoreError;

            fn length(&self) -> usize {
                $ek_len
            }

            fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
                let mut bytes = self.0.as_bytes();
                let n = ser.write_array(&bytes)?;
                bytes.zeroize();
                Ok(n)
            }

            fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
                let mut bytes = Array::from(de.read_array::<$ek_len>()?);
                let ek = <<ml_kem::$base as KemCore>::EncapsulationKey>::from_bytes(&bytes);
                bytes.zeroize();
                Ok(Self(Box::new(ek)))
            }
        }

        #[derive(Debug, Clone, PartialEq)]
        pub struct $dk(Box<<ml_kem::$base as KemCore>::DecapsulationKey>);

        #[allow(dead_code)]
        impl $dk {
            pub fn ek(&self) -> $ek {
                $ek(Box::new(self.0.encapsulation_key().clone()))
            }
        }

        impl Serializable for $dk {
            type Error = CryptoCoreError;

            fn length(&self) -> usize {
                $dk_len
            }

            fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
                let mut bytes = self.0.as_bytes();
                let n = ser.write_array(&bytes)?;
                bytes.zeroize();
                Ok(n)
            }

            fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
                let mut bytes = Array::from(de.read_array::<$dk_len>()?);
                let dk = <<ml_kem::$base as KemCore>::DecapsulationKey>::from_bytes(&bytes);
                bytes.zeroize();
                Ok(Self(Box::new(dk)))
            }
        }

        #[derive(Debug, PartialEq, Eq, Clone, Hash)]
        pub struct $enc(Box<Array<u8, <ml_kem::$base as KemCore>::CiphertextSize>>);

        impl Serializable for $enc {
            type Error = CryptoCoreError;

            fn length(&self) -> usize {
                $enc_len
            }

            fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
                ser.write_array(&self.0)
            }

            fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
                Ok(Self(Box::new(Array::<
                    u8,
                    <ml_kem::$base as KemCore>::CiphertextSize,
                >::from(de.read_array::<$enc_len>()?))))
            }
        }

        pub struct $base;

        impl KEM<SHARED_SECRET_LENGTH> for $base {
            type EncapsulationKey = $ek;
            type DecapsulationKey = $dk;
            type Encapsulation = $enc;
            type Error = Error;

            fn keygen(
                rng: &mut impl CryptoRngCore,
            ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error> {
                let (dk, ek) = <ml_kem::$base as KemCore>::generate(rng);
                Ok(($dk(Box::new(dk)), $ek(Box::new(ek))))
            }

            fn enc(
                ek: &Self::EncapsulationKey,
                rng: &mut impl CryptoRngCore,
            ) -> Result<(SymmetricKey<SHARED_SECRET_LENGTH>, Self::Encapsulation), Self::Error>
            {
                let (enc, mut ss) =
                    ek.0.encapsulate(rng)
                        .map_err(|e| Error::Kem(format!("{:?}", e)))?;
                let ss = Secret::from_unprotected_bytes(ss.as_mut());
                Ok((ss.into(), $enc(Box::new(enc))))
            }

            fn dec(
                dk: &Self::DecapsulationKey,
                enc: &Self::Encapsulation,
            ) -> Result<SymmetricKey<SHARED_SECRET_LENGTH>, Self::Error> {
                let mut ss =
                    dk.0.decapsulate(&enc.0)
                        .map_err(|e| Self::Error::Kem(format!("{e:?}")))?;
                let ss = Secret::from_unprotected_bytes(ss.as_mut());
                Ok(ss.into())
            }
        }
    };
}

#[cfg(feature = "mlkem-512")]
make_mlkem!(
    MlKem512,
    EncapsulationKey512,
    800,
    DecapsulationKey512,
    1632,
    Encapsulation512,
    768
);

#[cfg(feature = "mlkem-768")]
make_mlkem!(
    MlKem768,
    EncapsulationKey768,
    1184,
    DecapsulationKey768,
    2400,
    Encapsulation768,
    1088
);

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{
        bytes_ser_de::test_serialization, reexport::rand_core::SeedableRng, CsRng,
    };

    use super::*;

    macro_rules! test_mlkem {
        ($base:ident, $test_name:ident) => {
            #[test]
            fn $test_name() {
                let mut rng = CsRng::from_entropy();
                let (dk, ek) = $base::keygen(&mut rng).unwrap();
                test_serialization(&dk).unwrap();
                test_serialization(&ek).unwrap();
                let (ss1, enc) = $base::enc(&ek, &mut rng).unwrap();
                test_serialization(&enc).unwrap();
                let ss2 = $base::dec(&dk, &enc).unwrap();
                assert_eq!(ss1, ss2);
            }
        };
    }

    #[cfg(feature = "mlkem-512")]
    test_mlkem!(MlKem512, test_mlkem512);
    #[cfg(feature = "mlkem-768")]
    test_mlkem!(MlKem768, test_mlkem768);
}
