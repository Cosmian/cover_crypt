use crate::core::ae::AE;
use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;
use zeroize::Zeroizing;

pub trait KemTrait {
    type Error: std::error::Error;
    type Encapsulation;
    type SecretKey;
    type PublicKey;
    type SharedSecret;

    fn keygen(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SecretKey, Self::PublicKey), Self::Error>;

    fn encaps(
        &self,
        rng: &mut impl CryptoRngCore,
        pk: &Self::PublicKey,
    ) -> Result<(Self::SharedSecret, Self::Encapsulation), Self::Error>;

    fn decaps(
        &self,
        sk: &Self::SecretKey,
        encapsulation: &Self::Encapsulation,
    ) -> Result<Self::SharedSecret, Self::Error>;
}

pub trait PkeTrait<const KEY_LENGTH: usize> {
    type Ae: AE<KEY_LENGTH>;

    type Kem: KemTrait;

    type Ciphertext;

    type Error: std::error::Error + From<<Self::Kem as KemTrait>::Error>;

    #[allow(clippy::type_complexity)]
    fn keygen(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        (
            <Self::Kem as KemTrait>::SecretKey,
            <Self::Kem as KemTrait>::PublicKey,
        ),
        Self::Error,
    >;

    fn encrypt(
        &self,
        rng: &mut impl CryptoRngCore,
        pk: &<Self::Kem as KemTrait>::PublicKey,
        ptx: &[u8],
    ) -> Result<Self::Ciphertext, Self::Error>;

    fn decrypt(
        &self,
        sk: &<Self::Kem as KemTrait>::SecretKey,
        ctx: &Self::Ciphertext,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error>;
}
