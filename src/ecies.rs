use crate::traits;
use ecies::ecies;

pub struct Ecies();

impl traits::Kem for Ecies {
    type PublicKey = ecies::PublicKey;

    type PrivateKey = ecies::PrivateKey;

    type CipherText = ecies::Ciphertext;

    type Error = ecies::EciesError;

    fn setup() -> (Self::PrivateKey, Self::PublicKey) {
        ecies::setup()
    }

    fn encrypt(pk: &Self::PublicKey, m: &[u8]) -> Result<Self::CipherText, Self::Error> {
        ecies::encrypt(pk, m)
    }

    fn decrypt(
        pk: &Self::PublicKey,
        sk: &Self::PrivateKey,
        c: &Self::CipherText,
    ) -> Result<Vec<u8>, Self::Error> {
        ecies::decrypt(pk, sk, c)
    }
}
