use eyre::Result;

pub trait Kem {
    type PublicKey;
    type PrivateKey;
    type CipherText;
    type Error;
    fn setup() -> (Self::PrivateKey, Self::PublicKey);
    fn encrypt(pk: &Self::PublicKey, m: &[u8]) -> Result<Self::CipherText, Self::Error>;
    fn decrypt(
        pk: &Self::PublicKey,
        sk: &Self::PrivateKey,
        c: &Self::CipherText,
    ) -> Result<Vec<u8>, Self::Error>;
}
