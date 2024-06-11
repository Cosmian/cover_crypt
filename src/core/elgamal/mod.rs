//! Exposes masking and unmasking primitives based on an ElGamal KEM.
//!
//! Current implementation only uses Ristretto on Curve25519 but plans to add
//! more curves is on the TODO list.
//!
//! Curve points MUST provide:
//! - group operations (addition, neutral element);
//! - external multiplication with scalars.
//! - implement `Serializable`
//!
//! Scalars MUST provide:
//! - field operations (a fortiori the multiplicative inverse).
//! - implement `Serializable`

mod ristretto_25519;

use cosmian_crypto_core::{
    bytes_ser_de::Serializable, kdf256, reexport::rand_core::CryptoRngCore, Secret, SymmetricKey,
};
use zeroize::Zeroize;

pub use ristretto_25519::{EcPoint, Scalar};

use crate::Error;

/// ElGamal keypair.
///
/// The public key is optional. The following invariant is maintained:
/// > the  public key is `None` iff the keypair is deprecated
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keypair(Scalar, Option<EcPoint>);

impl Keypair {
    /// Returns a new random keypair.
    #[must_use]
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let sk = Scalar::new(rng);
        let pk = EcPoint::from(&sk);
        Self(sk, Some(pk))
    }

    /// Returns a reference on the secret key.
    #[inline(always)]
    pub fn sk(&self) -> &Scalar {
        &self.0
    }

    /// Returns a reference on the public key if the key is not
    /// deprecated. Returns `None` otherwise.
    #[inline(always)]
    pub fn pk(&self) -> Option<&EcPoint> {
        self.1.as_ref()
    }
}

impl Serializable for Keypair {
    type Error = Error;

    fn length(&self) -> usize {
        self.0.length()
            + 1			// option encoding overhead
            + self
                .1
                .as_ref()
                .map(Serializable::length)
                .unwrap_or_default()
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        let mut n = ser.write(&self.0)?;
        if let Some(pk) = &self.1 {
            n += ser.write_leb128_u64(0)?;
            n += ser.write(pk)?;
        } else {
            n += ser.write_leb128_u64(1)?;
        }
        Ok(n)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let sk = de.read::<Scalar>()?;
        let option_flag = de.read_leb128_u64()?;
        if 1 == option_flag {
            Ok(Self(sk, None))
        } else if 0 == option_flag {
            let pk = de.read::<EcPoint>()?;
            Ok(Self(sk, Some(pk)))
        } else {
            Err(Error::ConversionFailed(format!(
                "invalid option encoding {option_flag}"
            )))
        }
    }
}

/// One-Time Pad (OTP) encryption of the given plaintext.
fn otp_encrypt<const LENGTH: usize>(
    ctx: &mut [u8; LENGTH],
    key: &SymmetricKey<LENGTH>,
    ptx: &Secret<LENGTH>,
) {
    for pos in 0..LENGTH {
        ctx[pos] = key[pos] ^ ptx[pos];
    }
}

/// One-Time Pad (OTP) decryption of the given ciphertext.
fn otp_decrypt<const LENGTH: usize>(
    key: &SymmetricKey<LENGTH>,
    ctx: &[u8], // authorize byte slices from any object
) -> Result<Secret<LENGTH>, Error> {
    if ctx.len() < LENGTH {
        return Err(Error::OperationNotPermitted(format!(
            "cannot decrypt a plaintext of size {LENGTH} from a ciphertext of size {}",
            ctx.len()
        )));
    }
    let mut ptx = Secret::<LENGTH>::new();
    for pos in 0..LENGTH {
        ptx[pos] = key[pos] ^ ctx[pos];
    }
    Ok(ptx)
}

/// Masks the given bytes using the key derived from the ElGamal shared secret.
///
/// # Security
///
/// The security relies on the fact that the same ElGammal keypair is never used
/// on different input bytes.
pub fn mask<const LENGTH: usize>(
    ctx: &mut [u8; LENGTH],
    ephemeral_sk: &Scalar,
    recipient_pk: &EcPoint,
    ptx: &Secret<LENGTH>,
) {
    let mut shared_secret = recipient_pk * ephemeral_sk;
    let mut key = SymmetricKey::<LENGTH>::default();
    kdf256!(&mut key, &shared_secret.to_bytes());
    shared_secret.zeroize();
    otp_encrypt(ctx, &key, ptx)
}

/// Unmasks the given bytes using the key derived from the ElGamal shared secret.
pub fn unmask<const LENGTH: usize>(
    recipient_sk: &Scalar,
    ephemeral_pk: &EcPoint,
    ctx: &[u8],
) -> Result<Secret<LENGTH>, Error> {
    let mut shared_secret = ephemeral_pk * recipient_sk;
    let mut key = SymmetricKey::<LENGTH>::default();
    kdf256!(&mut *key, &shared_secret.to_bytes());
    shared_secret.zeroize();
    otp_decrypt(&key, ctx)
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{
        bytes_ser_de::Serializable, reexport::rand_core::SeedableRng, CsRng, Secret,
    };

    use super::{mask, unmask, Keypair};

    /// Arbitrary plaintext length.
    const PTX_LENGTH: usize = 108;

    #[test]
    fn test_elgamal_pke() {
        let mut rng = CsRng::from_entropy();
        let ptx = Secret::<PTX_LENGTH>::random(&mut rng);
        let ephemeral_keypair = Keypair::random(&mut rng);
        let recipient_keypair = Keypair::random(&mut rng);
        let mut ctx = [0; PTX_LENGTH];
        mask(
            &mut ctx,
            ephemeral_keypair.sk(),
            recipient_keypair.pk().unwrap(),
            &ptx,
        );
        let res = unmask(
            recipient_keypair.sk(),
            ephemeral_keypair.pk().unwrap(),
            &ctx,
        )
        .expect(
            "failed decryption with ephemeral keypair {ephemeral_keypair:#?}, \
	     recipient keypair {recipient_keypair:#?} and plaintext {ptx:#?}",
        );
        assert_eq!(
            ptx, res,
            "wrong decryption with ephemeral keypair {ephemeral_keypair:#?}, \
	     recipient keypair {recipient_keypair:#?} and plaintext {ptx:#?}",
        )
    }

    #[test]
    fn test_elgamal_serialization() {
        let mut rng = CsRng::from_entropy();
        let keypair = Keypair::random(&mut rng);
        let bytes = keypair.serialize().unwrap();
        assert_eq!(bytes.len(), keypair.length());
        let keypair_ = Keypair::deserialize(&bytes).unwrap();
        assert_eq!(keypair, keypair_);
    }
}
