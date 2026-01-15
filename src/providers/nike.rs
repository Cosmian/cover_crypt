#[cfg(all(feature = "curve25519", feature = "p-256"))]
compile_error!("only one elliptic curve can be chosen at a time");

// #[cfg(all(feature = "curve25519", not(feature = "p-256")))]
#[cfg(feature = "curve25519")]
pub use cosmian_crypto_core::R25519 as ElGamal;

#[cfg(feature = "p-256")]
mod p256;

#[cfg(feature = "p-256")]
pub use p256::P256 as ElGamal;
