#[cfg(all(feature = "curve25519", feature = "p-256"))]
compile_error!("only one elliptic curve can be chosen at a time");

#[cfg(feature = "curve25519")]
pub mod r25519;

#[cfg(feature = "curve25519")]
pub use r25519::R25519 as ElGamal;

#[cfg(feature = "p-256")]
mod p256;

#[cfg(feature = "p-256")]
pub use p256::P256 as ElGamal;
