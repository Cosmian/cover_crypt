#[cfg(not(any(feature = "curve25519", feature = "p-256")))]
compile_error!("at least one elliptic curve must be chosen");

#[cfg(all(feature = "curve25519", not(feature = "p-256")))]
pub use cosmian_rust_curve25519_provider::R25519 as ElGamal;

#[cfg(feature = "p-256")]
pub use cosmian_openssl_provider::p256::P256 as ElGamal;
