#[cfg(all(feature = "curve25519", feature = "p-256"))]
compile_error!("only one elliptic curve can be chosen at a time");

#[cfg(feature = "curve25519")]
pub use cosmian_rust_curve25519_provider::R25519 as ElGamal;

#[cfg(feature = "p-256")]
pub use cosmian_openssl_provider::p256::P256 as ElGamal;
