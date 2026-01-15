use cosmian_crypto_core::{kdf::Kdf as ShakeKDF, traits::cyclic_group_to_kem::GenericKem};

mod kem;
mod nike;

pub use kem::MlKem;
pub use nike::ElGamal;

pub const PRE_QUANTUM_KEM_KEY_LENGTH: usize = 32;

pub type PreQuantumKem = GenericKem<PRE_QUANTUM_KEM_KEY_LENGTH, nike::ElGamal, ShakeKDF>;
