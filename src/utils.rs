use rand_core::{CryptoRng, RngCore};
use std::sync::Mutex;

/// Generate `len` random bytes using a secure random number generator.
///
/// - `rng` : secure random number generator
/// - `len` : number of bytes to generate
pub(crate) fn generate_random_bytes<R: CryptoRng + RngCore>(rng: &Mutex<R>, len: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; len];
    rng.lock()
        .expect("Could not get a hold on the mutex")
        .fill_bytes(&mut bytes);
    bytes
}
