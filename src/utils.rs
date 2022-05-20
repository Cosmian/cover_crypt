use rand_core::{CryptoRng, RngCore};

/// Generate `len` random bytes using a secure random number generator.
///
/// - `rng` : secure random number generator
/// - `len` : number of bytes to generate
pub(crate) fn generate_random_bytes<R: CryptoRng + RngCore>(rng: &mut R, len: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}
