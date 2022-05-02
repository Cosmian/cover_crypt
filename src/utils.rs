use rand_core::{CryptoRng, RngCore};
use std::{collections::HashSet, sync::Mutex};

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

/// Get the `group_index` and the `set_index` associated with the given `uid`,
/// where:
/// - `group_index` is the index of the first user group among the groups
/// containing `uid` belonging to the target set
/// - `set_index` is the index of the first user group among such groups
/// belonging to the target set containing `uid`
///
/// - `uid` : the uiser ID
/// - `T`   : target set
/// - `S`   : list of all user groups
pub(crate) fn get_matching_indexes(
    uid: usize,
    T: &HashSet<usize>,
    S: &[HashSet<usize>],
) -> Option<(usize, usize)> {
    let mut target_group_index = 0;
    let mut user_group_index = 0;
    for S_i in S.iter() {
        let is_target_group = S_i.is_subset(T);
        let is_user_group = S_i.contains(&uid);
        if is_target_group && is_user_group {
            return Some((target_group_index, user_group_index));
        } else if is_target_group {
            target_group_index += 1;
        } else if is_user_group {
            user_group_index += 1;
        }
    }
    None
}
