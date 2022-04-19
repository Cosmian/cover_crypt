use crate::{ecies::Ecies, traits::Kem};
use std::collections::HashSet;

/// SSCover private keys are a set of KEM private keys
pub type PrivateKey = Vec<<Ecies as Kem>::PrivateKey>;

/// SSCover public keys are a set of KEM public keys
pub type PublicKey = Vec<<Ecies as Kem>::PublicKey>;

/// Generate the master private key and master public key of the SSCover scheme.
///
/// - `n`   : number of users
pub fn setup(n: usize) -> (PrivateKey, PublicKey) {
    let (mut msk, mut mpk) = (Vec::with_capacity(n), Vec::with_capacity(n));
    for _ in 0..n {
        let (ski, pki) = Ecies::setup();
        msk.push(ski);
        mpk.push(pki);
    }
    (msk, mpk)
}

/// Generate a user secret key for a given set of partitions.
///
/// - `msk`         : master secret key
/// - `uid`         : user ID
/// - `partitions`  : set of partitions for which to generate the key
pub fn join(msk: &PrivateKey, uid: usize, partitions: &[HashSet<usize>]) -> PrivateKey {
    partitions
        .iter()
        .enumerate()
        .filter_map(|(i, partition)| {
            if partition.contains(&uid) {
                Some(msk[i].clone())
            } else {
                None
            }
        })
        .collect()
}
