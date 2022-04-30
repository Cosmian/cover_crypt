#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::{ecies::Ecies, traits::Kem};
use std::collections::HashSet;

const N_BYTES: usize = 32;

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

fn generate_random_key(nbytes: usize) -> Vec<u8> {
    (0..nbytes).map(|_| rand::random()).collect()
}

pub fn encaps(
    mpk: &PublicKey,
    T: &HashSet<usize>,
    S: &[HashSet<usize>],
) -> Result<(), <Ecies as Kem>::Error> {
    // -> Ciphertext {

    // construct the list of indexes of the sets such that `T = Union_{i in A} S_i`
    let A = S.iter().enumerate().filter_map(|(i, S_i)| {
        if S_i.intersection(T).next().is_none() {
            None
        } else {
            Some(i)
        }
    });

    A.map(
        |i| -> Result<(Vec<u8>, <Ecies as Kem>::CipherText), <Ecies as Kem>::Error> {
            let K_i = generate_random_key(N_BYTES);
            let C_i = Ecies::encaps(&mpk[i], &K_i)?;
            Ok((K_i, C_i))
        },
    )
    .collect::<Result<Vec<(Vec<u8>, <Ecies as Kem>::CipherText)>, <Ecies as Kem>::Error>>()?;
    Ok(())
}

//pub fn decaps(mpk: &PublicKey, msk: &PrivateKey, sku: &PrivateKey) {
//}
