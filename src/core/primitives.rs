//! Implements the cryptographic primitives of CoverCrypt, based on
//! `bib/CoverCrypt.pdf`.

use crate::{
    core::{
        partitions::{filter_on_partition, Partition},
        Encapsulation, KeyEncapsulation, MasterSecretKey, PublicKey, UserSecretKey,
    },
    Error,
};
use cosmian_crypto_core::{
    asymmetric_crypto::DhKeyPair,
    kdf,
    reexport::rand_core::{CryptoRng, CryptoRngCore, RngCore},
    symmetric_crypto::SymKey,
    KeyTrait,
};
use pqc_kyber::{
    indcpa::{indcpa_dec, indcpa_enc, indcpa_keypair},
    KYBER_INDCPA_BYTES, KYBER_INDCPA_PUBLICKEYBYTES, KYBER_INDCPA_SECRETKEYBYTES, KYBER_SYMBYTES,
};
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    ops::{Add, Div, Mul, Sub},
};

/// Additional information to generate symmetric key using the KDF.
pub(crate) const KEY_GEN_INFO: &[u8] = b"key generation info";

/// Xor the two given byte arrays.
#[inline]
fn xor<const LENGTH: usize>(a: &[u8; LENGTH], b: &[u8; LENGTH]) -> [u8; LENGTH] {
    let mut res = [0; LENGTH];
    for (i, byte) in res.iter_mut().enumerate() {
        *byte = a[i] ^ b[i];
    }
    res
}

/// Generates the master secret key and master public key of the CoverCrypt
/// scheme.
///
/// TODO (TBZ): add ref to the paper for the algorithm.
///
/// # Arguments
///
/// - `rng`             : random number generator
/// - `partitions`      : set of partition to be used
/// - `is_hybridized`   : `true` if the setup should produced hybridized keys
pub fn setup<const PUBLIC_KEY_LENGTH: usize, const PRIVATE_KEY_LENGTH: usize, R, KeyPair>(
    rng: &mut impl CryptoRngCore,
    partitions: &HashMap<Partition, bool>,
) -> (
    MasterSecretKey<PRIVATE_KEY_LENGTH, KeyPair::PrivateKey>,
    PublicKey<PUBLIC_KEY_LENGTH, KeyPair::PublicKey>,
)
where
    KeyPair: DhKeyPair<PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH>,
    KeyPair::PublicKey: From<KeyPair::PrivateKey>,
    for<'a, 'b> &'a KeyPair::PublicKey: Add<&'b KeyPair::PublicKey, Output = KeyPair::PublicKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PublicKey>,
    for<'a, 'b> &'a KeyPair::PrivateKey: Add<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Sub<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Div<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>,
{
    let u = KeyPair::PrivateKey::new(rng);
    let v = KeyPair::PrivateKey::new(rng);
    let s = KeyPair::PrivateKey::new(rng);
    let U = KeyPair::PublicKey::from(u.clone());
    let V = KeyPair::PublicKey::from(v.clone());
    let S = KeyPair::PublicKey::from(s.clone());

    let mut x = HashMap::with_capacity(partitions.len());
    let mut H = HashMap::with_capacity(partitions.len());

    for (partition, &is_hybridized) in partitions {
        let x_i = KeyPair::PrivateKey::new(rng);
        let H_i = &S * &x_i;

        let (sk_pq, pk_pq) = if is_hybridized {
            let (mut sk, mut pk) = (
                [0; KYBER_INDCPA_SECRETKEYBYTES],
                [0; KYBER_INDCPA_PUBLICKEYBYTES],
            );
            indcpa_keypair(&mut pk, &mut sk, None, rng);
            (Some(sk), Some(pk))
        } else {
            (None, None)
        };

        x.insert(partition.clone(), (sk_pq, x_i));
        H.insert(partition.clone(), (pk_pq, H_i));
    }

    (MasterSecretKey { u, v, s, x }, PublicKey { U, V, H })
}

/// Generates a user secret key for the given decryption sets.
///
/// TODO (TBZ): add ref to the paper for the algorithm.
///
/// # Arguments
///
/// - `rng`             : random number generator
/// - `msk`             : master secret key
/// - `decryption_set`  : decryption set
pub fn join<const PUBLIC_KEY_LENGTH: usize, const PRIVATE_KEY_LENGTH: usize, R, KeyPair>(
    rng: &mut R,
    msk: &MasterSecretKey<PRIVATE_KEY_LENGTH, KeyPair::PrivateKey>,
    decryption_set: &HashSet<Partition>,
) -> Result<UserSecretKey<PRIVATE_KEY_LENGTH, KeyPair::PrivateKey>, Error>
where
    R: CryptoRng + RngCore,
    KeyPair: DhKeyPair<PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH>,
    KeyPair::PublicKey: From<KeyPair::PrivateKey>,
    KeyPair::PrivateKey: Hash,
    for<'a, 'b> &'a KeyPair::PublicKey: Add<&'b KeyPair::PublicKey, Output = KeyPair::PublicKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PublicKey>,
    for<'a, 'b> &'a KeyPair::PrivateKey: Add<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Sub<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Div<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>,
{
    let a = KeyPair::PrivateKey::new(rng);
    let b = &(&msk.s - &(&a * &msk.u)) / &msk.v;
    let x = filter_on_partition(decryption_set, &msk.x);
    Ok(UserSecretKey { a, b, x })
}

/// Generates the secret key encapsulation.
///
/// # Arguments
///
/// - `rng`             : secure random number generator
/// - `mpk`             : master public key
/// - `encryption_set`  : sets for which to generate a ciphertext
pub fn encaps<
    const TAG_LENGTH: usize,
    const SYM_KEY_LENGTH: usize,
    const PUBLIC_KEY_LENGTH: usize,
    const PRIVATE_KEY_LENGTH: usize,
    SymmetricKey,
    KeyPair,
>(
    rng: &mut impl CryptoRngCore,
    mpk: &PublicKey<PUBLIC_KEY_LENGTH, KeyPair::PublicKey>,
    encryption_set: &HashSet<Partition>,
) -> Result<
    (
        SymmetricKey,
        Encapsulation<TAG_LENGTH, SYM_KEY_LENGTH, PUBLIC_KEY_LENGTH, KeyPair::PublicKey>,
    ),
    Error,
>
where
    SymmetricKey: SymKey<SYM_KEY_LENGTH>,
    KeyPair: DhKeyPair<PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH>,
    KeyPair::PublicKey: From<KeyPair::PrivateKey>,
    for<'a, 'b> &'a KeyPair::PublicKey: Add<&'b KeyPair::PublicKey, Output = KeyPair::PublicKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PublicKey>,
    for<'a, 'b> &'a KeyPair::PrivateKey: Add<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Sub<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Div<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>,
{
    let mut K = [0; SYM_KEY_LENGTH];
    rng.fill_bytes(&mut K);
    let r = KeyPair::PrivateKey::new(rng);
    let C = &mpk.U * &r;
    let D = &mpk.V * &r;
    let mut E = HashSet::with_capacity(encryption_set.len());
    for partition in encryption_set {
        if let Some((pk_i, H_i)) = mpk.H.get(partition) {
            let K_i = (H_i * &r).to_bytes();
            let E_i = xor(&kdf!(SYM_KEY_LENGTH, &K_i), &K);
            if let Some(pk_i) = pk_i {
                let mut EPQ_i = [0; KYBER_INDCPA_BYTES];
                // TODO TBZ: which coin to use ?
                indcpa_enc(&mut EPQ_i, &E_i, pk_i, &[0; KYBER_SYMBYTES]);
                E.insert(KeyEncapsulation::HybridEncapsulation(Box::new(EPQ_i)));
            } else {
                E.insert(KeyEncapsulation::ClassicEncapsulation(Box::new(E_i)));
            }
        } // else unknown target partition
    }
    let (tag, K) = eakem_hash!(TAG_LENGTH, SYM_KEY_LENGTH, &K, KEY_GEN_INFO);
    Ok((SymmetricKey::from_bytes(K), Encapsulation { C, D, tag, E }))
}

/// Decapsulates the secret key.
///
/// # Arguments
///
/// - `sk_j`                : user secret key
/// - `encapsulation`       : symmetric key encapsulation
pub fn decaps<
    const TAG_LENGTH: usize,
    const SYM_KEY_LENGTH: usize,
    const PUBLIC_KEY_LENGTH: usize,
    const PRIVATE_KEY_LENGTH: usize,
    SymmetricKey,
    KeyPair,
>(
    usk: &UserSecretKey<PRIVATE_KEY_LENGTH, KeyPair::PrivateKey>,
    encapsulation: &Encapsulation<
        TAG_LENGTH,
        SYM_KEY_LENGTH,
        PUBLIC_KEY_LENGTH,
        KeyPair::PublicKey,
    >,
) -> Result<SymmetricKey, Error>
where
    SymmetricKey: SymKey<SYM_KEY_LENGTH>,
    KeyPair: DhKeyPair<PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH>,
    KeyPair::PublicKey: From<KeyPair::PrivateKey>,
    KeyPair::PrivateKey: Hash,
    for<'a, 'b> &'a KeyPair::PublicKey: Add<&'b KeyPair::PublicKey, Output = KeyPair::PublicKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PublicKey>,
    for<'a, 'b> &'a KeyPair::PrivateKey: Add<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Sub<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Div<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>,
{
    let precomp = &(&encapsulation.C * &usk.a) + &(&encapsulation.D * &usk.b);
    for encapsulation_i in &encapsulation.E {
        for (sk_j, x_j) in &usk.x {
            let E_j = match encapsulation_i {
                KeyEncapsulation::HybridEncapsulation(EPQ_i) => {
                    if let Some(sk_j) = sk_j {
                        let mut E_j = [0; SYM_KEY_LENGTH];
                        // TODO TBZ: which coin to use ?
                        indcpa_dec(&mut E_j, &**EPQ_i, sk_j);
                        E_j
                    } else {
                        continue;
                    }
                }
                KeyEncapsulation::ClassicEncapsulation(E_i) => **E_i,
            };
            let K_j = (&precomp * x_j).to_bytes();
            let K = xor(&kdf!(SYM_KEY_LENGTH, &K_j), &E_j);
            let (tag, K) = eakem_hash!(TAG_LENGTH, SYM_KEY_LENGTH, &K, KEY_GEN_INFO);
            if tag == encapsulation.tag {
                return Ok(SymmetricKey::from_bytes(K));
            }
        }
    }
    Err(Error::InsufficientAccessPolicy)
}

/// Update the master secret key and master public key of the CoverCrypt
/// scheme with the given list of partitions.
///
/// If a partition exists in the keys but not in the list, it will be removed
/// from the keys.
///
/// If a partition exists in the list, but not in the keys, it will be "added"
/// to the keys, by adding a new partition key pair as performed in the setup
/// procedure above.
///
/// # Arguments
///
/// - `rng`             : random number generator
/// - `msk`             : master secret key
/// - `mpk`             : master public key
/// - `partition_set`   : new set of partitions to use after the update
pub fn update<const PUBLIC_KEY_LENGTH: usize, const PRIVATE_KEY_LENGTH: usize, R, KeyPair>(
    rng: &mut impl CryptoRngCore,
    msk: &mut MasterSecretKey<PRIVATE_KEY_LENGTH, KeyPair::PrivateKey>,
    mpk: &mut PublicKey<PUBLIC_KEY_LENGTH, KeyPair::PublicKey>,
    partitions_set: &HashMap<Partition, bool>,
) -> Result<(), Error>
where
    KeyPair: DhKeyPair<PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH>,
    KeyPair::PublicKey: From<KeyPair::PrivateKey>,
    for<'a, 'b> &'a KeyPair::PublicKey: Add<&'b KeyPair::PublicKey, Output = KeyPair::PublicKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PublicKey>,
    for<'a, 'b> &'a KeyPair::PrivateKey: Add<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Sub<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Div<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>,
{
    let S = KeyPair::PublicKey::from(msk.s.clone());
    let mut new_x = HashMap::with_capacity(partitions_set.len());
    let mut new_H = HashMap::with_capacity(partitions_set.len());

    for (partition, &is_hybridized) in partitions_set {
        if let Some((sk_i, x_i)) = msk.x.get(partition) {
            // Set the correct hybridization property.
            let (sk_i, pk_i) = if is_hybridized {
                let (pk_i, _) = mpk.H.get(partition).ok_or_else(|| {
                    // Kyber public key cannot be computed from the secret key.
                    Error::CryptoError("Master keys are not synchronized.".to_string())
                })?;

                if sk_i.is_some() {
                    if pk_i.is_some() {
                        (*sk_i, *pk_i)
                    } else {
                        // Kyber public key cannot be computed from the secret key.
                        return Err(Error::CryptoError(
                            "Master keys are not synchronized.".to_string(),
                        ));
                    }
                } else {
                    let (mut sk_i, mut pk_i) = (
                        [0; KYBER_INDCPA_SECRETKEYBYTES],
                        [0; KYBER_INDCPA_PUBLICKEYBYTES],
                    );
                    indcpa_keypair(&mut pk_i, &mut sk_i, None, rng);
                    (Some(sk_i), Some(pk_i))
                }
            } else {
                (None, None)
            };
            new_x.insert(partition.clone(), (sk_i, x_i.clone()));
            new_H.insert(partition.clone(), (pk_i, &S * x_i));
        } else {
            // Create new entry.
            let x_i = KeyPair::PrivateKey::new(rng);
            let H_i = &S * &x_i;
            let (sk_pq, pk_pq) = if is_hybridized {
                let (mut sk_pq, mut pk_pq) = (
                    [0; KYBER_INDCPA_SECRETKEYBYTES],
                    [0; KYBER_INDCPA_PUBLICKEYBYTES],
                );
                indcpa_keypair(&mut pk_pq, &mut sk_pq, None, rng);
                (Some(sk_pq), Some(pk_pq))
            } else {
                (None, None)
            };
            new_x.insert(partition.clone(), (sk_pq, x_i));
            new_H.insert(partition.clone(), (pk_pq, H_i));
        }
    }

    msk.x = new_x;
    mpk.H = new_H;

    Ok(())
}

/// Refresh a user key from the master secret key and a list of partitions.
/// The partitions MUST exist in the master secret key.
///
/// If a partition exists in the user key but is not in the list, it will be
/// removed from the user key.
///
/// If a partition exists in the list, but not in the user key, it will be
/// "added" to the user key, by copying the proper partition key from the master
/// secret key
pub fn refresh<const PRIVATE_KEY_LENGTH: usize, PrivateKey>(
    msk: &MasterSecretKey<PRIVATE_KEY_LENGTH, PrivateKey>,
    usk: &mut UserSecretKey<PRIVATE_KEY_LENGTH, PrivateKey>,
    user_set: &HashSet<Partition>,
    keep_old_accesses: bool,
) -> Result<(), Error>
where
    PrivateKey: KeyTrait<PRIVATE_KEY_LENGTH> + Hash,
{
    if !keep_old_accesses {
        // generate a fresh key
        usk.x = Default::default();
    }

    // add keys for partitions that do not exist
    for partition in user_set {
        if let Some(x_i) = msk.x.get(partition) {
            usk.x.insert(x_i.clone());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decaps, encaps, join, refresh, setup, update};
    use cosmian_crypto_core::{
        asymmetric_crypto::curve25519::X25519KeyPair, reexport::rand_core::SeedableRng,
        symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto, CsRng,
    };

    //
    // Define types and constants used in the tests
    //
    const TAG_LENGTH: usize = 32;
    const SYM_KEY_LENGTH: usize = 32;
    type KeyPair = X25519KeyPair;
    #[allow(clippy::upper_case_acronyms)]
    type DEM = Aes256GcmCrypto;

    #[test]
    fn test_kyber() {
        let mut rng = CsRng::from_entropy();
        let keypair = pqc_kyber::keypair(&mut rng);
        let (ct, ss) = pqc_kyber::encapsulate(&keypair.public, &mut rng).unwrap();
        let res = pqc_kyber::decapsulate(&ct, &keypair.secret).unwrap();
        assert_eq!(ss, res, "Decapsulation failed!");
    }

    #[test]
    fn test_cover_crypt() -> Result<(), Error> {
        let admin_partition = Partition(b"admin".to_vec());
        let dev_partition = Partition(b"dev".to_vec());
        // partition list
        let partitions_set = HashMap::from([
            (admin_partition.clone(), true),
            (dev_partition.clone(), false),
        ]);
        // user list
        let users_set = vec![
            HashSet::from([dev_partition.clone()]),
            HashSet::from([admin_partition.clone(), dev_partition.clone()]),
        ];
        // target set
        let target_set = HashSet::from([admin_partition]);
        // secure random number generator
        let mut rng = CsRng::from_entropy();
        // setup scheme
        let (mut msk, mut mpk) = setup!(&mut rng, &partitions_set);
        // generate user secret keys
        let mut usk0 = join!(&mut rng, &msk, &users_set[0])?;
        let usk1 = join!(&mut rng, &msk, &users_set[1])?;
        // encapsulate for the target set
        let (sym_key, encapsulation) = encaps!(&mut rng, &mpk, &target_set)?;
        // decapsulate for users 1 and 3
        let res0 = decaps!(&usk0, &encapsulation);

        assert!(res0.is_err(), "User 0 shouldn't be able to decapsulate!");

        let res1 = decaps!(&usk1, &encapsulation)?;

        assert_eq!(sym_key, res1, "Wrong decapsulation for user 1!");

        // Change partition
        let client_partition = Partition(b"client".to_vec());
        let new_partitions_set =
            HashMap::from([(dev_partition, true), (client_partition.clone(), false)]);
        let new_target_set = HashSet::from([client_partition.clone()]);
        update!(&mut rng, &mut msk, &mut mpk, &new_partitions_set)?;
        refresh!(&msk, &mut usk0, &HashSet::from([client_partition]), false)?;
        let (sym_key, new_encapsulation) = encaps!(&mut rng, &mpk, &new_target_set)?;

        // New user key cannot decrypt old encapsulation.
        let res0 = decaps!(&usk0, &encapsulation);
        assert!(
            res0.is_err(),
            "User 0 should not be able to decapsulate the old encapsulation."
        );

        // Old user key cannot decrypt new encapsulation.
        let res1 = decaps!(&usk1, &new_encapsulation);
        assert!(
            res1.is_err(),
            "User 1 should not be able to decapsulate the new encapsulation."
        );

        // New user key can decrypt new encapsulation.
        let res0 = decaps!(&usk0, &new_encapsulation);
        match res0 {
            Err(err) => panic!("User 0 should be able to decapsulate: got error {err:?}"),
            Ok(res) => assert_eq!(sym_key, res, "Wrong decapsulation."),
        }

        Ok(())
    }

    #[test]
    fn test_master_keys_update() -> Result<(), Error> {
        let partition_1 = Partition(b"1".to_vec());
        let partition_2 = Partition(b"2".to_vec());
        // partition list
        let partitions_set =
            HashMap::from([(partition_1.clone(), true), (partition_2.clone(), true)]);
        // secure random number generator
        let mut rng = CsRng::from_entropy();
        // setup scheme
        let (mut msk, mut mpk) = setup!(&mut rng, &partitions_set);

        // now remove partition 1 and add partition 3
        let partition_3 = Partition(b"3".to_vec());
        let new_partitions_set =
            HashMap::from([(partition_2.clone(), true), (partition_3.clone(), false)]);
        update!(&mut rng, &mut msk, &mut mpk, &new_partitions_set)?;
        assert!(!msk.x.contains_key(&partition_1));
        assert!(msk.x.contains_key(&partition_2));
        assert!(msk.x.contains_key(&partition_3));
        assert!(!mpk.H.contains_key(&partition_1));
        assert!(mpk.H.contains_key(&partition_2));
        assert!(mpk.H.contains_key(&partition_3));
        Ok(())
    }

    #[test]
    fn test_user_key_refresh() -> Result<(), Error> {
        let partition_1 = Partition(b"1".to_vec());
        let partition_2 = Partition(b"2".to_vec());
        let partition_3 = Partition(b"3".to_vec());
        // partition list
        let partitions_set = HashMap::from([
            (partition_1.clone(), true),
            (partition_2.clone(), true),
            (partition_3.clone(), true),
        ]);
        // secure random number generator
        let mut rng = CsRng::from_entropy();
        // setup scheme
        let (mut msk, mut mpk) = setup!(&mut rng, &partitions_set);
        // create a user key with access to partition 1 and 2
        let mut usk = join!(
            &mut rng,
            &msk,
            &HashSet::from([partition_1.clone(), partition_2.clone()])
        )?;

        // now remove partition 1 and add partition 4
        let partition_4 = Partition(b"4".to_vec());
        let new_partition_set = HashMap::from([
            (partition_2.clone(), true),
            (partition_3.clone(), false),
            (partition_4.clone(), false),
        ]);
        // update the master keys
        let old_msk = msk.clone();
        update!(&mut rng, &mut msk, &mut mpk, &new_partition_set)?;
        // refresh the user key with partitions 2 and 4
        refresh!(
            &msk,
            &mut usk,
            &HashSet::from([partition_2.clone(), partition_4.clone()]),
            false
        )?;
        assert!(!usk.x.contains(old_msk.x.get(&partition_1).unwrap()));
        assert!(usk.x.contains(msk.x.get(&partition_2).unwrap()));
        assert!(!usk.x.contains(old_msk.x.get(&partition_3).unwrap()));
        assert!(usk.x.contains(msk.x.get(&partition_4).unwrap()));
        Ok(())
    }
}
