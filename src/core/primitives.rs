//! Implements the cryptographic primitives of `Covercrypt`, based on
//! `bib/Covercrypt.pdf`.

use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::{
    kdf256, reexport::rand_core::CryptoRngCore, FixedSizeCBytes, R25519CurvePoint,
    R25519PrivateKey, R25519PublicKey, RandomFixedSizeCBytes, SymmetricKey,
};
use pqc_kyber::{
    indcpa::{indcpa_dec, indcpa_enc, indcpa_keypair},
    KYBER_INDCPA_BYTES, KYBER_INDCPA_PUBLICKEYBYTES, KYBER_INDCPA_SECRETKEYBYTES, KYBER_SYMBYTES,
};
use tiny_keccak::{Hasher, IntoXof, Kmac, Xof};
use zeroize::Zeroizing;

use super::{
    KmacSignature, KyberPublicKey, KyberSecretKey, PublicSubkey, SecretSubkey, KMAC_KEY_LENGTH,
    KMAC_LENGTH, SYM_KEY_LENGTH, TAG_LENGTH,
};
use crate::{
    abe_policy::{
        AttributeStatus,
        AttributeStatus::{DecryptOnly, EncryptDecrypt},
        EncryptionHint, Partition,
    },
    core::{Encapsulation, KeyEncapsulation, MasterPublicKey, MasterSecretKey, UserSecretKey},
    data_struct::{Element, RevisionMap, RevisionVec},
    Error,
};

/// Additional information to generate symmetric key using the KDF.
pub(crate) const KEY_GEN_INFO: &[u8] = b"key generation info";

/// Xor the two given byte arrays in place.
fn xor_in_place<const LENGTH: usize>(a: &mut [u8; LENGTH], b: &[u8; LENGTH]) {
    for (a_i, b_i) in a.iter_mut().zip(b.iter()) {
        *a_i ^= b_i;
    }
}

/// Computes the signature of the given user key.
/// The order of the sub keys will impact the resulting KMAC.
fn compute_user_key_kmac(msk: &MasterSecretKey, usk: &UserSecretKey) -> Option<KmacSignature> {
    if let Some(kmac_key) = &msk.kmac_key {
        let mut kmac = Kmac::v256(kmac_key, &usk.a.to_bytes());
        kmac.update(&usk.b.to_bytes());

        for (partition, (sk_i, x_i)) in usk.subkeys.flat_iter() {
            kmac.update(&partition.0);
            if let Some(sk_i) = sk_i {
                kmac.update(sk_i);
            }
            kmac.update(&x_i.to_bytes());
        }

        let mut res = [0; KMAC_LENGTH];
        kmac.into_xof().squeeze(&mut res);
        Some(res)
    } else {
        None
    }
}

/// Checks that the provided KMAC matches the user secret key rights
fn verify_user_key_kmac(msk: &MasterSecretKey, usk: &UserSecretKey) -> Result<(), Error> {
    let kmac = compute_user_key_kmac(msk, usk);
    if usk.kmac != kmac {
        return Err(Error::KeyError(
            "The provided user key is corrupted.".to_string(),
        ));
    }
    Ok(())
}

/// Returns newly generated public and private Kyber key pair
fn create_kyber_key_pair(rng: &mut impl CryptoRngCore) -> (KyberPublicKey, KyberSecretKey) {
    let (mut sk, mut pk) = (
        KyberSecretKey([0; KYBER_INDCPA_SECRETKEYBYTES]),
        KyberPublicKey([0; KYBER_INDCPA_PUBLICKEYBYTES]),
    );
    indcpa_keypair(&mut pk.0, &mut sk.0, None, rng);
    (pk, sk)
}

/// Returns a newly generated pair of public and private subkeys with optional
/// Kyber keys if required
fn create_subkey_pair(
    rng: &mut impl CryptoRngCore,
    h: &R25519CurvePoint,
    is_hybridized: EncryptionHint,
) -> (PublicSubkey, SecretSubkey) {
    let sk_i = R25519PrivateKey::new(rng);
    let pk_i = h * &sk_i;

    let (pk_pq, sk_pq) = if is_hybridized.into() {
        let (pk, sk) = create_kyber_key_pair(rng);
        (Some(pk), Some(sk))
    } else {
        (None, None)
    };
    ((pk_pq, pk_i), (sk_pq, sk_i))
}

/// Update a pair of public and private subkeys of a `ReadWrite` partition
fn update_subkey_pair(
    rng: &mut impl CryptoRngCore,
    h: &R25519CurvePoint,
    mpk: &mut PublicSubkey,
    msk: &mut SecretSubkey,
    is_hybridized: EncryptionHint,
) -> Result<(), Error> {
    let (pk_pq, pk_i) = mpk;
    let (sk_pq, sk_i) = msk;

    // update public subkey
    *pk_i = h * &sk_i;

    // create or reuse Kyber keys
    if is_hybridized.into() {
        match (&pk_pq, &sk_pq) {
            (None, _) => {
                // generate a new Kyber key pair
                let (pk, sk) = create_kyber_key_pair(rng);
                pk_pq.replace(pk);
                sk_pq.replace(sk);
            }
            (Some(_), Some(_)) => {} // keep existing key
            (Some(_), None) => {
                return Err(Error::KeyError(
                    "Kyber public key cannot be computed from the secret key.".to_string(),
                ));
            }
        };
    }
    Ok(())
}

/// Update the private subkey of a `ReadOnly` partition
fn update_master_subkey(
    rng: &mut impl CryptoRngCore,
    _h: &R25519CurvePoint,
    msk: &mut SecretSubkey,
    is_hybridized: EncryptionHint,
) {
    let (sk_pq, _) = msk;
    // Add Kyber key if needed
    if is_hybridized.into() && sk_pq.is_none() {
        let (_, sk) = create_kyber_key_pair(rng);
        sk_pq.replace(sk);
    }
}

/// Generates the master secret key and master public key of the `Covercrypt`
/// scheme.
///
/// # Parameters
///
/// - `rng`             : random number generator
/// - `partitions`      : set of partition to be used
pub fn setup(
    rng: &mut impl CryptoRngCore,
    partitions: &HashMap<Partition, (EncryptionHint, AttributeStatus)>,
) -> (MasterSecretKey, MasterPublicKey) {
    let s = R25519PrivateKey::new(rng);
    let s1 = R25519PrivateKey::new(rng);
    let s2 = R25519PrivateKey::new(rng);
    let h = R25519PublicKey::from(&s);
    let g1 = R25519PublicKey::from(&s1);
    let g2 = R25519PublicKey::from(&s2);

    let mut sub_sk = RevisionMap::with_capacity(partitions.len());
    let mut sub_pk = HashMap::with_capacity(partitions.len());

    for (partition, &(is_hybridized, write_status)) in partitions {
        let (public_subkey, secret_subkey) = create_subkey_pair(rng, &h, is_hybridized);
        sub_sk.insert(partition.clone(), secret_subkey);
        if write_status == EncryptDecrypt {
            sub_pk.insert(partition.clone(), public_subkey);
        }
    }

    let kmac_key = Some(SymmetricKey::<KMAC_KEY_LENGTH>::new(rng));

    (
        MasterSecretKey {
            s,
            s1,
            s2,
            subkeys: sub_sk,
            kmac_key,
        },
        MasterPublicKey {
            g1,
            g2,
            subkeys: sub_pk,
        },
    )
}

/// Generates a user secret key for the given decryption set.
///
/// If the master secret key has a KMAC key, we use it to sign the user secret
/// key.
///
/// # Parameters
///
/// - `rng`             : random number generator
/// - `msk`             : master secret key
/// - `decryption_set`  : decryption set
pub fn keygen(
    rng: &mut impl CryptoRngCore,
    msk: &MasterSecretKey,
    decryption_set: &HashSet<Partition>,
) -> Result<UserSecretKey, Error> {
    let a = R25519PrivateKey::new(rng);
    let b = &(&msk.s - &(&a * &msk.s1)) / &msk.s2;
    // Use the last key for each partitions in the decryption set
    let mut subkeys = RevisionVec::with_capacity(decryption_set.len());
    decryption_set.iter().try_for_each(|partition| {
        let subkey = msk
            .subkeys
            .get_current_revision(partition)
            .ok_or(Error::KeyError(
                "Master secret key and Policy are not in sync.".to_string(),
            ))?;
        subkeys.create_chain_with_single_value(partition.clone(), subkey.clone());
        Ok::<_, Error>(())
    })?;

    let mut usk = UserSecretKey {
        a,
        b,
        subkeys,
        kmac: None,
    };
    usk.kmac = compute_user_key_kmac(msk, &usk);
    Ok(usk)
}

/// Generates a `Covercrypt` encapsulation of a random symmetric key.
/// Returns both the symmetric key and its encapsulation.
///
/// # Parameters
///
/// - `rng`             : secure random number generator
/// - `mpk`             : master public key
/// - `encryption_set`  : sets for which to generate a ciphertext
pub fn encaps(
    rng: &mut impl CryptoRngCore,
    mpk: &MasterPublicKey,
    encryption_set: &HashSet<Partition>,
) -> Result<(SymmetricKey<SYM_KEY_LENGTH>, Encapsulation), Error> {
    let mut seed = Zeroizing::new([0; SYM_KEY_LENGTH]);
    rng.fill_bytes(&mut *seed);

    let r = R25519PrivateKey::new(rng);
    let c1 = &mpk.g1 * &r;
    let c2 = &mpk.g2 * &r;
    let mut encs = HashSet::with_capacity(encryption_set.len());
    for partition in encryption_set {
        if let Some((pk_i, h_i)) = mpk.subkeys.get(partition) {
            let mut e_i = [0; SYM_KEY_LENGTH];
            kdf256!(&mut e_i, &(h_i * &r).to_bytes());
            xor_in_place(&mut e_i, &seed);
            if let Some(pk_i) = pk_i {
                let mut epq_i = [0; KYBER_INDCPA_BYTES];
                let mut coin = Zeroizing::new([0; KYBER_SYMBYTES]);
                rng.fill_bytes(&mut *coin);
                indcpa_enc(&mut epq_i, &e_i, pk_i, &*coin);
                encs.insert(KeyEncapsulation::HybridEncapsulation(Box::new(epq_i)));
            } else {
                encs.insert(KeyEncapsulation::ClassicEncapsulation(Box::new(e_i)));
            }
        }
        // else unknown target partition
        else {
            return Err(Error::KeyError(
                "Missing public key for this attribute, it appears that you are trying to encrypt \
                 for a disabled attribute."
                    .to_string(),
            ));
        }
    }
    let (tag, key) = eakem_hash!(TAG_LENGTH, SYM_KEY_LENGTH, &*seed, KEY_GEN_INFO)
        .map_err(Error::CryptoCoreError)?;
    Ok((key, Encapsulation { c1, c2, tag, encs }))
}

/// Tries to decapsulate the given `Covercrypt` encapsulation.
/// Returns the encapsulated symmetric key.
///
/// # Error
///
/// An error is returned if the user decryption set does not match the
/// encryption set used to generate the given encapsulation.
///
/// # Parameters
///
/// - `usk`             : user secret key
/// - `encapsulation`   : symmetric key encapsulation
pub fn decaps(
    usk: &UserSecretKey,
    encapsulation: &Encapsulation,
) -> Result<SymmetricKey<SYM_KEY_LENGTH>, Error> {
    let precomp = &(&encapsulation.c1 * &usk.a) + &(&encapsulation.c2 * &usk.b);
    for encapsulation_i in &encapsulation.encs {
        // BFS search user subkeys to first try the most recent rotations of each
        // partitions.
        for (sk_j, x_j) in usk.subkeys.bfs() {
            let e_j = match encapsulation_i {
                KeyEncapsulation::HybridEncapsulation(epq_i) => {
                    if let Some(sk_j) = sk_j {
                        let mut e_j = [0; SYM_KEY_LENGTH];
                        indcpa_dec(&mut e_j, &**epq_i, sk_j);
                        e_j
                    } else {
                        // Classic sub-key cannot decrypt hybridized encapsulation.
                        continue;
                    }
                }
                KeyEncapsulation::ClassicEncapsulation(e_i) => **e_i,
            };
            let mut seed = Zeroizing::new([0; SYM_KEY_LENGTH]);
            kdf256!(&mut *seed, &(&precomp * x_j).to_bytes());
            xor_in_place(&mut seed, &e_j);
            let (tag, key) = eakem_hash!(TAG_LENGTH, SYM_KEY_LENGTH, &*seed, KEY_GEN_INFO)
                .map_err(Error::CryptoCoreError)?;
            if tag == encapsulation.tag {
                return Ok(key);
            }
        }
    }
    Err(Error::InsufficientAccessPolicy)
}

/// Update the given master keys for the given list of partitions.
///
/// If a partition exists in the keys but not in the list, it will be removed
/// from the keys.
///
/// If a partition exists in the list, but not in the keys, it will be "added"
/// to the keys, by adding a new partition key pair as performed in the setup
/// procedure above.
///
/// If a partition exists in the list and in the keys, hybridization property
/// will be set as given.
///
/// If a partition exists in the list and in the master secret key a new public
/// sub-key is derived.
///
/// # Error
///
/// Due to library limitations, generating a new post-quantum public key from a
/// given post-quantum secret key is not possible yet. Therefore, an error will
/// be returned if no matching post-quantum public sub-key is found.
///
/// # Parameters
///
/// - `rng`             : random number generator
/// - `msk`             : master secret key
/// - `mpk`             : master public key
/// - `partition_set`   : new set of partitions to use after the update
pub fn update(
    rng: &mut impl CryptoRngCore,
    msk: &mut MasterSecretKey,
    mpk: &mut MasterPublicKey,
    partitions_set: &HashMap<Partition, (EncryptionHint, AttributeStatus)>,
) -> Result<(), Error> {
    // Remove keys from partitions deleted from Policy
    msk.subkeys.retain_keys(partitions_set.keys().collect());
    mpk.subkeys
        .retain(|part, _| partitions_set.contains_key(part));

    let h = R25519PublicKey::from(&msk.s);
    for (partition, &(is_hybridized, write_status)) in partitions_set {
        // check if secret key exist for this partition
        if let Some(secret_subkey) = msk.subkeys.get_mut(partition) {
            // update the master secret and public subkey if needed
            match (write_status, mpk.subkeys.get_mut(partition)) {
                (EncryptDecrypt, None) => unreachable!(),
                (EncryptDecrypt, Some(public_subkey)) => {
                    update_subkey_pair(rng, &h, public_subkey, secret_subkey, is_hybridized)?
                }
                (DecryptOnly, None) => update_master_subkey(rng, &h, secret_subkey, is_hybridized),
                (DecryptOnly, Some(_)) => {
                    mpk.subkeys.remove(partition);
                    update_master_subkey(rng, &h, secret_subkey, is_hybridized)
                }
            }
        } else {
            // generate new keys
            let (public_subkey, secret_subkey) = create_subkey_pair(rng, &h, is_hybridized);
            msk.subkeys.insert(partition.clone(), secret_subkey);
            if write_status == EncryptDecrypt {
                mpk.subkeys.insert(partition.clone(), public_subkey);
            }
        }
    }

    Ok(())
}

pub fn rekey(
    rng: &mut impl CryptoRngCore,
    msk: &mut MasterSecretKey,
    mpk: &mut MasterPublicKey,
    partitions_to_rotate: &HashSet<Partition>,
    keep_old_subkeys: bool,
) -> Result<(), Error> {
    let h = R25519PublicKey::from(&msk.s);
    for partition in partitions_to_rotate {
        // write a `get_encryption` function in a dedicated SecretSubkey struct?
        let is_hybridized = EncryptionHint::new(
            msk.subkeys
                .get_current_revision(partition)
                .and_then(|(sk_i, _)| sk_i.as_ref())
                .is_some(),
        );
        let (public_subkey, secret_subkey) = create_subkey_pair(rng, &h, is_hybridized);
        msk.subkeys.insert(partition.clone(), secret_subkey);
        if !keep_old_subkeys {
            // remove all older keys for a given partition
            msk.subkeys.pop_tail(partition);
        }

        // update public subkey if partition is not read only
        if mpk.subkeys.contains_key(partition) {
            mpk.subkeys.insert(partition.clone(), public_subkey);
        }
    }
    Ok(())
}
/// Refresh a user key from the master secret key and the given decryption set.
///
/// If `keep_old_rights` is set to false, old sub-keys are removed.
///
/// If a partition exists in the list and in the master secret key, the
/// associated sub-key is added to the user key.
///
/// # Parameters
///
/// - `msk`             : master secret key
/// - `usk`             : user secret key
/// - `keep_old_rights` : whether or not to keep old decryption rights
pub fn refresh(
    msk: &MasterSecretKey,
    usk: &mut UserSecretKey,
    keep_old_rights: bool,
) -> Result<(), Error> {
    verify_user_key_kmac(msk, usk)?;

    // Remove partitions missing from master keys
    usk.subkeys.retain_keys(msk.subkeys.keys().collect());

    for (partition, user_chain) in usk.subkeys.iter_mut() {
        let mut master_chain = msk.subkeys.iter_chain(partition).expect("at least one key");

        // Remove all but the most recent subkey for this partition
        if !keep_old_rights {
            // find the most recent subkey between the master and user key
            let master_first_key = master_chain.next().expect("at least one key");
            if Some(master_first_key) != user_chain.head.as_ref().map(|item| &item.data) {
                // new key
                let new_element = Box::new(Element::new(master_first_key.clone()));
                user_chain.head.replace(new_element);
            }
            // remove older keys if any and update length
            user_chain.pop_tail();
            // skip to next partition
            continue;
        }

        // 1 - add new master subkeys in user key if any
        let user_first_key = user_chain.head.take().expect("have one key");
        let mut insertion_cursor = &mut user_chain.head;

        let mut updated_chain_length = 0;
        // go through new keys found in MSK missing from USK
        for master_subkey in master_chain.by_ref() {
            updated_chain_length += 1;
            if master_subkey == &user_first_key.data {
                // we reached the first matching key between user and master keys
                // add this key back to the user subkeys and continue to step 2
                insertion_cursor = &mut insertion_cursor.insert(user_first_key).next;
                break;
            }
            let new_element = Element::new(master_subkey.clone());
            insertion_cursor = &mut insertion_cursor.insert(Box::new(new_element)).next;
        }

        // 2 - go through the remaining matching keys between the master and user chain
        for master_subkey in master_chain {
            let Some(current_user_subkey) = insertion_cursor else {
                // USK does not contain master keys from older rotations
                break;
            };
            // existing keys in both should match
            assert!(master_subkey == &current_user_subkey.data);
            insertion_cursor = &mut current_user_subkey.next;
            updated_chain_length += 1;
        }

        // 3 - old keys in USK not present in the MSK should be removed
        let _ = insertion_cursor.take();

        // update length
        user_chain.length = updated_chain_length;
    }

    // Update user key KMAC
    usk.kmac = compute_user_key_kmac(msk, usk);

    Ok(())
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{
        bytes_ser_de::Serializable, reexport::rand_core::SeedableRng, CsRng,
    };

    use super::*;

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
            (
                admin_partition.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
            (
                dev_partition.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
        ]);
        // user list
        let users_set = vec![
            HashSet::from([dev_partition.clone()]),
            HashSet::from([admin_partition.clone(), dev_partition.clone()]),
        ];
        // target set
        let admin_target_set = HashSet::from([admin_partition.clone()]);
        // secure random number generator
        let mut rng = CsRng::from_entropy();
        // setup scheme
        let (mut msk, mut mpk) = setup(&mut rng, &partitions_set);

        // The admin partition matches a hybridized sub-key.
        let admin_secret_subkeys = msk.subkeys.get_current_revision(&admin_partition);
        assert!(admin_secret_subkeys.is_some());
        assert!(admin_secret_subkeys.unwrap().0.is_some());

        // The developer partition matches a classic sub-key.
        let dev_secret_subkeys = msk.subkeys.get_current_revision(&dev_partition);
        assert!(dev_secret_subkeys.is_some());
        assert!(dev_secret_subkeys.unwrap().0.is_none());

        // Generate user secret keys.
        let mut dev_usk = keygen(&mut rng, &msk, &users_set[0])?;
        let admin_usk = keygen(&mut rng, &msk, &users_set[1])?;

        // Encapsulate key for the admin target set.
        let (sym_key, encapsulation) = encaps(&mut rng, &mpk, &admin_target_set).unwrap();

        // The encapsulation holds a unique, hybridized key encapsulation.
        assert_eq!(encapsulation.encs.len(), 1);
        for key_encapsulation in &encapsulation.encs {
            if let KeyEncapsulation::ClassicEncapsulation(_) = key_encapsulation {
                panic!("Wrong hybridization type");
            }
        }

        // Developer is unable to decapsulate.
        let res0 = decaps(&dev_usk, &encapsulation);
        assert!(res0.is_err(), "User 0 shouldn't be able to decapsulate!");

        // Admin is able to decapsulate.
        let res1 = decaps(&admin_usk, &encapsulation)?;
        assert_eq!(sym_key, res1, "Wrong decapsulation for user 1!");

        // Change partitions
        let client_partition = Partition(b"client".to_vec());
        let new_partitions_set = HashMap::from([
            (
                dev_partition.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
            (
                client_partition.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
        ]);
        let client_target_set = HashSet::from([client_partition.clone()]);

        update(&mut rng, &mut msk, &mut mpk, &new_partitions_set)?;
        refresh(&msk, &mut dev_usk, true)?;

        // The dev partition matches a hybridized sub-key.
        let dev_secret_subkeys = msk.subkeys.get_current_revision(&dev_partition);
        assert!(dev_secret_subkeys.is_some());
        assert!(dev_secret_subkeys.unwrap().0.is_some());

        // The client partition matches a classic sub-key.
        let client_secret_subkeys = msk.subkeys.get_current_revision(&client_partition);
        assert!(client_secret_subkeys.is_some());
        assert!(client_secret_subkeys.unwrap().0.is_none());

        // The developer now has a hybridized key.
        assert_eq!(dev_usk.subkeys.len(), 1);
        for key_encapsulation in &encapsulation.encs {
            if let KeyEncapsulation::ClassicEncapsulation(_) = key_encapsulation {
                panic!("Wrong hybridization type");
            }
        }

        let (sym_key, new_encapsulation) = encaps(&mut rng, &mpk, &client_target_set)?;

        // Client encapsulation holds a unique, classic key encapsulation.
        assert_eq!(new_encapsulation.encs.len(), 1);
        for key_encapsulation in &new_encapsulation.encs {
            if let KeyEncapsulation::HybridEncapsulation(_) = key_encapsulation {
                panic!("Wrong hybridization type");
            }
        }

        // The developer is unable to decapsulate.
        let res0 = decaps(&dev_usk, &encapsulation);
        assert!(
            res0.is_err(),
            "User 0 should not be able to decapsulate the old encapsulation."
        );

        // The admin is unable to decapsulate.
        let res1 = decaps(&admin_usk, &new_encapsulation);
        assert!(
            res1.is_err(),
            "User 1 should not be able to decapsulate the new encapsulation."
        );

        // Client is able to decapsulate.
        let client_usk = keygen(&mut rng, &msk, &HashSet::from([client_partition]))?;
        let res0 = decaps(&client_usk, &new_encapsulation);
        match res0 {
            Err(err) => panic!("Client should be able to decapsulate: {err:?}"),
            Ok(res) => assert_eq!(sym_key, res, "Wrong decapsulation."),
        }

        Ok(())
    }

    #[test]
    fn test_master_keys_update() -> Result<(), Error> {
        let partition_1 = Partition(b"1".to_vec());
        let partition_2 = Partition(b"2".to_vec());
        // partition list
        let partitions_set = HashMap::from([
            (
                partition_1.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
            (
                partition_2.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
        ]);
        // secure random number generator
        let mut rng = CsRng::from_entropy();
        // setup scheme
        let (mut msk, mut mpk) = setup(&mut rng, &partitions_set);

        // now remove partition 1 and add partition 3
        let partition_3 = Partition(b"3".to_vec());
        let new_partitions_set = HashMap::from([
            (
                partition_2.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
            (
                partition_3.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
        ]);
        update(&mut rng, &mut msk, &mut mpk, &new_partitions_set)?;
        assert!(!msk.subkeys.contains_key(&partition_1));
        assert!(msk.subkeys.contains_key(&partition_2));
        assert!(msk.subkeys.contains_key(&partition_3));
        assert!(!mpk.subkeys.contains_key(&partition_1));
        assert!(mpk.subkeys.contains_key(&partition_2));
        assert!(mpk.subkeys.contains_key(&partition_3));
        Ok(())
    }

    #[test]
    fn test_user_key_refresh() -> Result<(), Error> {
        let partition_1 = Partition(b"1".to_vec());
        let partition_2 = Partition(b"2".to_vec());
        let partition_3 = Partition(b"3".to_vec());
        // partition list
        let partitions_set = HashMap::from([
            (
                partition_1.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
            (
                partition_2.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
            (
                partition_3.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
        ]);
        // secure random number generator
        let mut rng = CsRng::from_entropy();
        // setup scheme
        let (mut msk, mut mpk) = setup(&mut rng, &partitions_set);
        // create a user key with access to partition 1 and 2
        let mut usk = keygen(
            &mut rng,
            &msk,
            &HashSet::from([partition_1.clone(), partition_2.clone()]),
        )?;

        // now remove partition 1 and add partition 4
        let partition_4 = Partition(b"4".to_vec());
        let new_partition_set = HashMap::from([
            (
                partition_2.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
            (
                partition_3.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
            (
                partition_4.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
        ]);
        //Covercrypt the master keys

        let old_msk = MasterSecretKey::deserialize(msk.serialize()?.as_slice())?;
        update(&mut rng, &mut msk, &mut mpk, &new_partition_set)?;
        // refresh the user key with partitions 2 and 4
        refresh(&msk, &mut usk, true)?;
        assert!(!usk.subkeys.flat_iter().any(|x| {
            x == (
                &partition_1,
                old_msk.subkeys.get_current_revision(&partition_1).unwrap(),
            )
        }));
        assert!(usk.subkeys.flat_iter().any(|x| {
            x == (
                &partition_2,
                msk.subkeys.get_current_revision(&partition_2).unwrap(),
            )
        }));
        assert!(!usk.subkeys.flat_iter().any(|x| {
            x == (
                &partition_3,
                old_msk.subkeys.get_current_revision(&partition_3).unwrap(),
            )
        }));
        assert!(usk.subkeys.flat_iter().any(|x| {
            x == (
                &partition_4,
                msk.subkeys.get_current_revision(&partition_4).unwrap(),
            )
        }));
        Ok(())
    }

    #[test]
    fn test_user_key_kmac() -> Result<(), Error> {
        let partition_1 = Partition(b"1".to_vec());
        let partition_2 = Partition(b"2".to_vec());
        // partition list
        let partitions_set = HashMap::from([
            (
                partition_1.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
            (
                partition_2.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
        ]);
        // secure random number generator
        let mut rng = CsRng::from_entropy();
        // setup scheme
        let (msk, _) = setup(&mut rng, &partitions_set);
        // create a user key with access to partition 1 and 2
        let mut usk = keygen(&mut rng, &msk, &HashSet::from([partition_1, partition_2]))?;

        assert!(verify_user_key_kmac(&msk, &usk).is_ok());
        let bytes = usk.serialize()?;
        let usk_ = UserSecretKey::deserialize(&bytes)?;
        assert!(verify_user_key_kmac(&msk, &usk_).is_ok());

        usk.subkeys.create_chain_with_single_value(
            Partition(b"3".to_vec()),
            (None, R25519PrivateKey::new(&mut rng)),
        );
        // KMAC verify will fail after modifying the user key
        assert!(verify_user_key_kmac(&msk, &usk).is_err());

        Ok(())
    }
}
