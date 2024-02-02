//! Implements the cryptographic primitives of `Covercrypt`, based on
//! `bib/Covercrypt.pdf`.

use std::{
    collections::{HashMap, HashSet, LinkedList},
    mem::take,
};

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
        Coordinate, EncryptionHint,
    },
    core::{Encapsulation, KeyEncapsulation, MasterPublicKey, MasterSecretKey, UserSecretKey},
    data_struct::{RevisionMap, RevisionVec},
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

        for (coordinate, (sk_i, x_i)) in usk.subkeys.flat_iter() {
            kmac.update(&coordinate.0);
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

/// Returns newly generated public and private Kyber key pair.
fn create_kyber_key_pair(rng: &mut impl CryptoRngCore) -> (KyberPublicKey, KyberSecretKey) {
    let (mut sk, mut pk) = (
        KyberSecretKey([0; KYBER_INDCPA_SECRETKEYBYTES]),
        KyberPublicKey([0; KYBER_INDCPA_PUBLICKEYBYTES]),
    );
    indcpa_keypair(&mut pk.0, &mut sk.0, None, rng);
    (pk, sk)
}

/// Returns a newly generated pair of public and private subkeys with optional
/// Kyber keys if hybridized.
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

/// Update a pair of public and private subkeys of a `ReadWrite` coordinate.
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
    *pk_i = h * sk_i;

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

/// Update the private subkey of a `ReadOnly` coordinate
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
/// - `coordinates`      : set of coordinate to be used
pub fn setup(
    rng: &mut impl CryptoRngCore,
    coordinates: HashMap<Coordinate, (EncryptionHint, AttributeStatus)>,
) -> (MasterSecretKey, MasterPublicKey) {
    let s = R25519PrivateKey::new(rng);
    let s1 = R25519PrivateKey::new(rng);
    let s2 = R25519PrivateKey::new(rng);
    let h = R25519PublicKey::from(&s);
    let g1 = R25519PublicKey::from(&s1);
    let g2 = R25519PublicKey::from(&s2);

    let mut sub_sk = RevisionMap::with_capacity(coordinates.len());
    let mut sub_pk = HashMap::with_capacity(coordinates.len());

    let policy = Policy::new();

    for (coordinate, (is_hybridized, write_status)) in coordinates {
        let (public_subkey, secret_subkey) = create_subkey_pair(rng, &h, is_hybridized);
        sub_sk.insert(coordinate.clone(), secret_subkey);
        if write_status == EncryptDecrypt {
            sub_pk.insert(coordinate, public_subkey);
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
            policy,
        },
        MasterPublicKey {
            g1,
            g2,
            subkeys: sub_pk,
            policy,
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
    decryption_set: &HashSet<Coordinate>,
) -> Result<UserSecretKey, Error> {
    let a = R25519PrivateKey::new(rng);
    let b = &(&msk.s - &(&a * &msk.s1)) / &msk.s2;
    // Use the last key for each coordinates in the decryption set
    let mut subkeys = RevisionVec::with_capacity(decryption_set.len());
    decryption_set.iter().try_for_each(|coordinate| {
        let subkey = msk.subkeys.get_latest(coordinate).ok_or(Error::KeyError(
            "Master secret key and Policy are not in sync.".to_string(),
        ))?;
        subkeys.create_chain_with_single_value(coordinate.clone(), subkey.clone());
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
    encryption_set: &HashSet<Coordinate>,
) -> Result<(SymmetricKey<SYM_KEY_LENGTH>, Encapsulation), Error> {
    let mut seed = Zeroizing::new([0; SYM_KEY_LENGTH]);
    rng.fill_bytes(&mut *seed);

    let r = R25519PrivateKey::new(rng);
    let c1 = &mpk.g1 * &r;
    let c2 = &mpk.g2 * &r;
    let mut encs = HashSet::with_capacity(encryption_set.len());
    for coordinate in encryption_set {
        if let Some((pk_i, h_i)) = mpk.subkeys.get(coordinate) {
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
        // else unknown target coordinate
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
        // coordinates.
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

/// Update the given master keys for the given list of coordinates.
///
/// If a coordinate exists in the keys but not in the list, it will be removed
/// from the keys.
///
/// If a coordinate exists in the list, but not in the keys, it will be "added"
/// to the keys, by adding a new coordinate key pair as performed in the setup
/// procedure above.
///
/// If a coordinate exists in the list and in the keys, hybridization property
/// will be set as given.
///
/// If a coordinate exists in the list and in the master secret key a new public
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
/// - `coordinate_set`   : new set of coordinates to use after the update
pub fn update(
    rng: &mut impl CryptoRngCore,
    msk: &mut MasterSecretKey,
    mpk: &mut MasterPublicKey,
    coordinates_set: HashMap<Coordinate, (EncryptionHint, AttributeStatus)>,
) -> Result<(), Error> {
    // Remove keys from coordinates deleted from Policy
    msk.subkeys
        .retain(|part| coordinates_set.contains_key(part));
    mpk.subkeys
        .retain(|part, _| coordinates_set.contains_key(part));

    let h = R25519PublicKey::from(&msk.s);
    for (coordinate, (is_hybridized, write_status)) in coordinates_set {
        // check if secret key exist for this coordinate
        if let Some(secret_subkey) = msk.subkeys.get_latest_mut(&coordinate) {
            // update the master secret and public subkey if needed
            match (write_status, mpk.subkeys.get_mut(&coordinate)) {
                (EncryptDecrypt, None) => unreachable!(),
                (EncryptDecrypt, Some(public_subkey)) => {
                    update_subkey_pair(rng, &h, public_subkey, secret_subkey, is_hybridized)?;
                }
                (DecryptOnly, None) => update_master_subkey(rng, &h, secret_subkey, is_hybridized),
                (DecryptOnly, Some(_)) => {
                    mpk.subkeys.remove(&coordinate);
                    update_master_subkey(rng, &h, secret_subkey, is_hybridized);
                }
            }
        } else {
            // generate new keys
            let (public_subkey, secret_subkey) = create_subkey_pair(rng, &h, is_hybridized);
            msk.subkeys.insert(coordinate.clone(), secret_subkey);
            if write_status == EncryptDecrypt {
                mpk.subkeys.insert(coordinate, public_subkey);
            }
        }
    }

    Ok(())
}

/// Rekeys the master keys by creating new subkeys for the given coordinates.
///
/// # Parameters
///
/// - `rng`             : random number generator
/// - `msk`             : master secret key
/// - `mpk`             : master public key
/// - `coordinate`      : set of keys coordinate to renew
pub fn rekey(
    rng: &mut impl CryptoRngCore,
    msk: &mut MasterSecretKey,
    mpk: &mut MasterPublicKey,
    coordinates: HashSet<Coordinate>,
) -> Result<(), Error> {
    let h = R25519PublicKey::from(&msk.s);
    for coordinate in coordinates {
        let is_hybridized = EncryptionHint::new(
            msk.subkeys
                .get_latest(&coordinate)
                .and_then(|(sk_i, _)| sk_i.as_ref())
                .is_some(),
        );
        let (public_subkey, secret_subkey) = create_subkey_pair(rng, &h, is_hybridized);
        msk.subkeys.insert(coordinate.clone(), secret_subkey);

        // update public subkey if coordinate is not read only
        if mpk.subkeys.contains_key(&coordinate) {
            mpk.subkeys.insert(coordinate, public_subkey);
        }
    }
    Ok(())
}

/// Prunes old subkeys from the master secret key for specified coordinates.
///
/// # Parameters
///
/// - `msk`             : master secret key
/// - `coordinates`     : set of subkeys coordinate to prune
pub fn prune(msk: &mut MasterSecretKey, coordinates: &HashSet<Coordinate>) -> Result<(), Error> {
    for coordinate in coordinates {
        msk.subkeys.keep(coordinate, 1);
    }
    Ok(())
}

/// Refresh a user key from the master secret key and the given decryption set.
///
/// If `keep_old_rights` is set to false, old sub-keys are removed.
///
/// If a coordinate exists in the list and in the master secret key, the
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

    // Take ownership of `usk.subkeys`
    let old_user_subkeys = take(&mut usk.subkeys);

    usk.subkeys = old_user_subkeys
        .into_iter()
        .filter_map(|(coordinate, user_chain)| {
            msk.subkeys.get(&coordinate).and_then(|msk_chain| {
                let mut msk_subkeys = if keep_old_rights {
                    msk_chain.iter().take(msk_chain.len())
                } else {
                    msk_chain.iter().take(1)
                };
                let mut usk_subkeys = user_chain.into_iter();
                let first_usk_subkey = usk_subkeys.next()?;

                let mut new_usk_subkeys = LinkedList::new();
                // Add new master secret subkeys
                for msk_subkey in msk_subkeys.by_ref() {
                    if msk_subkey == &first_usk_subkey {
                        new_usk_subkeys.push_back(first_usk_subkey);
                        break;
                    }
                    new_usk_subkeys.push_back(msk_subkey.clone());
                }
                // Keep old matching subkeys between the master and user subkeys
                for subkey in usk_subkeys {
                    if Some(&subkey) != msk_subkeys.next() {
                        break;
                    }
                    new_usk_subkeys.push_back(subkey);
                }
                Some((coordinate, new_usk_subkeys))
            })
        })
        .collect::<RevisionVec<_, _>>();

    // Update user key KMAC
    usk.kmac = compute_user_key_kmac(msk, usk);

    Ok(())
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{
        reexport::rand_core::SeedableRng, CsRng,
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
        let admin_coordinate = Coordinate(b"admin".to_vec());
        let dev_coordinate = Coordinate(b"dev".to_vec());
        // coordinate list
        let coordinates_set = HashMap::from([
            (
                admin_coordinate.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
            (
                dev_coordinate.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
        ]);
        // user list
        let users_set = vec![
            HashSet::from([dev_coordinate.clone()]),
            HashSet::from([admin_coordinate.clone(), dev_coordinate.clone()]),
        ];
        // target set
        let admin_target_set = HashSet::from([admin_coordinate.clone()]);
        // secure random number generator
        let mut rng = CsRng::from_entropy();
        // setup scheme
        let (mut msk, mut mpk) = setup(&mut rng, coordinates_set);

        // The admin coordinate matches a hybridized sub-key.
        let admin_secret_subkeys = msk.subkeys.get_latest(&admin_coordinate);
        assert!(admin_secret_subkeys.is_some());
        assert!(admin_secret_subkeys.unwrap().0.is_some());

        // The developer coordinate matches a classic sub-key.
        let dev_secret_subkeys = msk.subkeys.get_latest(&dev_coordinate);
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

        // Change coordinates
        let client_coordinate = Coordinate(b"client".to_vec());
        let new_coordinates_set = HashMap::from([
            (
                dev_coordinate.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
            (
                client_coordinate.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
        ]);
        let client_target_set = HashSet::from([client_coordinate.clone()]);

        update(&mut rng, &mut msk, &mut mpk, new_coordinates_set)?;
        refresh(&msk, &mut dev_usk, true)?;

        // The dev coordinate matches a hybridized sub-key.
        let dev_secret_subkeys = msk.subkeys.get_latest(&dev_coordinate);
        assert!(dev_secret_subkeys.is_some());
        assert!(dev_secret_subkeys.unwrap().0.is_some());

        // The client coordinate matches a classic sub-key.
        let client_secret_subkeys = msk.subkeys.get_latest(&client_coordinate);
        assert!(client_secret_subkeys.is_some());
        assert!(client_secret_subkeys.unwrap().0.is_none());

        // The developer now has a hybridized key.
        assert_eq!(dev_usk.subkeys.count_elements(), 1);
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
        let client_usk = keygen(&mut rng, &msk, &HashSet::from([client_coordinate]))?;
        let res0 = decaps(&client_usk, &new_encapsulation);
        match res0 {
            Err(err) => panic!("Client should be able to decapsulate: {err:?}"),
            Ok(res) => assert_eq!(sym_key, res, "Wrong decapsulation."),
        }

        Ok(())
    }

    #[test]
    fn test_master_keys_update() -> Result<(), Error> {
        let coordinate_1 = Coordinate(b"1".to_vec());
        let coordinate_2 = Coordinate(b"2".to_vec());
        // coordinate list
        let coordinates_set = HashMap::from([
            (
                coordinate_1.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
            (
                coordinate_2.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
        ]);
        // secure random number generator
        let mut rng = CsRng::from_entropy();
        // setup scheme
        let (mut msk, mut mpk) = setup(&mut rng, coordinates_set);

        // now remove coordinate 1 and add coordinate 3
        let coordinate_3 = Coordinate(b"3".to_vec());
        let new_coordinates_set = HashMap::from([
            (
                coordinate_2.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
            (
                coordinate_3.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
        ]);
        update(&mut rng, &mut msk, &mut mpk, new_coordinates_set)?;
        assert!(!msk.subkeys.contains_key(&coordinate_1));
        assert!(msk.subkeys.contains_key(&coordinate_2));
        assert!(msk.subkeys.contains_key(&coordinate_3));
        assert!(!mpk.subkeys.contains_key(&coordinate_1));
        assert!(mpk.subkeys.contains_key(&coordinate_2));
        assert!(mpk.subkeys.contains_key(&coordinate_3));
        Ok(())
    }

    #[test]
    fn test_user_key_refresh() -> Result<(), Error> {
        let coordinate_1 = Coordinate(b"1".to_vec());
        let coordinate_2 = Coordinate(b"2".to_vec());
        let coordinate_3 = Coordinate(b"3".to_vec());
        // coordinate list
        let coordinates_set = HashMap::from([
            (
                coordinate_1.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
            (
                coordinate_2.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
            (
                coordinate_3.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
        ]);
        // secure random number generator
        let mut rng = CsRng::from_entropy();
        // setup scheme
        let (mut msk, mut mpk) = setup(&mut rng, coordinates_set);
        // create a user key with access to coordinate 1 and 2
        let mut usk = keygen(
            &mut rng,
            &msk,
            &HashSet::from([coordinate_1.clone(), coordinate_2.clone()]),
        )?;

        // now remove coordinate 1 and remove hybrid key from coordinate 3
        let new_coordinate_set = HashMap::from([
            (
                coordinate_2.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
            (
                coordinate_3.clone(),
                (EncryptionHint::Classic, AttributeStatus::EncryptDecrypt),
            ),
        ]);
        //Covercrypt the master keys

        let old_msk = MasterSecretKey::deserialize(msk.serialize()?.as_slice())?;
        update(&mut rng, &mut msk, &mut mpk, new_coordinate_set)?;
        // refresh the user key
        refresh(&msk, &mut usk, true)?;
        // user key kept old access to coordinate 1
        assert!(!usk.subkeys.flat_iter().any(|x| {
            x == (
                &coordinate_1,
                old_msk.subkeys.get_latest(&coordinate_1).unwrap(),
            )
        }));
        assert!(usk.subkeys.flat_iter().any(|x| {
            x == (
                &coordinate_2,
                msk.subkeys.get_latest(&coordinate_2).unwrap(),
            )
        }));
        // user key kept the old hybrid key for coordinate 3
        assert!(!usk.subkeys.flat_iter().any(|x| {
            x == (
                &coordinate_3,
                old_msk.subkeys.get_latest(&coordinate_3).unwrap(),
            )
        }));

        // add new key for coordinate 2
        rekey(
            &mut rng,
            &mut msk,
            &mut mpk,
            HashSet::from([coordinate_2.clone()]),
        )?;
        // refresh the user key
        refresh(&msk, &mut usk, true)?;
        let usk_subkeys: Vec<_> = usk
            .subkeys
            .flat_iter()
            .filter(|(part, _)| *part == &coordinate_2)
            .map(|(_, subkey)| subkey)
            .collect();
        let msk_subkeys: Vec<_> = msk.subkeys.get(&coordinate_2).unwrap().iter().collect();
        assert_eq!(usk_subkeys.len(), 2);
        assert_eq!(usk_subkeys, msk_subkeys);

        Ok(())
    }

    #[test]
    fn test_user_key_kmac() -> Result<(), Error> {
        let coordinate_1 = Coordinate(b"1".to_vec());
        let coordinate_2 = Coordinate(b"2".to_vec());
        // coordinate list
        let coordinates_set = HashMap::from([
            (
                coordinate_1.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
            (
                coordinate_2.clone(),
                (EncryptionHint::Hybridized, AttributeStatus::EncryptDecrypt),
            ),
        ]);
        // secure random number generator
        let mut rng = CsRng::from_entropy();
        // setup scheme
        let (msk, _) = setup(&mut rng, coordinates_set);
        // create a user key with access to coordinate 1 and 2
        let mut usk = keygen(&mut rng, &msk, &HashSet::from([coordinate_1, coordinate_2]))?;

        assert!(verify_user_key_kmac(&msk, &usk).is_ok());
        let bytes = usk.serialize()?;
        let usk_ = UserSecretKey::deserialize(&bytes)?;
        assert!(verify_user_key_kmac(&msk, &usk_).is_ok());

        usk.subkeys.create_chain_with_single_value(
            Coordinate(b"3".to_vec()),
            (None, R25519PrivateKey::new(&mut rng)),
        );
        // KMAC verify will fail after modifying the user key
        assert!(verify_user_key_kmac(&msk, &usk).is_err());

        Ok(())
    }
}
