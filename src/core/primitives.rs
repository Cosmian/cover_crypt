use std::{
    collections::{HashMap, HashSet, LinkedList},
    mem::take,
};

use cosmian_crypto_core::{
    reexport::rand_core::CryptoRngCore, RandomFixedSizeCBytes, Secret, SymmetricKey,
};
use tiny_keccak::{Hasher, IntoXof, Kmac, Xof};
use zeroize::Zeroize;

use super::{
    elgamal, postquantum, CoordinateKeypair, CoordinatePublicKey, CoordinateSecretKey,
    KmacSignature, TracingSecretKey, MIN_TRACING_LEVEL, SEED_LENGTH, SIGNATURE_LENGTH,
    SIGNING_KEY_LENGTH, TAG_LENGTH,
};
use crate::{
    abe_policy::{AttributeStatus, Coordinate, EncryptionHint},
    core::{Encapsulation, MasterPublicKey, MasterSecretKey, SeedEncapsulation, UserSecretKey},
    data_struct::{RevisionMap, RevisionVec},
    Error,
};

/// Additional information to generate symmetric key using the KDF.
// TODO: find a more thoughtful message.
pub(crate) const KEY_GEN_INFO: &[u8] = b"key generation info";

/// Computes the signature of the given USK using the MSK.
fn sign_usk(msk: &MasterSecretKey, usk: &UserSecretKey) -> Option<KmacSignature> {
    if let Some(kmac_key) = &msk.signing_key {
        let mut kmac = Kmac::v256(kmac_key, b"USK signature");
        for marker in usk.id.iter() {
            kmac.update(marker.as_bytes())
        }
        // Subkeys ordering needs to be deterministic to allow deterministic
        // signatures. This explains why a hash-map cannot be used in USK.
        for (coordinate, keys) in usk.coordinate_keys.iter() {
            kmac.update(coordinate);
            for k in keys.iter() {
                match k {
                    CoordinateSecretKey::Hybridized {
                        postquantum_sk,
                        elgamal_sk,
                    } => {
                        kmac.update(postquantum_sk);
                        kmac.update(elgamal_sk.as_bytes());
                    }
                    CoordinateSecretKey::Classic { elgamal_sk } => {
                        kmac.update(elgamal_sk.as_bytes());
                    }
                }
            }
        }
        let mut res = [0; SIGNATURE_LENGTH];
        kmac.into_xof().squeeze(&mut res);
        Some(res)
    } else {
        None
    }
}

/// Verifies the integrity of the given USK using the MSK.
fn verify_usk(msk: &MasterSecretKey, usk: &UserSecretKey) -> Result<(), Error> {
    let fresh_signature = sign_usk(msk, usk);
    if fresh_signature != usk.msk_signature {
        Err(Error::KeyError(
            "USK failed the integrity check".to_string(),
        ))
    } else {
        Ok(())
    }
}

/// Generates new MSK with the given tracing level.
pub fn setup(rng: &mut impl CryptoRngCore, tracing_level: usize) -> Result<MasterSecretKey, Error> {
    if tracing_level < MIN_TRACING_LEVEL {
        return Err(Error::OperationNotPermitted(format!(
            "tracing level cannot be lower than {MIN_TRACING_LEVEL}"
        )));
    }
    let s = elgamal::Scalar::new(rng);

    let mut tsk = TracingSecretKey::default();
    (0..=tracing_level).for_each(|_| tsk.increase_tracing(rng));

    Ok(MasterSecretKey {
        s,
        tsk,
        coordinate_keypairs: RevisionMap::new(),
        signing_key: Some(SymmetricKey::<SIGNING_KEY_LENGTH>::new(rng)),
    })
}

/// Generates a new MPK holding the latest public information of each universal coordinate.
pub fn mpk_keygen(msk: &MasterSecretKey) -> Result<MasterPublicKey, Error> {
    Ok(MasterPublicKey {
        h: msk.binding_point(),
        tpk: msk.tsk.tpk(),
        coordinate_keys: msk.get_latest_coordinate_pk().collect(),
    })
}

/// Generates a USK for the given set of coordinates.
///
/// The generated key is provided with the last version of the key for each
/// coordinate in the given set. The USK can then open any up-to-date key
/// encapsulation for any such coordinate (provided the coordinate was not
/// rekeyed).
///
/// If the MSK has a signing key, sign the USK.
pub fn usk_keygen(
    rng: &mut impl CryptoRngCore,
    msk: &mut MasterSecretKey,
    coordinates: HashSet<Coordinate>,
) -> Result<UserSecretKey, Error> {
    let coordinate_keys = msk
        .get_latest_coordinate_sk(coordinates.into_iter())
        .collect::<Result<RevisionVec<Coordinate, CoordinateSecretKey>, Error>>()?;

    // Do not generate the ID if an error happens when extracting coordinate secrets.
    let id = msk.generate_user_id(rng)?;

    // Signature has to be added in a second time to allow using the signing
    // primitive. Maybe a better signing function could avoid it.
    let mut usk = UserSecretKey {
        id,
        coordinate_keys,
        msk_signature: None,
    };
    usk.msk_signature = sign_usk(msk, &usk);
    Ok(usk)
}

/// Generates a Covercrypt encapsulation of a random `SEED_LENGTH`-byte key for
/// the coordinate in the encryption set.
///
/// Returns both the key and its encapsulation.
pub fn encaps(
    rng: &mut impl CryptoRngCore,
    mpk: &MasterPublicKey,
    encryption_set: &HashSet<Coordinate>,
) -> Result<(Secret<SEED_LENGTH>, Encapsulation), Error> {
    let subkeys = encryption_set
        .iter()
        .map(|coordinate| {
            mpk.coordinate_keys.get(coordinate).ok_or_else(|| {
                Error::KeyError(format!("no public key for coordinate '{coordinate:#?}'"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    CoordinatePublicKey::assert_homogeneity(&subkeys)?;

    let seed = Secret::<SEED_LENGTH>::random(rng);
    let ephemeral_random = elgamal::Scalar::new(rng);

    let encaps_classical = |pk| {
        let mut elgamal_ctx = [0; SEED_LENGTH];
        elgamal::mask(&mut elgamal_ctx, &ephemeral_random, pk, &seed);
        elgamal_ctx
    };

    let mut encaps_hybridized =
        |postquantum_pk, elgamal_pk| -> Result<postquantum::Ciphertext, Error> {
            let mut elgamal_ctx = [0; SEED_LENGTH];
            elgamal::mask(&mut elgamal_ctx, &ephemeral_random, elgamal_pk, &seed);
            let postquantum_ctx = postquantum::encrypt(rng, postquantum_pk, &elgamal_ctx)?;
            elgamal_ctx.zeroize(); // ElGamal ciphertext is not secure in a post-quantum world
            Ok(postquantum_ctx)
        };

    let coordinate_encapsulations = subkeys
        .into_iter()
        .map(|subkey| -> Result<SeedEncapsulation, _> {
            match subkey {
                CoordinatePublicKey::Classic { elgamal_pk } => {
                    Ok(SeedEncapsulation::Classic(encaps_classical(elgamal_pk)))
                }
                CoordinatePublicKey::Hybridized {
                    postquantum_pk,
                    elgamal_pk,
                } => {
                    encaps_hybridized(postquantum_pk, elgamal_pk).map(SeedEncapsulation::Hybridized)
                }
            }
        })
        .collect::<Result<HashSet<_>, Error>>()?;

    let traps = mpk.set_traps(&ephemeral_random);
    let (tag, key) = eakem_hash!(TAG_LENGTH, SEED_LENGTH, &*seed, KEY_GEN_INFO)
        .map_err(Error::CryptoCoreError)?;

    Ok((
        key,
        Encapsulation {
            tag,
            traps,
            coordinate_encapsulations,
        },
    ))
}

/// Attempts opening the Covercrypt encapsulation using the given USK. Returns
/// the encapsulated key upon success, otherwise returns `None`.
pub fn decaps(
    usk: &UserSecretKey,
    encapsulation: &Encapsulation,
) -> Result<Option<Secret<SEED_LENGTH>>, Error> {
    let ephemeral_point = usk
        .id
        .iter()
        .zip(encapsulation.traps.iter())
        .map(|(marker, trap)| trap * marker)
        .fold(elgamal::EcPoint::identity(), |mut acc, elt| {
            acc = &acc + &elt;
            acc
        });

    for enc in &encapsulation.coordinate_encapsulations {
        // The breadth-first search tries all coordinate subkeys in a chronological order.
        for key in usk.coordinate_keys.bfs() {
            let seed: Secret<SEED_LENGTH> = match (key, enc) {
                (
                    CoordinateSecretKey::Hybridized {
                        postquantum_sk,
                        elgamal_sk,
                    },
                    SeedEncapsulation::Hybridized(ctx),
                ) => {
                    let elgammal_ctx = postquantum::decrypt(postquantum_sk, ctx);
                    elgamal::unmask(elgamal_sk, &ephemeral_point, &elgammal_ctx)?
                }
                (CoordinateSecretKey::Classic { elgamal_sk }, SeedEncapsulation::Classic(enc)) => {
                    elgamal::unmask(elgamal_sk, &ephemeral_point, enc)?
                }
                (CoordinateSecretKey::Classic { .. }, SeedEncapsulation::Hybridized(_))
                | (CoordinateSecretKey::Hybridized { .. }, SeedEncapsulation::Classic(_)) => {
                    // It is safe not to try decapsulating if there is a
                    // hybridization mismatch as it means either the
                    // encapsulation is not associated to the key coordinate,
                    // either the encapsulation is not valid.
                    continue;
                }
            };

            let (tag, seed) = eakem_hash!(TAG_LENGTH, SEED_LENGTH, &*seed, KEY_GEN_INFO)
                .map_err(Error::CryptoCoreError)?;
            if tag == encapsulation.tag {
                return Ok(Some(seed));
            }
        }
    }
    Ok(None)
}

/// Updates the coordinate keys from given MSK relatively to the given universal
/// coordinates:
///
/// - removes coordinates from the MSK that do not belong to the given coordinates;
/// - adds the given coordinates that do not belong yet to the MSK and generates
/// an associated keypair;
/// - modify hybridization property accordingly to the one of the given coordinates;
/// - modify the attribute status accordingly to the one of the given coordinates.
pub fn update_coordinate_keys(
    rng: &mut impl CryptoRngCore,
    msk: &mut MasterSecretKey,
    coordinates: HashMap<Coordinate, (EncryptionHint, AttributeStatus)>,
) -> Result<(), Error> {
    let h = msk.binding_point();
    let mut coordinate_keypairs = take(&mut msk.coordinate_keypairs);
    coordinate_keypairs.retain(|coordinate| coordinates.contains_key(coordinate));

    for (coordinate, (hint, status)) in coordinates {
        if let Some(coordinate_keypair) = coordinate_keypairs.get_latest_mut(&coordinate) {
            if EncryptionHint::Classic == hint {
                coordinate_keypair.drop_hybridization();
            }
            if AttributeStatus::DecryptOnly == status {
                coordinate_keypair.drop_encryption_key();
            }
        } else {
            if AttributeStatus::DecryptOnly == status {
                return Err(Error::OperationNotPermitted(
                    "cannot add decrypt only coordinate key".to_string(),
                ));
            }

            let elgamal_sk = elgamal::Scalar::new(rng);
            let elgamal_pk = &h * &elgamal_sk;
            let elgamal_keypair = elgamal::Keypair::new(elgamal_sk, elgamal_pk);

            let postquantum_keypair = if EncryptionHint::Hybridized == hint {
                Some(postquantum::Keypair::random(rng))
            } else {
                None
            };

            coordinate_keypairs.insert(
                coordinate,
                CoordinateKeypair {
                    elgamal_keypair,
                    postquantum_keypair,
                },
            );
        }
    }
    msk.coordinate_keypairs = coordinate_keypairs;
    Ok(())
}

/// Generates a new key for each coordinate in the given set that belongs to the
/// MSK.
pub fn rekey(
    rng: &mut impl CryptoRngCore,
    msk: &mut MasterSecretKey,
    target_space: HashSet<Coordinate>,
) -> Result<(), Error> {
    let h = msk.binding_point();
    for coordinate in target_space {
        if msk.coordinate_keypairs.contains_key(&coordinate) {
            let is_hybridized = msk
                .coordinate_keypairs
                .get_latest(&coordinate)
                .map(CoordinateKeypair::is_hybridized)
                .ok_or_else(|| {
                    Error::OperationNotPermitted(format!(
                        "no current key for coordinate {coordinate:#?}"
                    ))
                })?;

            msk.coordinate_keypairs.insert(
                coordinate,
                CoordinateKeypair::random(rng, &h, is_hybridized),
            );
        } else {
            return Err(Error::OperationNotPermitted(
                "cannot re-key coordinate that does not belong to the MSK".to_string(),
            ));
        }
    }
    Ok(())
}

/// Removes old keys associated all coordinates in the given set from the MSK.
///
/// # Safety
///
/// This operation *permanently* deletes old keys, this is thus not reversible!
pub fn prune(msk: &mut MasterSecretKey, coordinates: &HashSet<Coordinate>) {
    for coordinate in coordinates {
        msk.coordinate_keypairs.keep(coordinate, 1);
    }
}

/// Refreshes the USK relatively to the given MSK.
///
/// For each coordinate in the USK:
/// - if `keep_old_rights` is set to false, the last secret from MSK is given to
/// the USK, all secrets previously owned by the USK are removed;
/// - otherwise, secrets from the USK that do not belong to the MSK are removed,
/// and secrets from the MSK that do not belong to the USK are added.
pub fn refresh(
    rng: &mut impl CryptoRngCore,
    msk: &mut MasterSecretKey,
    usk: &mut UserSecretKey,
    keep_old_rights: bool,
) -> Result<(), Error> {
    verify_usk(msk, usk)?;

    let usk_id = take(&mut usk.id);
    usk.id = msk.refresh_id(rng, usk_id)?;

    let usk_rights = take(&mut usk.coordinate_keys);
    let new_rights = if keep_old_rights {
        refresh_coordinate_keys(msk, usk_rights)
    } else {
        msk.get_latest_coordinate_sk(usk_rights.into_keys())
            .collect::<Result<RevisionVec<Coordinate, CoordinateSecretKey>, Error>>()?
    };
    usk.coordinate_keys = new_rights;
    usk.msk_signature = sign_usk(msk, usk);
    Ok(())
}

/// For each coordinate given, filters out associated secrets that do not belong
/// to the MSK and add the most recent ones from the MSK to the associated list
/// of secret.
///
/// Removes coordinates that do not belong to the MSK.
///
/// Preserves the following invariant:
/// > 1. most recent coordinate secrets are listed first
/// > 2) USK secrets are a strict sub-sequence of the MSK ones
fn refresh_coordinate_keys(
    msk: &MasterSecretKey,
    coordinate_keys: RevisionVec<Coordinate, CoordinateSecretKey>,
) -> RevisionVec<Coordinate, CoordinateSecretKey> {
    coordinate_keys
        .into_iter()
        .filter_map(|(coordinate, user_chain)| {
            msk.coordinate_keypairs
                .get(&coordinate)
                .and_then(|msk_chain| {
                    let mut updated_chain = LinkedList::new();
                    let mut msk_keypairs = msk_chain.iter();
                    let mut usk_secrets = user_chain.into_iter();
                    let first_secret = usk_secrets.next()?;

                    // Add the most recent secrets from the MSK that do not belong
                    // to the USK at the front of the updated chain (cf Invariant.1)
                    for keypair in msk_keypairs.by_ref() {
                        if keypair.contains(&first_secret) {
                            break;
                        }
                        updated_chain.push_back(keypair.secret_key());
                    }

                    // Push the first USK secret since it was consumed from the USK
                    // chain iterator.
                    updated_chain.push_back(first_secret);

                    // Push the secrets already stored in the USK that also belong
                    // to the MSK keypairs.
                    for coordinate_sk in usk_secrets {
                        if let Some(keypair) = msk_keypairs.next() {
                            if keypair.contains(&coordinate_sk) {
                                updated_chain.push_back(coordinate_sk);
                                continue;
                            }
                        }
                        // No more shared secret after the first divergence (cf Invariant.2).
                        break;
                    }
                    Some((coordinate, updated_chain))
                })
        })
        .collect::<RevisionVec<_, _>>()
}
