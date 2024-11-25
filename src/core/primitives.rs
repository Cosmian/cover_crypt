use std::{
    any::type_name,
    cmp::Ordering,
    collections::{HashMap, HashSet, LinkedList},
    mem::take,
    u8,
};

use cosmian_crypto_core::{
    bytes_ser_de::Serializable,
    reexport::rand_core::{CryptoRngCore, RngCore},
    R25519CurvePoint, RandomFixedSizeCBytes, Secret, SymmetricKey,
};

use tiny_keccak::{Hasher, IntoXof, Kmac, Shake, Xof};
use zeroize::Zeroize;

use crate::{
    abe_policy::{AccessStructure, AttributeStatus, EncryptionHint, Right},
    core::{
        kem::MlKem512, nike::R25519, EcPoint, Encapsulation, KmacSignature, MasterPublicKey,
        MasterSecretKey, RightPublicKey, RightSecretKey, Scalar, TracingSecretKey, UserId,
        UserSecretKey, XEnc, MIN_TRACING_LEVEL, SHARED_SECRET_LENGTH, SIGNATURE_LENGTH,
        SIGNING_KEY_LENGTH, TAG_LENGTH,
    },
    data_struct::{RevisionMap, RevisionVec},
    traits::{Kem, Nike},
    Error,
};

fn xor_2<const LENGTH: usize>(lhs: &[u8; LENGTH], rhs: &[u8; LENGTH]) -> [u8; LENGTH] {
    let mut out = [0; LENGTH];
    for pos in 0..LENGTH {
        out[pos] = lhs[pos] ^ rhs[pos];
    }
    out
}

fn xor_3<const LENGTH: usize>(
    lhs: &[u8; LENGTH],
    mhs: &[u8; LENGTH],
    rhs: &[u8; LENGTH],
) -> [u8; LENGTH] {
    let mut out = [0; LENGTH];
    for pos in 0..LENGTH {
        out[pos] = lhs[pos] ^ mhs[pos] ^ rhs[pos];
    }
    out
}

fn shuffle<T>(xs: &mut [T], rng: &mut impl RngCore) {
    xs.sort_by(|_, _| {
        if rng.next_u32() & 1 == 0 {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    });
}

/// Computes the signature of the given USK using the MSK.
fn sign(
    msk: &MasterSecretKey,
    id: &UserId,
    keys: &RevisionVec<Right, RightSecretKey>,
) -> Result<Option<KmacSignature>, Error> {
    if let Some(kmac_key) = &msk.signing_key {
        let mut kmac = Kmac::v256(&**kmac_key, b"USK signature");
        for marker in id.iter() {
            kmac.update(marker.as_bytes())
        }
        // Subkeys ordering needs to be deterministic to allow deterministic
        // signatures. This explains why a hash-map is not used in USK.
        for (coordinate, keys) in keys.iter() {
            kmac.update(coordinate);
            for subkey in keys.iter() {
                match subkey {
                    RightSecretKey::Hybridized { sk: s_i, dk: dk_i } => {
                        kmac.update(s_i.as_bytes());
                        kmac.update(&dk_i.serialize()?);
                    }
                    RightSecretKey::Classic { sk: s_i } => {
                        kmac.update(s_i.as_bytes());
                    }
                }
            }
        }
        let mut res = [0; SIGNATURE_LENGTH];
        kmac.into_xof().squeeze(&mut res);
        Ok(Some(res))
    } else {
        Ok(None)
    }
}

/// Verifies the integrity of the given USK using the MSK.
fn verify(msk: &MasterSecretKey, usk: &UserSecretKey) -> Result<(), Error> {
    let fresh_signature = sign(msk, &usk.id, &usk.secrets)?;
    if fresh_signature != usk.signature {
        Err(Error::KeyError(
            "USK failed the integrity check".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn g_hash(seed: &Secret<SHARED_SECRET_LENGTH>) -> Result<Scalar, Error> {
    let mut bytes = [0; 64];
    let mut hasher = Shake::v256();
    hasher.update(&**seed);
    hasher.squeeze(&mut bytes);
    let s = Scalar::from_raw_bytes(&bytes);
    bytes.zeroize();
    Ok(s)
}

fn h_hash(mut ss: EcPoint) -> Secret<SHARED_SECRET_LENGTH> {
    let mut secret = Secret::<SHARED_SECRET_LENGTH>::default();
    let mut hasher = Shake::v256();
    hasher.update(&ss.to_bytes());
    hasher.squeeze(&mut *secret);
    ss.zeroize();
    secret
}

fn j_hash(
    seed: &[u8; SHARED_SECRET_LENGTH],
    c: &[EcPoint],
    encapsulations: &[Encapsulation],
) -> Result<([u8; TAG_LENGTH], Secret<SHARED_SECRET_LENGTH>), Error> {
    let mut hasher = Shake::v256();

    hasher.update(seed);
    for (c_i, seed_encapsulation) in c.iter().zip(encapsulations) {
        hasher.update(&c_i.to_bytes());
        match seed_encapsulation {
            Encapsulation::Classic { F: F_i } => hasher.update(F_i),
            Encapsulation::Hybridized { E: E_i, F: F_i } => {
                hasher.update(&E_i.serialize()?);
                hasher.update(F_i);
            }
        }
    }

    let mut tag = [0; TAG_LENGTH];
    let mut seed = Secret::<SHARED_SECRET_LENGTH>::default();
    hasher.squeeze(&mut tag);
    hasher.squeeze(&mut *seed);
    Ok((tag, seed))
}

/// Generates new MSK with the given tracing level.
pub fn setup(tracing_level: usize, rng: &mut impl CryptoRngCore) -> Result<MasterSecretKey, Error> {
    if tracing_level < MIN_TRACING_LEVEL {
        return Err(Error::OperationNotPermitted(format!(
            "tracing level cannot be lower than {MIN_TRACING_LEVEL}"
        )));
    }

    let tsk = TracingSecretKey::new_with_level(tracing_level, rng)?;
    let policy = AccessStructure::default();

    Ok(MasterSecretKey {
        tsk,
        secrets: RevisionMap::new(),
        signing_key: Some(SymmetricKey::<SIGNING_KEY_LENGTH>::new(rng)),
        access_structure: policy,
    })
}

/// Generates a USK for the given set of coordinates.
///
/// The generated key is provided with the last version of the key for each
/// coordinate in the given set. The USK can then open any up-to-date key
/// encapsulation for any such coordinate (provided the coordinate was not
/// re-keyed in-between).
///
/// If the MSK has a signing key, signs the USK.
pub fn usk_keygen(
    rng: &mut impl CryptoRngCore,
    msk: &mut MasterSecretKey,
    coordinates: HashSet<Right>,
) -> Result<UserSecretKey, Error> {
    // Extract keys first to avoid unnecessary computation in case those cannot be found.
    let coordinate_keys = msk
        .get_latest_right_sk(coordinates.into_iter())
        .collect::<Result<RevisionVec<_, _>, Error>>()?;
    let id = msk.tsk.generate_user_id(rng)?;
    let signature = sign(msk, &id, &coordinate_keys)?;

    Ok(UserSecretKey {
        id,
        secrets: coordinate_keys,
        signature,
    })
}

/// Generates a Covercrypt encapsulation of a random `SEED_LENGTH`-byte key for
/// the coordinate in the encryption set.
///
/// Returns both the key and its encapsulation.
///
/// # Error
///
/// Returns an error in case the public key is missing for some coordinate or both classic and
/// hybridized coordinate keys are targeted.
pub fn encaps(
    rng: &mut impl CryptoRngCore,
    mpk: &MasterPublicKey,
    encryption_set: &HashSet<Right>,
) -> Result<(Secret<SHARED_SECRET_LENGTH>, XEnc), Error> {
    let coordinate_keys = mpk.select_subkeys(encryption_set)?;

    let S = Secret::<SHARED_SECRET_LENGTH>::random(rng);
    let r = g_hash(&S)?;
    let c = mpk.set_traps(&r);

    let mut coordinate_encapsulations = coordinate_keys
        .into_iter()
        .map(|subkey| -> Result<Encapsulation, _> {
            match subkey {
                RightPublicKey::Hybridized { H, ek } => {
                    let mut K1 = h_hash(R25519::session_key(&r, H)?);
                    let (K2, E) = MlKem512::enc(ek, rng)?;
                    let F = xor_3(&S, &K1, &K2);
                    K1.zeroize();
                    Ok(Encapsulation::Hybridized { E, F })
                }
                RightPublicKey::Classic { H } => {
                    let K1 = h_hash(R25519::session_key(&r, H)?);
                    let F = xor_2(&S, &K1);
                    Ok(Encapsulation::Classic { F })
                }
            }
        })
        .collect::<Result<Vec<_>, Error>>()?;

    shuffle(&mut coordinate_encapsulations, rng);

    let (tag, ss) = j_hash(&S, &c, &coordinate_encapsulations)?;

    Ok((
        ss,
        XEnc {
            tag,
            c,
            encapsulations: coordinate_encapsulations,
        },
    ))
}

/// Attempts opening the Covercrypt encapsulation using the given USK. Returns
/// the encapsulated key upon success, otherwise returns `None`.
pub fn decaps(
    usk: &UserSecretKey,
    encapsulation: &XEnc,
) -> Result<Option<Secret<SHARED_SECRET_LENGTH>>, Error> {
    // A = ⊙ _i (α_i. c_i)
    let A = usk
        .id
        .iter()
        .zip(encapsulation.c.iter())
        .map(|(marker, trap)| trap * marker)
        .fold(EcPoint::identity(), |mut acc, elt| {
            acc = &acc + &elt;
            acc
        });

    for enc in &encapsulation.encapsulations {
        // The breadth-first search tries all coordinate subkeys in a chronological order.
        for key in usk.secrets.bfs() {
            let S = S(key, enc, A.clone());
            if S.is_some() {
                let unwrap_S = S.unwrap();
                let (tag, ss) = j_hash(&unwrap_S, &encapsulation.c, &encapsulation.encapsulations)?;

                if tag == encapsulation.tag {
                    return Ok(Some(ss));
                }
            }
        }
    }
    Ok(None)
}

/// Updates the MSK such that it has at least one secret per right given, and no secret for rights
/// that are not given. Updates hybridization of the remaining secrets when required.
pub fn update_msk(
    rng: &mut impl CryptoRngCore,
    msk: &mut MasterSecretKey,
    rights: HashMap<Right, (EncryptionHint, AttributeStatus)>,
) -> Result<(), Error> {
    let mut secrets = take(&mut msk.secrets);
    secrets.retain(|r| rights.contains_key(r));

    for (r, (hint, status)) in rights {
        if let Some((is_activated, coordinate_secret)) = secrets.get_latest_mut(&r) {
            *is_activated = AttributeStatus::EncryptDecrypt == status;
            if EncryptionHint::Classic == hint {
                *coordinate_secret = coordinate_secret.drop_hybridization();
            }
        } else {
            if AttributeStatus::DecryptOnly == status {
                return Err(Error::OperationNotPermitted(
                    "cannot add decrypt only secret".to_string(),
                ));
            }
            let secret = RightSecretKey::random(rng, EncryptionHint::Hybridized == hint)?;
            secrets.insert(r, (true, secret));
        }
    }
    msk.secrets = secrets;
    Ok(())
}

/// Generates a new secret for each right in the given set that belongs to the MSK.
pub fn rekey(
    rng: &mut impl CryptoRngCore,
    msk: &mut MasterSecretKey,
    rights: HashSet<Right>,
) -> Result<(), Error> {
    for r in rights {
        if msk.secrets.contains_key(&r) {
            let is_hybridized = msk
                .secrets
                .get_latest(&r)
                .map(|(_, k)| k.is_hybridized())
                .ok_or_else(|| {
                    Error::OperationNotPermitted(format!("no current key for coordinate {r:#?}"))
                })?;

            msk.secrets
                .insert(r, (true, RightSecretKey::random(rng, is_hybridized)?));
        } else {
            return Err(Error::OperationNotPermitted(
                "cannot re-key a right not belonging to the MSK".to_string(),
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
pub fn prune(msk: &mut MasterSecretKey, coordinates: &HashSet<Right>) {
    for coordinate in coordinates {
        msk.secrets.keep(coordinate, 1);
    }
}

/// Refreshes the USK relatively to the given MSK.
///
/// For each coordinate in the USK:
/// - if `keep_old_rights` is set to false, the last secret from MSK is given to
///   the USK, all secrets previously owned by the USK are removed;
/// - otherwise, secrets from the USK that do not belong to the MSK are removed,
///   and secrets from the MSK that do not belong to the USK are added.
pub fn refresh(
    rng: &mut impl CryptoRngCore,
    msk: &mut MasterSecretKey,
    usk: &mut UserSecretKey,
    keep_old_rights: bool,
) -> Result<(), Error> {
    verify(msk, usk)?;

    let usk_id = take(&mut usk.id);
    let new_id = msk.tsk.refresh_id(rng, usk_id)?;

    let usk_rights = take(&mut usk.secrets);
    let new_rights = if keep_old_rights {
        refresh_coordinate_keys(msk, usk_rights)
    } else {
        msk.get_latest_right_sk(usk_rights.into_keys())
            .collect::<Result<RevisionVec<Right, RightSecretKey>, Error>>()?
    };

    let signature = sign(msk, &new_id, &new_rights)?;

    usk.id = new_id;
    usk.secrets = new_rights;
    usk.signature = signature;

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
    coordinate_keys: RevisionVec<Right, RightSecretKey>,
) -> RevisionVec<Right, RightSecretKey> {
    coordinate_keys
        .into_iter()
        .filter_map(|(coordinate, user_chain)| {
            msk.secrets.get(&coordinate).and_then(|msk_chain| {
                let mut updated_chain = LinkedList::new();
                let mut msk_secrets = msk_chain.iter();
                let mut usk_secrets = user_chain.into_iter();
                let first_secret = usk_secrets.next()?;

                // Add the most recent secrets from the MSK that do not belong
                // to the USK at the front of the updated chain (cf Invariant.1)
                for (_, msk_secret) in msk_secrets.by_ref() {
                    if msk_secret == &first_secret {
                        break;
                    }
                    updated_chain.push_back(msk_secret.clone());
                }

                // Push the first USK secret since it was consumed from the USK
                // chain iterator.
                updated_chain.push_back(first_secret);

                // Push the secrets already stored in the USK that also belong
                // to the MSK keypairs.
                for coordinate_sk in usk_secrets {
                    if let Some((_, msk_secret)) = msk_secrets.next() {
                        if msk_secret == &coordinate_sk {
                            updated_chain.push_back(msk_secret.clone());
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

/// Attempts opening the Covercrypt encapsulation using the given USK. Returns
/// the encapsulated key and associated rights upon success, otherwise returns `None`.
pub fn full_decaps(
    encapsulation: &XEnc,
    msk: &MasterSecretKey,
) -> Result<Vec<(Right, Secret<SHARED_SECRET_LENGTH>)>, Error> {
    // A = ⊙ _i (α_i. c_i)
    let A: R25519CurvePoint = msk.tsk.s.clone().into();

    let mut rights_list: Vec<(Right, Secret<SHARED_SECRET_LENGTH>)> = Vec::new();

    for enc in &encapsulation.encapsulations {
        for (right, key) in msk.secrets.iter() {
            for k in key {
                let S = S(&k.1, enc, A.clone());
                if S.is_some() {
                    println!("SOME");
                    let unwrap_S = S.unwrap();
                    println!("{:?}", unwrap_S);

                    let (tag, ss) =
                        j_hash(&unwrap_S, &encapsulation.c, &encapsulation.encapsulations)?;
                        println!("SS: {:?}", ss);
                        println!("TAG: {:?}", tag);

                    if tag == encapsulation.tag {
                        rights_list.push((right.clone(), ss));
                    }
                } else {
                    println!("NONE");
                    continue;
                }
            }
        }
    }
    Ok(rights_list)
}

fn S(key: &RightSecretKey, enc: &Encapsulation, A: R25519CurvePoint) -> Option<[u8; 32]> {
    match (key, enc) {
        (RightSecretKey::Hybridized { sk, dk }, Encapsulation::Hybridized { E, F }) => {
            let mut K1 = h_hash(R25519::session_key(&sk, &A).unwrap());
            let K2 = MlKem512::dec(&dk, &E).unwrap();
            let S = xor_3(&F, &K1, &K2);
            K1.zeroize();
            return Some(S);
        }
        (RightSecretKey::Classic { sk }, Encapsulation::Classic { F }) => {
            let K1 = h_hash(R25519::session_key(&sk, &A).unwrap());
            return Some(xor_2(&F, &K1));
        }
        (RightSecretKey::Hybridized { .. }, Encapsulation::Classic { .. })
        | (RightSecretKey::Classic { .. }, Encapsulation::Hybridized { .. }) => return None,
    };
}
