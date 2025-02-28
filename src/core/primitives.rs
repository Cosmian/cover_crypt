use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet, LinkedList},
    mem::take,
};

use cosmian_crypto_core::{
    bytes_ser_de::Serializable,
    reexport::rand_core::{CryptoRngCore, RngCore},
    RandomFixedSizeCBytes, Secret, SymmetricKey,
};

use tiny_keccak::{Hasher, Kmac, Sha3};
use zeroize::Zeroize;

use crate::{
    abe_policy::{AccessStructure, AttributeStatus, EncryptionHint, Right},
    core::{
        kem::{self, MlKem},
        Encapsulations, KmacSignature, MasterPublicKey, MasterSecretKey, RightPublicKey,
        RightSecretKey, TracingSecretKey, UserId, UserSecretKey, XEnc, MIN_TRACING_LEVEL,
        SHARED_SECRET_LENGTH, SIGNATURE_LENGTH, SIGNING_KEY_LENGTH, TAG_LENGTH,
    },
    data_struct::{RevisionMap, RevisionVec},
    traits::{Kem, Nike, Sampling},
    Error,
};

use super::nike::ElGamal;

fn xor_2<const LENGTH: usize>(lhs: &[u8; LENGTH], rhs: &[u8; LENGTH]) -> [u8; LENGTH] {
    let mut out = [0; LENGTH];
    for pos in 0..LENGTH {
        out[pos] = lhs[pos] ^ rhs[pos];
    }
    out
}

fn xor_in_place<const LENGTH: usize>(
    mut lhs: Secret<LENGTH>,
    rhs: &[u8; LENGTH],
) -> Secret<LENGTH> {
    for pos in 0..LENGTH {
        lhs[pos] ^= rhs[pos];
    }
    lhs
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
            kmac.update(&marker.serialize()?)
        }
        // Subkeys ordering needs to be deterministic to allow deterministic
        // signatures. This explains why a hash-map is not used in USK.
        for (coordinate, keys) in keys.iter() {
            kmac.update(coordinate);
            for subkey in keys.iter() {
                match subkey {
                    RightSecretKey::Hybridized { sk: s_i, dk: dk_i } => {
                        kmac.update(&s_i.serialize()?);
                        kmac.update(&dk_i.serialize()?);
                    }
                    RightSecretKey::Classic { sk: s_i } => {
                        kmac.update(&s_i.serialize()?);
                    }
                }
            }
        }
        let mut res = [0; SIGNATURE_LENGTH];
        kmac.finalize(&mut res);
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

fn G_hash(seed: &Secret<SHARED_SECRET_LENGTH>) -> Result<<ElGamal as Nike>::SecretKey, Error> {
    Ok(<<ElGamal as Nike>::SecretKey as Sampling>::hash(&**seed))
}

fn H_hash(
    K1: &<ElGamal as Nike>::PublicKey,
    K2: Option<&Secret<SHARED_SECRET_LENGTH>>,
    T: &Secret<SHARED_SECRET_LENGTH>,
) -> Result<Secret<SHARED_SECRET_LENGTH>, Error> {
    let mut hasher = Sha3::v256();
    // SHARED_SECRET_LENGTH = 32 = 256 / 8
    let mut H = Secret::<SHARED_SECRET_LENGTH>::new();
    hasher.update(&K1.serialize()?);
    if let Some(K2) = K2 {
        hasher.update(&**K2);
    }
    hasher.update(&**T);
    hasher.finalize(&mut *H);
    Ok(H)
}

fn J_hash(
    S: &Secret<SHARED_SECRET_LENGTH>,
    U: &Secret<SHARED_SECRET_LENGTH>,
) -> ([u8; TAG_LENGTH], Secret<SHARED_SECRET_LENGTH>) {
    let mut hasher = Sha3::v384();
    let mut bytes = [0; 384 / 8];
    hasher.update(&**S);
    hasher.update(&**U);
    hasher.finalize(&mut bytes);

    let mut tag = [0; TAG_LENGTH];
    let mut seed = Secret::<SHARED_SECRET_LENGTH>::default();
    tag.copy_from_slice(&bytes[..TAG_LENGTH]);
    seed.copy_from_slice(&bytes[TAG_LENGTH..]);
    (tag, seed)
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
        ps: msk.tsk.tracers.iter().map(|(_, Pi)| Pi).cloned().collect(),
        secrets: coordinate_keys,
        signature,
    })
}

/// Generates a hybridized encapsulation of the given secret S with the given
/// marker c, ElGamal random r and subkeys.
fn h_encaps(
    S: Secret<SHARED_SECRET_LENGTH>,
    c: Vec<<ElGamal as Nike>::PublicKey>,
    r: <ElGamal as Nike>::SecretKey,
    subkeys: &[&RightPublicKey],
    rng: &mut impl CryptoRngCore,
) -> Result<(Secret<SHARED_SECRET_LENGTH>, XEnc), Error> {
    let encs = subkeys
        .iter()
        .map(|subkey| match subkey {
            RightPublicKey::Hybridized { H, ek } => {
                let K1 = ElGamal::session_key(&r, H)?;
                let (K2, E) = MlKem::enc(ek, rng)?;
                Ok((K1, K2, E))
            }
            RightPublicKey::Classic { .. } => {
                Err(Error::Kem("all subkeys should be hybridized".to_string()))
            }
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let T = {
        let mut hasher = Sha3::v256();
        let mut T = Secret::<SHARED_SECRET_LENGTH>::new();
        c.iter().try_for_each(|ck| {
            hasher.update(&ck.serialize()?);
            Ok::<_, Error>(())
        })?;
        encs.iter().try_for_each(|(_, _, E)| {
            hasher.update(&E.serialize()?);
            Ok::<_, Error>(())
        })?;
        hasher.finalize(&mut *T);
        T
    };

    let encs = encs
        .into_iter()
        .map(|(mut K1, K2, E)| -> Result<_, _> {
            let F = xor_2(&S, &*H_hash(&K1, Some(&K2), &T)?);
            K1.zeroize();
            Ok((E, F))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let U = {
        let mut U = Secret::<SHARED_SECRET_LENGTH>::new();
        let mut hasher = Sha3::v256();
        hasher.update(&*T);
        encs.iter().for_each(|(_, F)| hasher.update(F));
        hasher.finalize(&mut *U);
        U
    };

    let (tag, ss) = J_hash(&S, &U);

    Ok((
        ss,
        XEnc {
            tag,
            c,
            encapsulations: Encapsulations::HEncs(encs),
        },
    ))
}

/// Generates a classic encapsulation of the given secret S with the given
/// marker c, ElGamal random r and subkeys.
fn c_encaps(
    S: Secret<SHARED_SECRET_LENGTH>,
    c: Vec<<ElGamal as Nike>::PublicKey>,
    r: <ElGamal as Nike>::SecretKey,
    subkeys: Vec<&RightPublicKey>,
) -> Result<(Secret<SHARED_SECRET_LENGTH>, XEnc), Error> {
    // In classic mode, T is only updated with c.
    let T = {
        let mut hasher = Sha3::v256();
        let mut T = Secret::<SHARED_SECRET_LENGTH>::new();
        c.iter().try_for_each(|ck| {
            hasher.update(&ck.serialize()?);
            Ok::<_, Error>(())
        })?;
        hasher.finalize(&mut *T);
        T
    };

    let encs = subkeys
        .into_iter()
        .map(|subkey| -> Result<_, _> {
            let H = match subkey {
                RightPublicKey::Hybridized { H, .. } => H,
                RightPublicKey::Classic { H } => H,
            };
            let K1 = ElGamal::session_key(&r, H)?;
            let F = xor_2(&S, &*H_hash(&K1, None, &T)?);
            Ok(F)
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let U = {
        let mut U = Secret::<SHARED_SECRET_LENGTH>::new();
        let mut hasher = Sha3::v256();
        hasher.update(&*T);
        encs.iter().for_each(|F| hasher.update(F));
        hasher.finalize(&mut *U);
        U
    };

    let (tag, ss) = J_hash(&S, &U);

    Ok((
        ss,
        XEnc {
            tag,
            c,
            encapsulations: Encapsulations::CEncs(encs),
        },
    ))
}

/// Generates a Covercrypt encapsulation of a random `SHARED_SECRET_LENGTH`-byte
/// session key for the coordinates in the encryption set.
///
/// Returns both the key and its encapsulation.
///
/// # Error
///
/// Returns an error in case the public key is missing for some coordinate or
/// both classic and hybridized coordinate keys are targeted.
pub fn encaps(
    rng: &mut impl CryptoRngCore,
    mpk: &MasterPublicKey,
    encryption_set: &HashSet<Right>,
) -> Result<(Secret<SHARED_SECRET_LENGTH>, XEnc), Error> {
    let (is_hybridized, mut coordinate_keys) = mpk.select_subkeys(encryption_set)?;

    // Shuffling must be performed *before* generating the encapsulations since
    // rights are hashed in-order. If shuffling is performed after generating
    // the encapsulations, there would be no way to know in which order to
    // perform hashing upon decapsulation.
    shuffle(&mut coordinate_keys, rng);

    let S = Secret::<SHARED_SECRET_LENGTH>::random(rng);
    let r = G_hash(&S)?;
    let c = mpk.set_traps(&r);

    if is_hybridized {
        h_encaps(S, c, r, &coordinate_keys, rng)
    } else {
        c_encaps(S, c, r, coordinate_keys)
    }
}

/// Attempts to open the given hybridized encapsulations with this user secret
/// key.
fn h_decaps(
    rng: &mut impl CryptoRngCore,
    usk: &UserSecretKey,
    A: &<ElGamal as Nike>::PublicKey,
    c: &[<ElGamal as Nike>::PublicKey],
    tag: &[u8; TAG_LENGTH],
    encs: &[(
        <kem::MlKem as Kem>::Encapsulation,
        [u8; SHARED_SECRET_LENGTH],
    )],
) -> Result<Option<Secret<SHARED_SECRET_LENGTH>>, Error> {
    let T = {
        let mut hasher = Sha3::v256();
        let mut T = Secret::<SHARED_SECRET_LENGTH>::new();
        c.iter().try_for_each(|ck| {
            hasher.update(&ck.serialize()?);
            Ok::<_, Error>(())
        })?;
        encs.iter().try_for_each(|(E, _)| {
            hasher.update(&E.serialize()?);
            Ok::<_, Error>(())
        })?;
        hasher.finalize(&mut *T);
        T
    };

    let U = {
        let mut U = Secret::<SHARED_SECRET_LENGTH>::new();
        let mut hasher = Sha3::v256();
        hasher.update(&*T);
        encs.iter().for_each(|(_, F)| hasher.update(F));
        hasher.finalize(&mut *U);
        U
    };

    // Shuffle encapsulation to counter timing attacks attempting to determine
    // which right was used to open an encapsulation.
    let mut encs = encs.iter().collect::<Vec<_>>();
    shuffle(&mut encs, rng);

    for (E, F) in encs {
        // The breadth-first search tries all coordinate subkeys in a chronological
        // order.
        for secret in usk.secrets.bfs() {
            if let RightSecretKey::Hybridized { sk, dk } = secret {
                let mut K1 = ElGamal::session_key(sk, A)?;
                let K2 = MlKem::dec(dk, E)?;
                let S_ij = xor_in_place(H_hash(&K1, Some(&K2), &T)?, F);
                let (tag_ij, ss) = J_hash(&S_ij, &U);
                if tag == &tag_ij {
                    // Fujisaki-Okamoto
                    let r = G_hash(&S_ij)?;
                    let c_ij = usk.set_traps(&r);
                    if c == c_ij {
                        K1.zeroize();
                        return Ok(Some(ss));
                    }
                }
            }
        }
    }

    Ok(None)
}

/// Attempts to open the given classic encapsulations with this user secret key.
fn c_decaps(
    rng: &mut impl CryptoRngCore,
    usk: &UserSecretKey,
    A: &<ElGamal as Nike>::PublicKey,
    c: &[<ElGamal as Nike>::PublicKey],
    tag: &[u8; TAG_LENGTH],
    encs: &Vec<[u8; SHARED_SECRET_LENGTH]>,
) -> Result<Option<Secret<SHARED_SECRET_LENGTH>>, Error> {
    let T = {
        let mut hasher = Sha3::v256();
        let mut T = Secret::<SHARED_SECRET_LENGTH>::new();
        c.iter().try_for_each(|ck| {
            hasher.update(&ck.serialize()?);
            Ok::<_, Error>(())
        })?;
        hasher.finalize(&mut *T);
        T
    };

    let U = {
        let mut U = Secret::<SHARED_SECRET_LENGTH>::new();
        let mut hasher = Sha3::v256();
        hasher.update(&*T);
        encs.iter().for_each(|F| hasher.update(F));
        hasher.finalize(&mut *U);
        U
    };

    // Shuffle encapsulation to counter timing attacks attempting to determine
    // which right was used to open an encapsulation.
    let mut encs = encs.iter().collect::<Vec<_>>();
    shuffle(&mut encs, rng);

    for F in encs {
        // The breadth-first search tries all coordinate subkeys in a chronological
        // order.
        for secret in usk.secrets.bfs() {
            let sk = match secret {
                RightSecretKey::Hybridized { sk, .. } => sk,
                RightSecretKey::Classic { sk } => sk,
            };
            let mut K1 = ElGamal::session_key(sk, A)?;
            let S = xor_in_place(H_hash(&K1, None, &T)?, F);
            K1.zeroize();
            let (tag_ij, ss) = J_hash(&S, &U);
            if tag == &tag_ij {
                // Fujisaki-Okamoto
                let r = G_hash(&S)?;
                let c_ij = usk.set_traps(&r);
                if c == c_ij {
                    return Ok(Some(ss));
                }
            }
        }
    }

    Ok(None)
}

/// Attempts opening the Covercrypt encapsulation using the given USK. Returns
/// the encapsulated key upon success, otherwise returns `None`.
pub fn decaps(
    rng: &mut impl CryptoRngCore,
    usk: &UserSecretKey,
    encapsulation: &XEnc,
) -> Result<Option<Secret<SHARED_SECRET_LENGTH>>, Error> {
    // A = ⊙ _i (α_i. c_i)
    let A = usk
        .id
        .iter()
        .zip(encapsulation.c.iter())
        .map(|(marker, trap)| trap * marker)
        .sum();

    match &encapsulation.encapsulations {
        Encapsulations::HEncs(encs) => {
            h_decaps(rng, usk, &A, &encapsulation.c, &encapsulation.tag, encs)
        }
        Encapsulations::CEncs(encs) => {
            c_decaps(rng, usk, &A, &encapsulation.c, &encapsulation.tag, encs)
        }
    }
}

/// Recover the encapsulated shared secret and set of rights used in the
/// encapsulation.
pub fn full_decaps(
    msk: &MasterSecretKey,
    encapsulation: &XEnc,
) -> Result<(Secret<SHARED_SECRET_LENGTH>, HashSet<Right>), Error> {
    let A = {
        let c_0 = encapsulation
            .c
            .first()
            .ok_or_else(|| Error::Kem("invalid encapsulation: C is empty".to_string()))?;
        let t_0 = msk
            .tsk
            .tracers
            .front()
            .map(|(si, _)| si)
            .ok_or_else(|| Error::KeyError("MSK has no tracer".to_string()))?;

        c_0 * &(&msk.tsk.s / t_0)?
    };

    let T = {
        let mut hasher = Sha3::v256();
        let mut T = Secret::<SHARED_SECRET_LENGTH>::new();
        encapsulation.c.iter().try_for_each(|ck| {
            hasher.update(&ck.serialize()?);
            Ok::<_, Error>(())
        })?;

        if let Encapsulations::HEncs(encs) = &encapsulation.encapsulations {
            encs.iter().try_for_each(|(E, _)| {
                hasher.update(&E.serialize()?);
                Ok::<_, Error>(())
            })?;
        }
        hasher.finalize(&mut *T);
        T
    };

    let U = {
        let mut U = Secret::<SHARED_SECRET_LENGTH>::new();
        let mut hasher = Sha3::v256();
        hasher.update(&*T);
        match &encapsulation.encapsulations {
            Encapsulations::HEncs(encs) => encs.iter().for_each(|(_, F)| hasher.update(F)),
            Encapsulations::CEncs(encs) => encs.iter().for_each(|F| hasher.update(F)),
        }
        hasher.finalize(&mut *U);
        U
    };

    let mut enc_ss = None;
    let mut rights = HashSet::with_capacity(encapsulation.count());
    let mut try_decaps = |right: &Right,
                          K1: &mut <ElGamal as Nike>::PublicKey,
                          K2: Option<Secret<SHARED_SECRET_LENGTH>>,
                          F| {
        let S_ij = xor_in_place(H_hash(K1, K2.as_ref(), &T)?, F);
        let (tag_ij, ss) = J_hash(&S_ij, &U);
        if encapsulation.tag == tag_ij {
            // Fujisaki-Okamoto
            let r = G_hash(&S_ij)?;
            let c_ij = msk.tsk.set_traps(&r);
            if encapsulation.c == c_ij {
                K1.zeroize();
                enc_ss = Some(ss);
                rights.insert(right.clone());
            }
        }
        Ok::<_, Error>(())
    };

    match &encapsulation.encapsulations {
        Encapsulations::HEncs(encs) => {
            for (E, F) in encs {
                for (right, secret_set) in msk.secrets.iter() {
                    for (is_activated, secret) in secret_set {
                        if *is_activated {
                            if let RightSecretKey::Hybridized { sk, dk } = secret {
                                let mut K1 = ElGamal::session_key(sk, &A)?;
                                let K2 = MlKem::dec(dk, E)?;
                                try_decaps(right, &mut K1, Some(K2), F)?;
                            }
                        }
                    }
                }
            }
        }
        Encapsulations::CEncs(encs) => {
            for F in encs {
                for (right, secret_set) in msk.secrets.iter() {
                    for (is_activated, secret) in secret_set {
                        if *is_activated {
                            let sk = match secret {
                                RightSecretKey::Hybridized { sk, .. } => sk,
                                RightSecretKey::Classic { sk } => sk,
                            };
                            let mut K1 = ElGamal::session_key(sk, &A)?;
                            try_decaps(right, &mut K1, None, F)?;
                        }
                    }
                }
            }
        }
    }
    enc_ss
        .map(|ss| (ss, rights))
        .ok_or_else(|| Error::Kem("could not open the encapsulation".to_string()))
}

/// Updates the MSK such that it has at least one secret per right given, and no
/// secret for rights that are not given. Updates hybridization of the remaining
/// secrets when required.
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
