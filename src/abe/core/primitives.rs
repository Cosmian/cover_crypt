use crate::{
    abe::{
        core::{
            KmacSignature, MasterPublicKey, MasterSecretKey, RightPublicKey, RightSecretKey,
            TracingSecretKey, UserId, UserSecretKey, XEnc, MIN_TRACING_LEVEL, SHARED_SECRET_LENGTH,
            SIGNATURE_LENGTH, SIGNING_KEY_LENGTH, TAG_LENGTH,
        },
        policy::{AccessStructure, EncryptionHint, EncryptionStatus, Right},
    },
    data_struct::{RevisionMap, RevisionVec},
    providers::{ElGamal, MlKem},
    Error,
};
use cosmian_crypto_core::{
    bytes_ser_de::Serializable,
    reexport::{
        rand_core::{CryptoRngCore, RngCore},
        tiny_keccak::{Hasher, Kmac, Sha3},
    },
    traits::{Seedable, KEM, NIKE},
    RandomFixedSizeCBytes, Secret, SymmetricKey,
};
use std::{
    collections::{HashMap, HashSet, LinkedList},
    mem::take,
};

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
    for i in 0..xs.len() {
        let j = rng.next_u32() as usize % xs.len();
        xs.swap(i, j);
    }
}

/// Computes the signature of the given USK using the MSK.
fn sign(
    msk: &MasterSecretKey,
    id: &UserId,
    keys: &RevisionVec<Right, RightSecretKey>,
) -> Result<Option<KmacSignature>, Error> {
    if let Some(kmac_key) = &msk.signing_key {
        // Subkeys ordering needs to be deterministic to allow deterministic
        // signatures. This explains why a hash-map is not used in USK.
        let mut res = [0; SIGNATURE_LENGTH];
        let mut kmac = Kmac::v256(&**kmac_key, b"USK signature");
        kmac.update(&id.serialize()?);
        kmac.update(&keys.serialize()?);
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

fn G_hash(seed: &Secret<SHARED_SECRET_LENGTH>) -> Result<<ElGamal as NIKE>::SecretKey, Error> {
    Ok(<<ElGamal as NIKE>::SecretKey as Seedable<
        SHARED_SECRET_LENGTH,
    >>::from_seed(seed))
}

fn H_hash(
    K1: Option<&<ElGamal as NIKE>::PublicKey>,
    K2: Option<&SymmetricKey<SHARED_SECRET_LENGTH>>,
    T: &Secret<SHARED_SECRET_LENGTH>,
) -> Result<Secret<SHARED_SECRET_LENGTH>, Error> {
    // Additional check to enforce the constraint on the SHARED_SECRET_LENGTH
    // constant that is defined in another file.
    //
    // NOTE: it would be nice to perform this check at compile-time instead.
    assert_eq!(SHARED_SECRET_LENGTH, 32);

    let mut hasher = Sha3::v256();
    let mut H = Secret::<SHARED_SECRET_LENGTH>::new();
    if let Some(K1) = K1 {
        hasher.update(&K1.serialize()?);
    }
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

fn generate_T<'a>(
    c: Option<&[<ElGamal as NIKE>::PublicKey]>,
    encapsulations: Option<
        impl IntoIterator<Item = &'a <MlKem as KEM<{ MlKem::KEY_LENGTH }>>::Encapsulation>,
    >,
) -> Result<Secret<SHARED_SECRET_LENGTH>, Error> {
    let mut hasher = Sha3::v256();
    let mut T = Secret::new();
    if let Some(c) = c {
        c.iter().try_for_each(|ck| {
            hasher.update(&ck.serialize()?);
            Ok::<_, Error>(())
        })?;
    }
    if let Some(encapsulations) = encapsulations {
        encapsulations.into_iter().try_for_each(|E| {
            hasher.update(&E.serialize()?);
            Ok::<_, Error>(())
        })?;
    }
    hasher.finalize(&mut *T);
    Ok(T)
}

fn generate_U<'a>(
    T: &Secret<SHARED_SECRET_LENGTH>,
    encapsulations: impl IntoIterator<Item = &'a [u8; 32]>,
) -> Secret<SHARED_SECRET_LENGTH> {
    let mut U = Secret::<SHARED_SECRET_LENGTH>::new();
    let mut hasher = Sha3::v256();
    hasher.update(&**T);
    encapsulations.into_iter().for_each(|F| hasher.update(F));
    hasher.finalize(&mut *U);
    U
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
fn h_encaps<'a>(
    S: Secret<SHARED_SECRET_LENGTH>,
    c: Vec<<ElGamal as NIKE>::PublicKey>,
    r: <ElGamal as NIKE>::SecretKey,
    subkeys: impl IntoIterator<
        Item = (
            &'a <ElGamal as NIKE>::PublicKey,
            &'a <MlKem as KEM<{ MlKem::KEY_LENGTH }>>::EncapsulationKey,
        ),
    >,
    rng: &mut impl CryptoRngCore,
) -> Result<(Secret<SHARED_SECRET_LENGTH>, XEnc), Error> {
    let encs = subkeys
        .into_iter()
        .map(|(H, ek)| {
            let K1 = ElGamal::shared_secret(&r, H)?;
            let (K2, E) = MlKem::enc(ek, rng)?;
            Ok((K1, K2, E))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let T = generate_T(Some(&c), Some(encs.iter().map(|(_, _, E)| E)))?;

    let encapsulations = encs
        .into_iter()
        .map(|(K1, K2, E)| -> Result<_, _> {
            let F = xor_2(&S, &*H_hash(Some(&K1), Some(&K2), &T)?);
            Ok((E, F))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let U = generate_U(&T, encapsulations.iter().map(|(_, F)| F));

    let (tag, ss) = J_hash(&S, &U);

    Ok((
        ss,
        XEnc::Hybridized {
            tag,
            c,
            encapsulations,
        },
    ))
}

/// Generates post-quantum encapsulation of the given secret S with the given
/// subkeys.
fn post_quantum_encaps<'a>(
    S: Secret<SHARED_SECRET_LENGTH>,
    subkeys: impl IntoIterator<Item = &'a <MlKem as KEM<{ MlKem::KEY_LENGTH }>>::EncapsulationKey>,
    rng: &mut impl CryptoRngCore,
) -> Result<(Secret<SHARED_SECRET_LENGTH>, XEnc), Error> {
    let encs = subkeys
        .into_iter()
        .map(|ek| MlKem::enc(ek, rng))
        .collect::<Result<Vec<_>, Error>>()?;

    let T = generate_T(None, Some(encs.iter().map(|(_, E)| E)))?;

    let encapsulations = encs
        .into_iter()
        .map(|(K2, E)| -> Result<_, _> {
            let F = xor_2(&S, &*H_hash(None, Some(&K2), &T)?);
            Ok((E, F))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let U = generate_U(&T, encapsulations.iter().map(|(_, F)| F));

    let (tag, ss) = J_hash(&S, &U);

    Ok((
        ss,
        XEnc::PostQuantum {
            tag,
            encapsulations,
        },
    ))
}

/// Generates a pre-quantum encapsulation of the given secret S with the given
/// marker c, ElGamal random r and subkeys.
fn pre_quantum_encaps<'a>(
    S: Secret<SHARED_SECRET_LENGTH>,
    c: Vec<<ElGamal as NIKE>::PublicKey>,
    r: <ElGamal as NIKE>::SecretKey,
    subkeys: impl IntoIterator<Item = &'a <ElGamal as NIKE>::PublicKey>,
) -> Result<(Secret<SHARED_SECRET_LENGTH>, XEnc), Error> {
    let T = generate_T(Some(&c), None::<Vec<_>>)?;

    let encapsulations = subkeys
        .into_iter()
        .map(|H| -> Result<_, _> {
            let K1 = ElGamal::shared_secret(&r, H)?;
            let F = xor_2(&S, &*H_hash(Some(&K1), None, &T)?);
            Ok(F)
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let U = generate_U(&T, &encapsulations);

    let (tag, ss) = J_hash(&S, &U);

    Ok((
        ss,
        XEnc::PreQuantum {
            tag,
            c,
            encapsulations,
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
/// Returns an error in case the public key is missing for some coordinate.
pub fn encaps(
    rng: &mut impl CryptoRngCore,
    mpk: &MasterPublicKey,
    encryption_set: &HashSet<Right>,
) -> Result<(Secret<SHARED_SECRET_LENGTH>, XEnc), Error> {
    // A typed key container would avoid the need for casting in the match arms
    // but would also involve additional overhead.
    let (is_hybridized, mut coordinate_keys) = mpk.select_subkeys(encryption_set)?;

    // Shuffling must be performed *before* generating the final encapsulations
    // in order to have a deterministic digest.
    shuffle(&mut coordinate_keys, rng);

    let S = Secret::random(rng);

    match is_hybridized {
        EncryptionHint::PreQuantum => {
            let r = G_hash(&S)?;
            let c = mpk.set_traps(&r);

            let subkeys = coordinate_keys.into_iter().map(|subkey| {
                if let RightPublicKey::PreQuantum { H } = subkey {
                    H
                } else {
                    panic!("select_subkeys already ensures homogeneity")
                }
            });
            pre_quantum_encaps(S, c, r, subkeys)
        }
        EncryptionHint::PostQuantum => {
            let subkeys = coordinate_keys.into_iter().map(|subkey| {
                if let RightPublicKey::PostQuantum { ek } = subkey {
                    ek
                } else {
                    panic!("select_subkeys already ensures homogeneity")
                }
            });
            post_quantum_encaps(S, subkeys, rng)
        }
        EncryptionHint::Hybridized => {
            let r = G_hash(&S)?;
            let c = mpk.set_traps(&r);

            let subkeys = coordinate_keys.into_iter().map(|subkey| {
                if let RightPublicKey::Hybridized { H, ek } = subkey {
                    (H, ek)
                } else {
                    panic!("select_subkeys already ensures homogeneity")
                }
            });
            h_encaps(S, c, r, subkeys, rng)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn attempt_pre_quantum_decaps<'a>(
    secret: &RightSecretKey,
    A: &<ElGamal as NIKE>::PublicKey,
    U: &Secret<SHARED_SECRET_LENGTH>,
    T: &Secret<SHARED_SECRET_LENGTH>,
    F: &[u8; 32],
    c: &[<ElGamal as NIKE>::PublicKey],
    tag: &[u8; TAG_LENGTH],
    tracing_points: impl IntoIterator<Item = &'a <ElGamal as NIKE>::PublicKey>,
) -> Result<Option<Secret<32>>, Error> {
    if let RightSecretKey::PreQuantum { sk } = secret {
        let K1 = ElGamal::shared_secret(sk, A)?;
        let S = xor_in_place(H_hash(Some(&K1), None, T)?, F);
        let (tag_ij, ss) = J_hash(&S, U);
        if tag == &tag_ij {
            // Fujisaki-Okamoto
            let r = G_hash(&S)?;
            let c_ij = tracing_points
                .into_iter()
                .map(|P| P * &r)
                .collect::<Vec<_>>();
            if c == c_ij {
                return Ok(Some(ss));
            }
        }
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
fn attempt_hybridized_decaps<'a>(
    secret: &RightSecretKey,
    A: &<ElGamal as NIKE>::PublicKey,
    U: &Secret<SHARED_SECRET_LENGTH>,
    T: &Secret<SHARED_SECRET_LENGTH>,
    E: &<MlKem as KEM<{ MlKem::KEY_LENGTH }>>::Encapsulation,
    F: &[u8; 32],
    c: &[<ElGamal as NIKE>::PublicKey],
    tag: &[u8; TAG_LENGTH],
    tracing_points: impl IntoIterator<Item = &'a <ElGamal as NIKE>::PublicKey>,
) -> Result<Option<Secret<32>>, Error> {
    if let RightSecretKey::Hybridized { sk, dk } = secret {
        let K1 = ElGamal::shared_secret(sk, A)?;
        let K2 = MlKem::dec(dk, E)?;
        let S_ij = xor_in_place(H_hash(Some(&K1), Some(&K2), T)?, F);
        let (tag_ij, ss) = J_hash(&S_ij, U);
        if tag == &tag_ij {
            // Fujisaki-Okamoto
            let r = G_hash(&S_ij)?;
            let c_ij = tracing_points
                .into_iter()
                .map(|P| P * &r)
                .collect::<Vec<_>>();
            if c == c_ij {
                return Ok(Some(ss));
            }
        }
    }
    Ok(None)
}

fn attempt_post_quantum_decaps(
    secret: &RightSecretKey,
    U: &Secret<SHARED_SECRET_LENGTH>,
    T: &Secret<SHARED_SECRET_LENGTH>,
    E: &<MlKem as KEM<{ MlKem::KEY_LENGTH }>>::Encapsulation,
    F: &[u8; 32],
    tag: &[u8; TAG_LENGTH],
) -> Result<Option<Secret<32>>, Error> {
    if let RightSecretKey::PostQuantum { dk } = secret {
        let K2 = MlKem::dec(dk, E)?;
        let S_ij = xor_in_place(H_hash(None, Some(&K2), T)?, F);
        let (tag_ij, ss) = J_hash(&S_ij, U);
        if tag == &tag_ij {
            return Ok(Some(ss));
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
    fn generate_tracing_closure(
        usk: &UserSecretKey,
        c: &[<ElGamal as NIKE>::PublicKey],
    ) -> <ElGamal as NIKE>::PublicKey {
        usk.id
            .iter()
            .zip(c.iter())
            .map(|(marker, trap)| trap * marker)
            .sum::<<ElGamal as NIKE>::PublicKey>()
    }

    fn partial_post_quantum_decaps(
        rng: &mut impl CryptoRngCore,
        usk: &UserSecretKey,
        tag: &[u8; TAG_LENGTH],
        encs: &[(
            <MlKem as KEM<{ MlKem::KEY_LENGTH }>>::Encapsulation,
            [u8; SHARED_SECRET_LENGTH],
        )],
    ) -> Result<Option<Secret<SHARED_SECRET_LENGTH>>, Error> {
        let T = generate_T(None, Some(encs.iter().map(|(E, _)| E)))?;
        let U = generate_U(&T, encs.iter().map(|(_, F)| F));

        // Shuffle encapsulation to counter timing attacks attempting to determine
        // which right was used to open an encapsulation.
        let mut encs = encs.iter().collect::<Vec<_>>();
        shuffle(&mut encs, rng);

        // Loop order matters: this ordering is faster.
        for mut revision in usk.secrets.revisions() {
            // Shuffle secrets to counter timing attacks attempting to determine
            // whether successive encapsulations target the same user right.
            shuffle(&mut revision, rng);
            for (E, F) in &encs {
                for (_, secret) in &revision {
                    if let Some(ss) = attempt_post_quantum_decaps(secret, &U, &T, E, F, tag)? {
                        return Ok(Some(ss));
                    }
                }
            }
        }

        Ok(None)
    }

    fn partial_hybridized_decaps(
        rng: &mut impl CryptoRngCore,
        usk: &UserSecretKey,
        c: &[<ElGamal as NIKE>::PublicKey],
        tag: &[u8; TAG_LENGTH],
        encs: &[(
            <MlKem as KEM<{ MlKem::KEY_LENGTH }>>::Encapsulation,
            [u8; SHARED_SECRET_LENGTH],
        )],
    ) -> Result<Option<Secret<SHARED_SECRET_LENGTH>>, Error> {
        let A = generate_tracing_closure(usk, c);
        let T = generate_T(Some(c), Some(encs.iter().map(|(E, _)| E)))?;
        let U = generate_U(&T, encs.iter().map(|(_, F)| F));

        // Shuffle encapsulation to counter timing attacks attempting to determine
        // which right was used to open an encapsulation.
        let mut encs = encs.iter().collect::<Vec<_>>();
        shuffle(&mut encs, rng);

        // Loop order matters: this ordering is faster.
        for mut revision in usk.secrets.revisions() {
            // Shuffle secrets to counter timing attacks attempting to determine
            // whether successive encapsulations target the same user right.
            shuffle(&mut revision, rng);
            for (E, F) in &encs {
                for (_, secret) in &revision {
                    if let Some(ss) = attempt_hybridized_decaps(
                        secret,
                        &A,
                        &U,
                        &T,
                        E,
                        F,
                        c,
                        tag,
                        usk.tracing_points(),
                    )? {
                        return Ok(Some(ss));
                    }
                }
            }
        }

        Ok(None)
    }

    fn partial_pre_quantum_decaps(
        rng: &mut impl CryptoRngCore,
        usk: &UserSecretKey,
        c: &[<ElGamal as NIKE>::PublicKey],
        tag: &[u8; TAG_LENGTH],
        encs: &Vec<[u8; SHARED_SECRET_LENGTH]>,
    ) -> Result<Option<Secret<SHARED_SECRET_LENGTH>>, Error> {
        let A = generate_tracing_closure(usk, c);
        let T = generate_T(Some(c), None::<Vec<_>>)?;
        let U = generate_U(&T, encs);

        // Shuffle encapsulations to counter timing attacks attempting to determine
        // which right was used to open an encapsulation.
        let mut encs = encs.iter().collect::<Vec<_>>();
        shuffle(&mut encs, rng);

        // Loop order matters: this ordering is faster.
        for mut revision in usk.secrets.revisions() {
            // Shuffle secrets to counter timing attacks attempting to determine
            // whether successive encapsulations target the same user right.
            shuffle(&mut revision, rng);
            for F in &encs {
                for (_, secret) in &revision {
                    if let Some(ss) = attempt_pre_quantum_decaps(
                        secret,
                        &A,
                        &U,
                        &T,
                        F,
                        c,
                        tag,
                        usk.tracing_points(),
                    )? {
                        return Ok(Some(ss));
                    }
                }
            }
        }

        Ok(None)
    }

    match encapsulation {
        XEnc::Hybridized {
            tag,
            c,
            encapsulations,
        } => partial_hybridized_decaps(rng, usk, c, tag, encapsulations),
        XEnc::PostQuantum {
            tag,
            encapsulations,
        } => partial_post_quantum_decaps(rng, usk, tag, encapsulations),
        XEnc::PreQuantum {
            tag,
            c,
            encapsulations,
        } => partial_pre_quantum_decaps(rng, usk, c, tag, encapsulations),
    }
}

/// Recover the encapsulated shared secret and set of rights used in the
/// encapsulation.
pub fn master_decaps(
    msk: &MasterSecretKey,
    encapsulation: &XEnc,
    full: bool,
) -> Result<(Secret<SHARED_SECRET_LENGTH>, HashSet<Right>), Error> {
    /// Opens the given encapsulation with the provided secrets. Returns both
    /// the encapsulated secret and the right associated to the first secret
    /// allowing opening this encapsulation, or returns an error if no secret
    /// allow opening this encapsulation.
    fn open(
        secrets: &RevisionMap<Right, (EncryptionStatus, RightSecretKey)>,
        attempt_opening: impl Fn(&RightSecretKey) -> Result<Option<Secret<SHARED_SECRET_LENGTH>>, Error>,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, Right), Error> {
        for (right, secret_set) in secrets.iter() {
            for (_, secret) in secret_set {
                if let Some(ss) = attempt_opening(secret)? {
                    return Ok::<_, Error>((ss, right.clone()));
                }
            }
        }
        Err(Error::Kem("could not open the encapsulation".to_string()))
    }

    fn generate_tracing_closure(
        msk: &MasterSecretKey,
        c: &[<ElGamal as NIKE>::PublicKey],
    ) -> Result<<ElGamal as NIKE>::PublicKey, Error> {
        let c_0 = c
            .first()
            .ok_or_else(|| Error::Kem("invalid encapsulation: C is empty".to_string()))?;
        let t_0 = msk
            .tsk
            .tracers
            .front()
            .map(|(si, _)| si)
            .ok_or_else(|| Error::KeyError("MSK has no tracer".to_string()))?;

        Ok(c_0 * &(&msk.tsk.s / t_0)?)
    }

    fn pre_quantum_decapsulation(
        msk: &MasterSecretKey,
        tag: &[u8; TAG_LENGTH],
        c: &[<ElGamal as NIKE>::PublicKey],
        encapsulations: &[[u8; 32]],
        full: bool,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, HashSet<Right>), Error> {
        let A = generate_tracing_closure(msk, c)?;
        let T = generate_T(Some(c), None::<Vec<_>>)?;
        let U = generate_U(&T, encapsulations);

        // Attempts opening the encapsulation F with this right secret key.
        let attempt_opening = |F, secret: &RightSecretKey| {
            attempt_pre_quantum_decaps(secret, &A, &U, &T, F, c, tag, msk.tracing_points())
        };

        let mut enc_ss = None;
        let mut rights = HashSet::with_capacity(encapsulations.len());
        let mut secrets = msk.secrets.clone();

        for F in encapsulations {
            let (ss, right) = open(&secrets, |secret| attempt_opening(F, secret))?;
            if let Some(enc_ss) = &enc_ss {
                if &ss != enc_ss {
                    return Err(Error::Kem(
                        "malformed encapsulation: different encapsulated secrets found".to_string(),
                    ));
                }
            }
            // Removes this right since well-formed encapsulations use rights
            // only once. This should allow a ~2x speed-up.
            secrets.remove(&right);
            enc_ss = Some(ss);
            rights.insert(right);

            if !full {
                break;
            }
        }

        enc_ss
            .map(|ss| (ss, rights))
            // An empty encapsulation should be the only way to raise this error
            // since the function `open` either errors upon failure to open.
            .ok_or_else(|| Error::Kem("empty encapsulation".to_string()))
    }

    fn post_quantum_decapsulation(
        msk: &MasterSecretKey,
        tag: &[u8; TAG_LENGTH],
        encapsulations: &[(
            <MlKem as KEM<{ MlKem::KEY_LENGTH }>>::Encapsulation,
            [u8; SHARED_SECRET_LENGTH],
        )],
        full: bool,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, HashSet<Right>), Error> {
        let T = generate_T(None, Some(encapsulations.iter().map(|(E, _)| E)))?;
        let U = generate_U(&T, encapsulations.iter().map(|(_, F)| F));

        let attempt_opening =
            |E, F, secret: &RightSecretKey| attempt_post_quantum_decaps(secret, &U, &T, E, F, tag);

        let mut enc_ss = None;
        let mut rights = HashSet::with_capacity(encapsulations.len());
        let mut secrets = msk.secrets.clone();

        for (E, F) in encapsulations {
            let (ss, right) = open(&secrets, |secret| attempt_opening(E, F, secret))?;
            if let Some(enc_ss) = &enc_ss {
                if &ss != enc_ss {
                    return Err(Error::Kem(
                        "malformed encapsulation: different encapsulated secrets found".to_string(),
                    ));
                }
            }
            // Removes this right since well-formed encapsulations use rights
            // only once. This should allow a ~2x speed-up.
            secrets.remove(&right);
            enc_ss = Some(ss);
            rights.insert(right);

            if !full {
                break;
            }
        }

        enc_ss
            .map(|ss| (ss, rights))
            // An empty encapsulation should be the only way to raise this error
            // since the function `open` either errors upon failure to open.
            .ok_or_else(|| Error::Kem("empty encapsulation".to_string()))
    }

    fn hybrid_decapsulation(
        msk: &MasterSecretKey,
        tag: &[u8; TAG_LENGTH],
        c: &[<ElGamal as NIKE>::PublicKey],
        encapsulations: &[(
            <MlKem as KEM<{ MlKem::KEY_LENGTH }>>::Encapsulation,
            [u8; SHARED_SECRET_LENGTH],
        )],
        full: bool,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, HashSet<Right>), Error> {
        let A = generate_tracing_closure(msk, c)?;
        let T = generate_T(Some(c), Some(encapsulations.iter().map(|(E, _)| E)))?;
        let U = generate_U(&T, encapsulations.iter().map(|(_, F)| F));

        let attempt_opening = |E, F, secret: &RightSecretKey| {
            attempt_hybridized_decaps(secret, &A, &U, &T, E, F, c, tag, msk.tracing_points())
        };

        let mut enc_ss = None;
        let mut rights = HashSet::with_capacity(encapsulations.len());
        let mut secrets = msk.secrets.clone();

        for (E, F) in encapsulations {
            let (ss, right) = open(&secrets, |secret| attempt_opening(E, F, secret))?;
            if let Some(enc_ss) = &enc_ss {
                if &ss != enc_ss {
                    return Err(Error::Kem(
                        "malformed encapsulation: different encapsulated secrets found".to_string(),
                    ));
                }
            }
            // Removes this right since well-formed encapsulations use rights
            // only once. This should allow a ~2x speed-up.
            secrets.remove(&right);
            enc_ss = Some(ss);
            rights.insert(right);

            if !full {
                break;
            }
        }

        enc_ss
            .map(|ss| (ss, rights))
            // An empty encapsulation should be the only way to raise this error
            // since the function `open` either errors upon failure to open.
            .ok_or_else(|| Error::Kem("empty encapsulation".to_string()))
    }

    match encapsulation {
        XEnc::PreQuantum {
            tag,
            c,
            encapsulations,
        } => pre_quantum_decapsulation(msk, tag, c, encapsulations, full),
        XEnc::PostQuantum {
            tag,
            encapsulations,
        } => post_quantum_decapsulation(msk, tag, encapsulations, full),
        XEnc::Hybridized {
            tag,
            c,
            encapsulations,
        } => hybrid_decapsulation(msk, tag, c, encapsulations, full),
    }
}

/// Updates the MSK such that it has at least one secret per right given, and no
/// secret for rights that are not given. Updates hybridization of the remaining
/// secrets when required.
pub fn update_msk(
    rng: &mut impl CryptoRngCore,
    msk: &mut MasterSecretKey,
    rights: HashMap<Right, (EncryptionHint, EncryptionStatus)>,
) -> Result<(), Error> {
    let mut secrets = take(&mut msk.secrets);
    secrets.retain(|r| rights.contains_key(r));

    for (r, (mode, status)) in rights {
        if let Some(revisions) = secrets.get_mut(&r) {
            if let Some((_, secret)) = revisions.pop_front() {
                revisions.push_front((status, secret.set_security_mode(mode, rng)?))
            } else {
                return Err(Error::OperationNotPermitted(
                    "empty revision list is illegal".to_string(),
                ));
            }
        } else {
            if EncryptionStatus::DecryptOnly == status {
                return Err(Error::OperationNotPermitted(
                    "cannot add decrypt only secret".to_string(),
                ));
            }
            let secret = RightSecretKey::random(rng, mode)?;
            secrets.insert(r, (status, secret));
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
            let security_mode = msk
                .secrets
                .get_latest(&r)
                .map(|(_, k)| k.security_mode())
                .ok_or_else(|| {
                    Error::OperationNotPermitted(format!("no current key for coordinate {r:#?}"))
                })?;

            msk.secrets.insert(
                r,
                (
                    EncryptionStatus::default(),
                    RightSecretKey::random(rng, security_mode)?,
                ),
            );
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
