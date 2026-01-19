#![allow(non_snake_case)]

use crate::{
    abe::policy::{AccessStructure, EncryptionHint, EncryptionStatus, Right},
    data_struct::{RevisionMap, RevisionVec},
    providers::{ElGamal, MlKem},
    Error,
};
use cosmian_crypto_core::{
    reexport::{rand_core::CryptoRngCore, zeroize::ZeroizeOnDrop},
    traits::{Sampling, Zero, KEM, NIKE},
    SymmetricKey,
};
use std::{
    collections::{HashMap, HashSet, LinkedList},
    hash::Hash,
};

mod serialization;

#[cfg(test)]
mod tests;

pub mod primitives;

/// The length of the secret encapsulated by Covercrypt.
pub const SHARED_SECRET_LENGTH: usize = 32;

/// The length of the key used to sign user secret keys.
///
/// It is only 16-byte long because no post-quantum security is needed for
/// now. An upgraded signature scheme can still be added later when quantum
/// computers become available.
const SIGNING_KEY_LENGTH: usize = 16;

/// The length of the KMAC signature.
const SIGNATURE_LENGTH: usize = 32;

/// KMAC signature is used to guarantee the integrity of the user secret keys.
type KmacSignature = [u8; SIGNATURE_LENGTH];

/// Length of the Covercrypt early abort tag. 128 bits are enough since we only want collision
/// resistance.
const TAG_LENGTH: usize = 16;

/// Covercrypt early abort tag is used during the decapsulation to verify the
/// integrity of the result.
type Tag = [u8; TAG_LENGTH];

/// Number of colluding users needed to escape tracing.
pub const MIN_TRACING_LEVEL: usize = 1;

/// The Covercrypt subkeys hold the DH secret key associated to a right.
///
/// Subkeys can be hybridized in which case they also hold a PQ-KEM secret key,
/// or post-quantum in which case they only hold a PQ-KEM secret key.
#[derive(Clone, Debug, PartialEq)]
enum RightSecretKey {
    PreQuantum {
        sk: <ElGamal as NIKE>::SecretKey,
    },
    PostQuantum {
        dk: <MlKem as KEM<{ MlKem::KEY_LENGTH }>>::DecapsulationKey,
    },
    Hybridized {
        sk: <ElGamal as NIKE>::SecretKey,
        dk: <MlKem as KEM<{ MlKem::KEY_LENGTH }>>::DecapsulationKey,
    },
}

impl RightSecretKey {
    /// Generates a new random right secret key cryptographically bound to the Covercrypt binding
    /// point `h`.
    fn random(rng: &mut impl CryptoRngCore, security_mode: EncryptionHint) -> Result<Self, Error> {
        match security_mode {
            EncryptionHint::PreQuantum => {
                let sk = <ElGamal as NIKE>::SecretKey::random(rng);
                Ok(Self::PreQuantum { sk })
            }
            EncryptionHint::PostQuantum => {
                let (dk, _) = MlKem::keygen(rng)?;
                Ok(Self::PostQuantum { dk })
            }
            EncryptionHint::Hybridized => {
                let sk = <ElGamal as NIKE>::SecretKey::random(rng);
                let (dk, _) = MlKem::keygen(rng)?;
                Ok(Self::Hybridized { sk, dk })
            }
        }
    }

    /// Generates the associated right public key.
    #[must_use]
    fn cpk(&self, h: &<ElGamal as NIKE>::PublicKey) -> RightPublicKey {
        match self {
            Self::Hybridized { sk, dk } => RightPublicKey::Hybridized {
                H: h * sk,
                ek: dk.ek(),
            },
            Self::PostQuantum { dk } => RightPublicKey::PostQuantum { ek: dk.ek() },
            Self::PreQuantum { sk } => RightPublicKey::PreQuantum { H: h * sk },
        }
    }

    /// Returns the security mode of this right secret key.
    fn security_mode(&self) -> EncryptionHint {
        match self {
            Self::Hybridized { .. } => EncryptionHint::Hybridized,
            Self::PostQuantum { .. } => EncryptionHint::PostQuantum,
            Self::PreQuantum { .. } => EncryptionHint::PreQuantum,
        }
    }

    /// Sets the security mode of this right secret key.
    fn set_security_mode(
        self,
        security_mode: EncryptionHint,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, Error> {
        Ok(match (self, security_mode) {
            (Self::Hybridized { sk, .. }, EncryptionHint::PreQuantum) => Self::PreQuantum { sk },
            (Self::Hybridized { dk, .. }, EncryptionHint::PostQuantum) => Self::PostQuantum { dk },
            (Self::Hybridized { sk, dk }, EncryptionHint::Hybridized) => {
                Self::Hybridized { sk, dk }
            }
            (Self::PostQuantum { .. }, EncryptionHint::PreQuantum) => Self::PostQuantum {
                dk: <MlKem as KEM<{ MlKem::KEY_LENGTH }>>::keygen(rng)?.0,
            },
            (Self::PostQuantum { dk }, EncryptionHint::PostQuantum) => Self::PostQuantum { dk },
            (Self::PostQuantum { dk }, EncryptionHint::Hybridized) => Self::Hybridized {
                sk: <ElGamal as NIKE>::keygen(rng)?.0,
                dk,
            },
            (Self::PreQuantum { sk }, EncryptionHint::PreQuantum) => Self::PreQuantum { sk },
            (Self::PreQuantum { .. }, EncryptionHint::PostQuantum) => Self::PostQuantum {
                dk: <MlKem as KEM<{ MlKem::KEY_LENGTH }>>::keygen(rng)?.0,
            },
            (Self::PreQuantum { sk }, EncryptionHint::Hybridized) => Self::Hybridized {
                sk,
                dk: <MlKem as KEM<{ MlKem::KEY_LENGTH }>>::keygen(rng)?.0,
            },
        })
    }
}

/// The Covercrypt public keys hold the DH secret public key associated to a
/// right.
///
/// Subkeys can be hybridized in which case they also hold a PQ-KEM public key,
/// or post-quantum, in which case they only hold a PQ-KEM public key.
#[derive(Clone, Debug, PartialEq)]
enum RightPublicKey {
    PreQuantum {
        H: <ElGamal as NIKE>::PublicKey,
    },
    PostQuantum {
        ek: <MlKem as KEM<{ MlKem::KEY_LENGTH }>>::EncapsulationKey,
    },
    Hybridized {
        H: <ElGamal as NIKE>::PublicKey,
        ek: <MlKem as KEM<{ MlKem::KEY_LENGTH }>>::EncapsulationKey,
    },
}

impl RightPublicKey {
    /// Returns the security mode of this right public key.
    pub fn security_mode(&self) -> EncryptionHint {
        match self {
            Self::Hybridized { .. } => EncryptionHint::Hybridized,
            Self::PostQuantum { .. } => EncryptionHint::PostQuantum,
            Self::PreQuantum { .. } => EncryptionHint::PreQuantum,
        }
    }
}

/// Covercrypt user IDs are used to make user keys unique and traceable.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
struct UserId(LinkedList<<ElGamal as NIKE>::SecretKey>);

impl UserId {
    /// Returns the tracing level of the USK.
    fn tracing_level(&self) -> usize {
        self.0.len() - 1
    }

    fn iter(&self) -> impl Iterator<Item = &<ElGamal as NIKE>::SecretKey> {
        self.0.iter()
    }
}

/// Covercrypt tracing secret key.
///
/// It allows creating tracing encapsulations. Such encapsulations can only be
/// opened by a specific USK or combination of USKs (which IDs are known). The
/// number of tracers in the key defines the tracing level. Any key generated by
/// a number of users strictly lower than this level can be traced.
///
/// For example, if the tracing level is two, any collusion of up to two users
/// can be traced.
///
/// It is composed of:
/// - a generator
/// - the tracers;
/// - the set of known user IDs.
#[derive(Debug, PartialEq, Eq)]
struct TracingSecretKey {
    s: <ElGamal as NIKE>::SecretKey,
    tracers: LinkedList<(<ElGamal as NIKE>::SecretKey, <ElGamal as NIKE>::PublicKey)>,
    users: HashSet<UserId>,
}

impl TracingSecretKey {
    fn new_with_level(level: usize, rng: &mut impl CryptoRngCore) -> Result<Self, Error> {
        let s = <ElGamal as NIKE>::SecretKey::random(rng);
        let tracers = (0..=level)
            .map(|_| <ElGamal as NIKE>::keygen(rng))
            .collect::<Result<_, _>>()?;
        let users = HashSet::new();

        Ok(Self { s, tracers, users })
    }

    /// Returns the current tracing level.
    fn tracing_level(&self) -> usize {
        self.tracers.len() - 1
    }

    /// Generates a new tracer. Returns the associated trap.
    fn _increase_tracing(&mut self, rng: &mut impl CryptoRngCore) -> Result<(), Error> {
        self.tracers.push_back(<ElGamal as NIKE>::keygen(rng)?);
        Ok(())
    }

    /// Drops the oldest tracer and returns it.
    fn _decrease_tracing(
        &mut self,
    ) -> Result<(<ElGamal as NIKE>::SecretKey, <ElGamal as NIKE>::PublicKey), Error> {
        if self.tracing_level() == MIN_TRACING_LEVEL {
            Err(Error::OperationNotPermitted(format!(
                "tracing level cannot be lower than {MIN_TRACING_LEVEL}"
            )))
        } else {
            Ok(self
                .tracers
                .pop_front()
                .expect("previous check ensures the queue is never empty"))
        }
    }

    /// Set the level of the tracing secret key to the target level.
    pub fn _set_tracing_level(
        &mut self,
        rng: &mut impl CryptoRngCore,
        target_level: usize,
    ) -> Result<(), Error> {
        if target_level < self.tracing_level() {
            for _ in target_level..self.tracing_level() {
                self._decrease_tracing()?;
            }
        } else {
            for _ in self.tracing_level()..target_level {
                self._increase_tracing(rng)?;
            }
        }
        Ok(())
    }

    /// Returns true if the given user ID is known.
    fn is_known(&self, id: &UserId) -> bool {
        self.users.contains(id)
    }

    /// Adds the given user ID to the list of known users.
    fn add_user(&mut self, id: UserId) {
        self.users.insert(id);
    }

    /// Removes the given user ID from the list of known users.
    ///
    /// Returns true if the user was in the list.
    fn del_user(&mut self, id: &UserId) -> bool {
        self.users.remove(id)
    }

    /// Generates the associated tracing public key.
    #[must_use]
    fn tpk(&self) -> TracingPublicKey {
        TracingPublicKey(self.tracers.iter().map(|(_, Pi)| Pi).cloned().collect())
    }

    /// Returns the binding points.
    fn binding_point(&self) -> <ElGamal as NIKE>::PublicKey {
        (&self.s).into()
    }

    /// Generates a new ID and adds it to the list of known user IDs.
    fn generate_user_id(&mut self, rng: &mut impl CryptoRngCore) -> Result<UserId, Error> {
        if let Some((last_tracer, _)) = self.tracers.back() {
            // Generate all but the last marker at random.
            let mut markers = self
                .tracers
                .iter()
                .take(self.tracers.len() - 1)
                .map(|_| <ElGamal as NIKE>::SecretKey::random(rng))
                .collect::<LinkedList<_>>();

            let last_marker = ((&self.s
                - &self
                    .tracers
                    .iter()
                    .zip(markers.iter())
                    .map(|((sk_i, _), a_i)| sk_i * a_i)
                    .fold(<ElGamal as NIKE>::SecretKey::zero(), |acc, x_i| acc + x_i))
                / last_tracer)?;

            markers.push_back(last_marker);
            let id = UserId(markers);
            self.add_user(id.clone());
            Ok(id)
        } else {
            Err(Error::KeyError("MSK has no tracer".to_string()))
        }
    }

    /// Returns true if the given user ID is valid.
    fn _validate_user_id(&self, id: &UserId) -> bool {
        self.s
            == id
                .iter()
                .zip(self.tracers.iter())
                .map(|(identifier, (tracer, _))| identifier * tracer)
                .sum()
    }

    /// If the tracing level of the user ID is not in sync with the one of the
    /// MSK, generate a new ID with the correct tracing level and replace the
    /// old ID by the new one in the MSK.
    ///
    /// # Error
    ///
    /// Returns an error if the ID is unknown.
    fn refresh_id(&mut self, rng: &mut impl CryptoRngCore, id: UserId) -> Result<UserId, Error> {
        if !self.is_known(&id) {
            Err(Error::Tracing("unknown user".to_string()))
        } else if id.tracing_level() != self.tracing_level() {
            let new_id = self.generate_user_id(rng)?;
            self.add_user(new_id.clone());
            self.del_user(&id);
            Ok(new_id)
        } else {
            // Since the integrity of the USK is checked, there is no need to
            // validated the ID before returning it. This saves O(tracing-level)
            // multiplications... but there is actually no way to locally check
            // the caller actually checked the integrity first.
            Ok(id)
        }
    }
}

/// Covercrypt tracing public key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct TracingPublicKey(LinkedList<<ElGamal as NIKE>::PublicKey>);

impl TracingPublicKey {
    /// Returns the tracing level tracing of this key.
    fn tracing_level(&self) -> usize {
        self.0.len() - 1
    }
}

/// The Covercrypt Master Secret Key (MSK).
///
/// It is composed of:
/// - the scalar `s` used to bind tracing and right secrets;
/// - the tracing secret key used to produce challenges to trace user keys;
/// - the secret associated to the each right in Omega;
/// - an optional key for symmetric USK-signing;
/// - the access structure.
#[derive(Debug, PartialEq)]
pub struct MasterSecretKey {
    tsk: TracingSecretKey,
    secrets: RevisionMap<Right, (EncryptionStatus, RightSecretKey)>,
    signing_key: Option<SymmetricKey<SIGNING_KEY_LENGTH>>,
    pub access_structure: AccessStructure,
}

// All secret keys are zeroized on drop.
impl ZeroizeOnDrop for MasterSecretKey {}

impl MasterSecretKey {
    /// Returns the most recent secret key associated to each given right.
    ///
    /// # Error
    ///
    /// Returns an error if some right is missing from the MSK.
    fn get_latest_right_sk<'a>(
        &'a self,
        rs: impl Iterator<Item = Right> + 'a,
    ) -> impl Iterator<Item = Result<(Right, RightSecretKey), Error>> + 'a {
        rs.map(|r| {
            self.secrets
                .get_latest(&r)
                .ok_or(Error::KeyError(format!("MSK has no key for right {r:?}")))
                .cloned()
                .map(|(_, key)| (r, key))
        })
    }

    fn tracing_points(&self) -> impl IntoIterator<Item = &<ElGamal as NIKE>::PublicKey> {
        self.tsk.tracers.iter().map(|(_, P)| P)
    }

    /// Generates a new MPK holding the latest public information of each right in Omega.
    pub fn mpk(&self) -> Result<MasterPublicKey, Error> {
        let h = self.tsk.binding_point();
        Ok(MasterPublicKey {
            tpk: self.tsk.tpk(),
            encryption_keys: self
                .secrets
                .iter()
                .filter_map(|(r, secrets)| {
                    secrets.front().and_then(|(status, csk)| {
                        if &EncryptionStatus::EncryptDecrypt == status {
                            Some((r.clone(), csk.cpk(&h)))
                        } else {
                            None
                        }
                    })
                })
                .collect(),
            access_structure: self.access_structure.clone(),
        })
    }
}

/// Covercrypt Public Key (PK).
///
/// It is composed of:
/// - the tracing public key;
/// - the public keys for each right in Omega;
/// - the access structure.
#[derive(Debug, PartialEq, Clone)]
pub struct MasterPublicKey {
    tpk: TracingPublicKey,
    encryption_keys: HashMap<Right, RightPublicKey>,
    pub access_structure: AccessStructure,
}

impl MasterPublicKey {
    /// Returns the tracing level of this MPK.
    pub fn tracing_level(&self) -> usize {
        self.tpk.tracing_level()
    }

    /// Generates traps for the given scalar.
    // TODO: find a better concept.
    fn set_traps(&self, r: &<ElGamal as NIKE>::SecretKey) -> Vec<<ElGamal as NIKE>::PublicKey> {
        self.tpk.0.iter().map(|Pi| Pi * r).collect()
    }

    /// Returns the subkeys associated with the given rights in this public key,
    /// alongside a boolean value that is true if all of them are hybridized.
    ///
    /// # Error
    ///
    /// Returns an error in case a key is missing for one of the target rights
    /// or these rights do not define an homogeneous set of keys.
    fn select_subkeys(
        &self,
        targets: &HashSet<Right>,
    ) -> Result<(EncryptionHint, Vec<&RightPublicKey>), Error> {
        let subkeys = targets
            .iter()
            .map(|r| {
                self.encryption_keys
                    .get(r)
                    .ok_or_else(|| Error::KeyError(format!("no public key for right '{r:#?}'")))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let (security_mode, is_homogeneous) = subkeys
            .iter()
            .map(|k| (k.security_mode(), true))
            .reduce(|(lhs_mode, lhs_bool), (rhs_mode, rhs_bool)| {
                if lhs_mode == rhs_mode {
                    (lhs_mode, lhs_bool && rhs_bool)
                } else {
                    (lhs_mode, false)
                }
            })
            .ok_or_else(|| {
                Error::OperationNotPermitted("target set cannot be empty".to_string())
            })?;

        if is_homogeneous {
            Ok((security_mode, subkeys))
        } else {
            Err(Error::OperationNotPermitted(
                "cannot select subkeys with different security modes".to_string(),
            ))
        }
    }
}

/// Covercrypt User Secret Key (USK).
///
/// It is composed of:
/// - a user ID (pair of scalars);
/// - the keys of the rights derived from the user decryption policy;
/// - a signature from the MSK that guarantees its integrity.
#[derive(Clone, Debug, PartialEq)]
pub struct UserSecretKey {
    id: UserId,
    ps: Vec<<ElGamal as NIKE>::PublicKey>,
    secrets: RevisionVec<Right, RightSecretKey>,
    signature: Option<KmacSignature>,
}

// All secret keys are zeroized on drop.
impl ZeroizeOnDrop for UserSecretKey {}

impl UserSecretKey {
    /// Returns the tracing level of this user secret key.
    pub fn tracing_level(&self) -> usize {
        self.id.tracing_level()
    }

    #[cfg(feature = "test-utils")]
    pub fn count(&self) -> usize {
        self.secrets.len()
    }

    fn tracing_points(&self) -> &[<ElGamal as NIKE>::PublicKey] {
        &self.ps
    }
}

/// Covercrypt encapsulation.
///
/// It is created for a subset of rights from Omega.
///
/// It is composed of:
/// - the early abort tag;
/// - the traps used to select users that can open this encapsulation;
/// - the right encapsulations.
#[derive(Debug, Clone, PartialEq)]
pub enum XEnc {
    PreQuantum {
        tag: Tag,
        c: Vec<<ElGamal as NIKE>::PublicKey>,
        encapsulations: Vec<[u8; SHARED_SECRET_LENGTH]>,
    },
    PostQuantum {
        tag: Tag,
        encapsulations: Vec<(
            <MlKem as KEM<{ MlKem::KEY_LENGTH }>>::Encapsulation,
            [u8; SHARED_SECRET_LENGTH],
        )>,
    },
    Hybridized {
        tag: Tag,
        c: Vec<<ElGamal as NIKE>::PublicKey>,
        encapsulations: Vec<(
            <MlKem as KEM<{ MlKem::KEY_LENGTH }>>::Encapsulation,
            [u8; SHARED_SECRET_LENGTH],
        )>,
    },
}

impl XEnc {
    /// Returns the tracing level of this encapsulation.
    pub fn tracing_level(&self) -> usize {
        match self {
            Self::PreQuantum { c, .. } => c.len() - 1,
            Self::PostQuantum { .. } => 0,
            Self::Hybridized { c, .. } => c.len() - 1,
        }
    }

    pub fn count(&self) -> usize {
        match self {
            Self::Hybridized { encapsulations, .. } => encapsulations.len(),
            Self::PostQuantum { encapsulations, .. } => encapsulations.len(),
            Self::PreQuantum { encapsulations, .. } => encapsulations.len(),
        }
    }

    pub fn security_mode(&self) -> EncryptionHint {
        match self {
            Self::Hybridized { .. } => EncryptionHint::Hybridized,
            Self::PostQuantum { .. } => EncryptionHint::PostQuantum,
            Self::PreQuantum { .. } => EncryptionHint::PreQuantum,
        }
    }
}
