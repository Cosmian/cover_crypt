use std::{
    collections::{HashMap, HashSet, LinkedList},
    hash::Hash,
};

use cosmian_crypto_core::{reexport::rand_core::CryptoRngCore, SymmetricKey};

use crate::{
    abe_policy::Coordinate,
    data_struct::{RevisionMap, RevisionVec},
    Error,
};

#[macro_use]
pub mod macros;
pub mod ae;
pub mod api;
mod encrypted_header;
pub mod primitives;
#[cfg(feature = "serialization")]
pub mod serialization;

mod elgamal;
mod postquantum;
#[cfg(test)]
mod tests;

use elgamal::{EcPoint, Scalar};
pub use encrypted_header::{CleartextHeader, EncryptedHeader};

/// The length of the secret encapsulated by Covercrypt.
///
/// They are 32 bytes long to enable reaching 128 bits of post-quantum security
/// when using it with a sensible DEM.
pub const SEED_LENGTH: usize = 32;

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

/// The Covercrypt subkeys hold the DH secret key associated to a coordinate.
/// Subkeys can be hybridized, in which case they also hold a PQ-KEM secret key.
#[derive(Clone, Debug, PartialEq, Eq)]
enum CoordinateSecretKey {
    Hybridized {
        postquantum_sk: postquantum::SecretKey,
        elgamal_sk: Scalar,
    },
    Classic {
        elgamal_sk: Scalar,
    },
}

/// The Covercrypt public keys hold the DH secret public key associated to a coordinate.
/// Subkeys can be hybridized, in which case they also hold a PQ-KEM public key.
#[derive(Clone, Debug, PartialEq, Eq)]
enum CoordinatePublicKey {
    Hybridized {
        postquantum_pk: postquantum::PublicKey,
        elgamal_pk: EcPoint,
    },
    Classic {
        elgamal_pk: EcPoint,
    },
}

impl CoordinatePublicKey {
    pub fn is_hybridized(&self) -> bool {
        match self {
            Self::Hybridized { .. } => true,
            Self::Classic { .. } => false,
        }
    }

    pub fn assert_homogeneity(subkeys: &[&Self]) -> Result<(), Error> {
        let is_homogeneous = subkeys
            .iter()
            .all(|cpk| cpk.is_hybridized() == subkeys[0].is_hybridized());

        if is_homogeneous {
            Ok(())
        } else {
            Err(Error::OperationNotPermitted(
                "classic and hybridized access policies cannot be mixed".to_string(),
            ))
        }
    }
}

/// ElGamal keypair optionally hybridized with a post-quantum KEM associated to
/// a coordinate.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CoordinateKeypair {
    elgamal_keypair: elgamal::Keypair,
    postquantum_keypair: Option<postquantum::Keypair>,
}

impl CoordinateKeypair {
    /// Generates a new random coordinate keypair cryptographically bound to the
    /// Covercrypt binding point `h`.
    #[must_use]
    fn random(rng: &mut impl CryptoRngCore, h: &EcPoint, hybridize: bool) -> Self {
        let elgamal_sk = Scalar::new(rng);
        let elgamal_pk = h * &elgamal_sk;
        let elgamal_keypair = elgamal::Keypair::new(elgamal_sk, elgamal_pk);
        let postquantum_keypair = if hybridize {
            Some(postquantum::Keypair::random(rng))
        } else {
            None
        };
        CoordinateKeypair {
            elgamal_keypair,
            postquantum_keypair,
        }
    }

    /// Returns a copy of the public key.
    #[must_use]
    fn public_key(&self) -> Option<CoordinatePublicKey> {
        match (
            self.elgamal_keypair.pk().cloned(),
            &self.postquantum_keypair,
        ) {
            (Some(elgamal_pk), None) => Some(CoordinatePublicKey::Classic { elgamal_pk }),
            (Some(elgamal_pk), Some(postquantum_keypair)) => {
                let postquantum_pk = postquantum_keypair.pk().clone();
                Some(CoordinatePublicKey::Hybridized {
                    elgamal_pk,
                    postquantum_pk,
                })
            }
            (None, _) => None,
        }
    }

    /// Returns a copy of the secret key.
    #[must_use]
    fn secret_key(&self) -> CoordinateSecretKey {
        let elgamal_sk = self.elgamal_keypair.sk().clone();
        if let Some(keypair) = &self.postquantum_keypair {
            let postquantum_sk = keypair.sk().clone();
            CoordinateSecretKey::Hybridized {
                elgamal_sk,
                postquantum_sk,
            }
        } else {
            CoordinateSecretKey::Classic { elgamal_sk }
        }
    }

    /// Returns true if the given coordinate secret key is contained in this keypair.
    fn contains(&self, coordinate_sk: &CoordinateSecretKey) -> bool {
        match (coordinate_sk, &self.postquantum_keypair) {
            (CoordinateSecretKey::Classic { elgamal_sk }, None) => {
                self.elgamal_keypair.contains(elgamal_sk)
            }
            (
                CoordinateSecretKey::Hybridized {
                    postquantum_sk,
                    elgamal_sk,
                },
                Some(postquantum_keypair),
            ) => {
                self.elgamal_keypair.contains(elgamal_sk)
                    && postquantum_keypair.contains(postquantum_sk)
            }
            (CoordinateSecretKey::Hybridized { .. }, None)
            | (CoordinateSecretKey::Classic { .. }, Some(_)) => false,
        }
    }

    /// Returns true if this coordinate keypair is hybridized.
    fn is_hybridized(&self) -> bool {
        self.postquantum_keypair.is_some()
    }

    /// Drop the ElGamal public key of this coordinate keypair.
    ///
    /// Future MPK will be generated without any key for this coordinate, thus
    /// disabling encryption for this coordinate.
    fn drop_encryption_key(&mut self) {
        self.elgamal_keypair.deprecate();
    }

    /// Drop the post-quantum part of this coordinate keypair.
    ///
    /// Future MPK will be generated without post-quantum key, thus disabling
    /// hybridized encryption.
    fn drop_hybridization(&mut self) {
        self.postquantum_keypair = None;
    }
}

/// Covercrypt user IDs are used to make user keys unique and traceable.
///
/// They are composed of a sequence of `LENGTH` scalars.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
struct UserId(LinkedList<Scalar>);

impl UserId {
    /// Returns the tracing level of the USK.
    fn tracing_level(&self) -> usize {
        self.0.len() - 1
    }

    fn iter(&self) -> impl Iterator<Item = &Scalar> {
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
#[derive(Debug, PartialEq, Eq, Default)]
struct TracingSecretKey {
    tracers: LinkedList<elgamal::Keypair>,
    users: HashSet<UserId>,
}

impl TracingSecretKey {
    /// Returns the current tracing level.
    fn tracing_level(&self) -> usize {
        self.tracers.len() - 1
    }

    /// Generates a new tracer. Returns the associated trap.
    fn increase_tracing(&mut self, rng: &mut impl CryptoRngCore) {
        self.tracers.push_back(elgamal::Keypair::random(rng));
    }

    /// Drops the oldest tracer and returns it.
    fn _decrease_tracing(&mut self) -> Result<elgamal::Keypair, Error> {
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

    /// Set the level of the tracing keypair to the target level.
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
                self.increase_tracing(rng);
            }
        }
        Ok(())
    }

    /// Returns true if the given user ID is known.
    fn knows(&self, id: &UserId) -> bool {
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
        TracingPublicKey(
            self.tracers
                .iter()
                .filter_map(elgamal::Keypair::pk)
                .cloned()
                .collect(),
        )
    }
}

/// Covercrypt tracing public key.
#[derive(Debug, PartialEq, Eq, Default)]
struct TracingPublicKey(LinkedList<EcPoint>);

impl TracingPublicKey {
    /// Returns the tracing level tracing of this key.
    fn tracing_level(&self) -> usize {
        self.0.len() - 1
    }
}

/// The Covercrypt Master Secret Key (MSK).
///
/// It is composed of:
/// - the scalar `s` used to bind tracing and coordinate keys;
/// - the tracing secret key used to produce challenges to trace user keys;
/// - the secret keys associated to the universal coordinates;
/// - an optional key for symmetric USK-signing.
#[derive(Debug, PartialEq, Eq)]
pub struct MasterSecretKey {
    s: Scalar,
    tsk: TracingSecretKey,
    coordinate_keypairs: RevisionMap<Coordinate, CoordinateKeypair>,
    signing_key: Option<SymmetricKey<SIGNING_KEY_LENGTH>>,
}

impl MasterSecretKey {
    /// Returns the binding points.
    fn binding_point(&self) -> EcPoint {
        EcPoint::from(&self.s)
    }

    /// Generates a new ID and adds it to the list of known user IDs.
    fn generate_user_id(&mut self, rng: &mut impl CryptoRngCore) -> Result<UserId, Error> {
        if let Some(first_tracer) = self.tsk.tracers.front() {
            let mut markers = LinkedList::new();
            // Generate all but the first identifier at random. The first
            // one is the solution of `(s - linear_comb)/first_tracer`.
            let mut linear_comb = Scalar::zero();
            for tracer in self.tsk.tracers.iter().skip(1) {
                let ai = Scalar::new(rng);
                linear_comb = &linear_comb + &(&ai * tracer.sk());
                markers.push_back(ai);
            }
            markers.push_front(&(&self.s - &linear_comb) / first_tracer.sk());
            let id = UserId(markers);
            self.tsk.add_user(id.clone());
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
                .zip(self.tsk.tracers.iter())
                .map(|(identifier, tracer)| identifier * tracer.sk())
                .fold(Scalar::zero(), |mut acc, elt| {
                    acc = &acc + &elt;
                    acc
                })
    }

    /// If the tracing level of the user ID is not in sync with the one of the
    /// MSK, generate a new ID with the correct tracing level and replace the
    /// old ID by the new one in the MSK.
    ///
    /// # Error
    ///
    /// Returns an error if the ID is unknown.
    fn refresh_id(&mut self, rng: &mut impl CryptoRngCore, id: UserId) -> Result<UserId, Error> {
        if !self.tsk.knows(&id) {
            Err(Error::Tracing("unknown user".to_string()))
        } else if id.tracing_level() != self.tsk.tracing_level() {
            let new_id = self.generate_user_id(rng)?;
            self.tsk.add_user(new_id.clone());
            self.tsk.del_user(&id);
            Ok(new_id)
        } else {
            // Since the integrity of the USK is checked, there is no need to
            // validated the ID before returning it. This saves O(tracing-level)
            // multiplications... but there is actually no way to locally check
            // the caller actually checked the integrity first.
            Ok(id)
        }
    }

    /// Returns the most recent secret key associated to each given coordinate.
    ///
    /// # Error
    ///
    /// Returns an error if some coordinate is missing from the MSK.
    fn get_latest_coordinate_sk<'a>(
        &'a self,
        coordinates: impl Iterator<Item = Coordinate> + 'a,
    ) -> impl Iterator<Item = Result<(Coordinate, CoordinateSecretKey), Error>> + 'a {
        coordinates.map(|coordinate| {
            self.coordinate_keypairs
                .get_latest(&coordinate)
                .ok_or(Error::KeyError(format!(
                    "MSK has no key for coordinate {coordinate:?}"
                )))
                .map(CoordinateKeypair::secret_key)
                .map(|key| (coordinate, key))
        })
    }

    /// Returns the most recent public key associated to each coordinate.
    fn get_latest_coordinate_pk(
        &self,
    ) -> impl Iterator<Item = (Coordinate, CoordinatePublicKey)> + '_ {
        self.coordinate_keypairs
            .iter()
            .filter_map(|(coordinate, keypairs)| {
                let pk: Option<CoordinatePublicKey> =
                    keypairs.front().and_then(|keypair| keypair.public_key());
                pk.map(|pk| (coordinate.clone(), pk))
            })
    }
}

/// Covercrypt Public Key (PK).
///
/// It is composed of:
/// - the binding point `h`;
/// - the tracing public key;
/// - the public keys of the universal coordinates.
#[derive(Debug, PartialEq, Eq)]
pub struct MasterPublicKey {
    h: EcPoint,
    tpk: TracingPublicKey,
    coordinate_keys: HashMap<Coordinate, CoordinatePublicKey>,
}

impl MasterPublicKey {
    /// Returns the tracing level of this MPK.
    #[inline(always)]
    pub fn tracing_level(&self) -> usize {
        self.tpk.tracing_level()
    }

    /// Generates traps for the given scalar.
    // TODO: find a better concept.
    fn set_traps(&self, r: &Scalar) -> Vec<EcPoint> {
        self.tpk.0.iter().map(|gi| gi * r).collect()
    }
}

/// Covercrypt User Secret Key (USK).
///
/// It is composed of:
/// - a user ID (pair of scalars);
/// - the keys of the coordinates derived from the user decryption policy;
/// - a signature from the MSK that guarantees its integrity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserSecretKey {
    id: UserId,
    coordinate_keys: RevisionVec<Coordinate, CoordinateSecretKey>,
    msk_signature: Option<KmacSignature>,
}

/// Encapsulation of a `SEED_LENGTH`-byte seed for a given coordinate.
///
/// In case the security level of the associated coordinate was set to
/// post-quantum secure, the key encapsulation is hybridized. This implies a
/// significant size overhead.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum SeedEncapsulation {
    Classic([u8; SEED_LENGTH]),
    Hybridized(postquantum::Ciphertext),
}

/// Covercrypt encapsulation.
///
/// It is created for a subset of universal coordinates. One key encapsulation
/// is created per associated coordinate.
///
/// It is composed of:
/// - the early abort tag;
/// - the traps used to select users that can open this encapsulation;
/// - the coordinate encapsulations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encapsulation {
    tag: Tag,
    traps: Vec<EcPoint>,
    coordinate_encapsulations: HashSet<SeedEncapsulation>,
}

impl Encapsulation {
    /// Returns the tracing level of this encapsulation.
    pub fn tracing_level(&self) -> usize {
        self.traps.len() - 1
    }
}
