//! Implements the core functionalities of `Covercrypt`.

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    ops::Deref,
};

use cosmian_crypto_core::{R25519PrivateKey, R25519PublicKey, SymmetricKey};
use pqc_kyber::{KYBER_INDCPA_BYTES, KYBER_INDCPA_PUBLICKEYBYTES, KYBER_INDCPA_SECRETKEYBYTES};
use zeroize::ZeroizeOnDrop;

use crate::{
    abe_policy::Partition,
    data_struct::{RevisionMap, RevisionVec},
};

#[macro_use]
pub mod macros;

pub mod api;
pub mod primitives;

#[cfg(feature = "serialization")]
pub mod serialization;

/// The symmetric key is 32 bytes long to provide 128 bits of post-quantum
/// security.
pub const SYM_KEY_LENGTH: usize = 32;

/// The length of the KMAC key.
pub const KMAC_KEY_LENGTH: usize = 16;

/// The length of the KMAC output.
const KMAC_LENGTH: usize = 32;
type KmacSignature = [u8; KMAC_LENGTH];

/// Length of the `Covercrypt` tag
const TAG_LENGTH: usize = 16;
type Tag = [u8; TAG_LENGTH];

/// Kyber public key length
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KyberPublicKey([u8; KYBER_INDCPA_PUBLICKEYBYTES]);

impl Deref for KyberPublicKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Kyber secret key length
#[derive(Debug, Clone, PartialEq, Eq, Hash, ZeroizeOnDrop)]
pub struct KyberSecretKey([u8; KYBER_INDCPA_SECRETKEYBYTES]);

impl Deref for KyberSecretKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub(super) type PublicSubkey = (Option<KyberPublicKey>, R25519PublicKey);

#[derive(Debug, PartialEq, Eq)]
pub struct MasterPublicKey {
    g1: R25519PublicKey,
    g2: R25519PublicKey,
    pub(crate) subkeys: HashMap<Partition, PublicSubkey>,
}

pub(super) type SecretSubkey = (Option<KyberSecretKey>, R25519PrivateKey);
#[derive(Debug, PartialEq, Eq)]
pub struct MasterSecretKey {
    s: R25519PrivateKey,
    s1: R25519PrivateKey,
    s2: R25519PrivateKey,
    pub(crate) subkeys: RevisionMap<Partition, SecretSubkey>,
    kmac_key: Option<SymmetricKey<KMAC_KEY_LENGTH>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct UserSecretKey {
    a: R25519PrivateKey,
    b: R25519PrivateKey,
    pub(crate) subkeys: RevisionVec<Partition, SecretSubkey>,
    kmac: Option<KmacSignature>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum KeyEncapsulation {
    ClassicEncapsulation(Box<[u8; SYM_KEY_LENGTH]>),
    HybridEncapsulation(Box<[u8; KYBER_INDCPA_BYTES]>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encapsulation {
    c1: R25519PublicKey,
    c2: R25519PublicKey,
    tag: Tag,
    encs: HashSet<KeyEncapsulation>,
}
