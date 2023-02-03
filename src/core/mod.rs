//! Implements the core functionalities of `CoverCrypt`.

// Allows using the paper notations.
#![allow(non_snake_case)]

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use cosmian_crypto_core::KeyTrait;
use pqc_kyber::{KYBER_INDCPA_BYTES, KYBER_INDCPA_PUBLICKEYBYTES, KYBER_INDCPA_SECRETKEYBYTES};

use crate::abe_policy::Partition;

#[macro_use]
pub mod macros;

pub mod api;
pub mod primitives;

#[cfg(feature = "interface")]
pub mod serialization;

/// Length of the EAKEM tag
// TODO TBZ: use as constant generic ?
type Tag<const LENGTH: usize> = [u8; LENGTH];

/// Kyber public key length
type KyberPublicKey = [u8; KYBER_INDCPA_PUBLICKEYBYTES];

/// Kyber secret key length
type KyberSecretKey = [u8; KYBER_INDCPA_SECRETKEYBYTES];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey<const PUBLIC_KEY_LENGTH: usize, DhPublicKey: KeyTrait<PUBLIC_KEY_LENGTH>> {
    U: DhPublicKey,
    V: DhPublicKey,
    pub(crate) H: HashMap<Partition, (Option<KyberPublicKey>, DhPublicKey)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MasterSecretKey<
    const PRIVATE_KEY_LENGTH: usize,
    DhPrivateKey: KeyTrait<PRIVATE_KEY_LENGTH>,
> {
    u: DhPrivateKey,
    v: DhPrivateKey,
    s: DhPrivateKey,
    pub(crate) x: HashMap<Partition, (Option<KyberSecretKey>, DhPrivateKey)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserSecretKey<
    const PRIVATE_KEY_LENGTH: usize,
    DhPrivateKey: KeyTrait<PRIVATE_KEY_LENGTH> + Hash,
> {
    a: DhPrivateKey,
    b: DhPrivateKey,
    pub(crate) x: HashSet<(Option<KyberSecretKey>, DhPrivateKey)>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum KeyEncapsulation<const SYM_KEY_LENGTH: usize> {
    ClassicEncapsulation(Box<[u8; SYM_KEY_LENGTH]>),
    HybridEncapsulation(Box<[u8; KYBER_INDCPA_BYTES]>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encapsulation<
    const TAG_LENGTH: usize,
    const SYM_KEY_LENGTH: usize,
    const PUBLIC_KEY_LENGTH: usize,
    PublicKey: KeyTrait<PUBLIC_KEY_LENGTH>,
> {
    C: PublicKey,
    D: PublicKey,
    tag: Tag<TAG_LENGTH>,
    E: HashSet<KeyEncapsulation<SYM_KEY_LENGTH>>,
}
