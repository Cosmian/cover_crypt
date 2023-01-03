//! Defines the CoverCrypt API.

use crate::Error;
use abe_policy::{AccessPolicy, Policy};
#[cfg(feature = "interface")]
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_crypto_core::{
    asymmetric_crypto::DhKeyPair,
    symmetric_crypto::{Dem, SymKey},
};
use std::{
    fmt::Debug,
    ops::{Add, Div, Mul, Sub},
};

/// This trait is the main entry point for the core functionalities.
///
/// It supplies a simple API that lets generate keys, encrypt and decrypt
/// messages.
///
/// In addition, two methods are supplied to generate random symmetric keys and
/// their corresponding cipher texts.
pub trait CoverCrypt<
    const TAG_LENGTH: usize,
    const SYM_KEY_LENGTH: usize,
    const PK_LENGTH: usize,
    const SK_LENGTH: usize,
    KeyPair,
    DEM,
>: Default + Debug + PartialEq where
    KeyPair: DhKeyPair<PK_LENGTH, SK_LENGTH>,
    DEM: Dem<SYM_KEY_LENGTH>,
    KeyPair::PublicKey: From<KeyPair::PrivateKey>,
    for<'a, 'b> &'a KeyPair::PublicKey: Add<&'b KeyPair::PublicKey, Output = KeyPair::PublicKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PublicKey>,
    for<'a, 'b> &'a KeyPair::PrivateKey: Add<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Sub<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Div<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>,
{
    const SYM_KEY_LENGTH: usize = SYM_KEY_LENGTH;
    const PUBLIC_KEY_LENGTH: usize = PK_LENGTH;
    const PRIVATE_KEY_LENGTH: usize = SK_LENGTH;

    #[cfg(not(feature = "interface"))]
    type MasterSecretKey: PartialEq + Eq;
    #[cfg(feature = "interface")]
    type MasterSecretKey: PartialEq + Eq + Serializable<Error = Error>;

    #[cfg(not(feature = "interface"))]
    type UserSecretKey: PartialEq + Eq;
    #[cfg(feature = "interface")]
    type UserSecretKey: PartialEq + Eq + Serializable<Error = Error>;

    #[cfg(not(feature = "interface"))]
    type PublicKey: PartialEq + Eq;
    #[cfg(feature = "interface")]
    type PublicKey: PartialEq + Eq + Serializable<Error = Error>;

    #[cfg(not(feature = "interface"))]
    type Encapsulation: PartialEq + Eq;
    #[cfg(feature = "interface")]
    type Encapsulation: PartialEq + Eq + Serializable<Error = Error>;

    type SymmetricKey: SymKey<SYM_KEY_LENGTH>;

    /// Generates the master authority keys for supplied Policy
    ///
    ///  - `policy` : Policy to use to generate the keys
    fn generate_master_keys(
        &self,
        policy: &Policy,
    ) -> Result<(Self::MasterSecretKey, Self::PublicKey), Error>;

    /// Updates the master keys according to this new policy.
    ///
    /// When a partition exists in the new policy but not in the master keys,
    /// a new key pair is added to the master keys for that partition.
    /// When a partition exists on the master keys, but not in the new policy,
    /// it is removed from the master keys.
    ///
    ///  - `policy` : Policy to use to generate the keys
    ///  - `msk`    : master secret key
    ///  - `mpk`    : master public key
    fn update_master_keys(
        &self,
        policy: &Policy,
        msk: &mut Self::MasterSecretKey,
        mpk: &mut Self::PublicKey,
    ) -> Result<(), Error>;

    /// Generates a user secret key.
    ///
    /// A new user secret key does NOT include to old (i.e. rotated) partitions
    ///
    /// - `msk`         : master secret key
    /// - `user_policy` : user access policy
    /// - `policy`      : global policy
    fn generate_user_secret_key(
        &self,
        msk: &Self::MasterSecretKey,
        user_policy: &AccessPolicy,
        policy: &Policy,
    ) -> Result<Self::UserSecretKey, Error>;

    /// Refreshes the user key according to the given master key and user policy.
    ///
    /// The user key will be granted access to the current partitions, as
    /// determined by its access policy. If `preserve_old_partitions_access`
    /// is set, the old user access will be preserved.
    ///
    /// - `usk`                 : the user key to refresh
    /// - `user_policy`         : the access policy of the user key
    /// - `msk`                 : master secret key
    /// - `policy`              : global policy of the master secret key
    /// - `keep_old_accesses`   : whether access to old partitions (i.e. before
    ///   rotation) should be kept
    fn refresh_user_secret_key(
        &self,
        usk: &mut Self::UserSecretKey,
        user_policy: &AccessPolicy,
        msk: &Self::MasterSecretKey,
        policy: &Policy,
        keep_old_accesses: bool,
    ) -> Result<(), Error>;

    /// Generates a random symmetric key to be used with a DEM scheme and
    /// generates its `CoverCrypt` encapsulation for the given policy
    /// `attributes`.
    ///
    /// - `policy`              : global policy
    /// - `pk`                  : public key
    /// - `encryption_policy`   : encryption policy used for the encapsulation
    fn encaps(
        &self,
        policy: &Policy,
        pk: &Self::PublicKey,
        encryption_policy: &AccessPolicy,
    ) -> Result<(DEM::Key, Self::Encapsulation), Error>;

    /// Decapsulates a symmetric key from the given `CoverCrypt` encapsulation.
    /// This returns multiple key candidates. The use of an authenticated DEM
    /// scheme allows to select valid ones.
    ///
    /// - `sk_u`            : user secret key
    /// - `encapsulation`   : encrypted symmetric key
    fn decaps(
        &self,
        sk_u: &Self::UserSecretKey,
        encapsulation: &Self::Encapsulation,
    ) -> Result<DEM::Key, Error>;

    /// Encrypts given plaintext using the given symmetric key.
    ///
    /// - `symmetric_key`       : symmetric key used to encrypt data
    /// - `plaintext`           : data to be encrypted
    /// - `authentication_data` : optional data used for authentication
    fn encrypt(
        &self,
        symmetric_key: &DEM::Key,
        plaintext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error>;

    /// Decrypts the given ciphertext using the given symmetric key.
    ///
    /// - `symmetric_key`       : symmetric key used to encrypt data
    /// - `plaintext`           : data to be encrypted
    /// - `authentication_data` : optional data used for authentication
    fn decrypt(
        &self,
        key: &DEM::Key,
        ciphertext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error>;
}

/// Encrypted header holding a `CoverCrypt` encapsulation of a symmetric key and
/// additional data encrypted using the `CoverCrypt` DEM with the encapsulated
/// key.
///
/// *Note*: the DEM ciphertext is also used to select the correct symmetric key
/// from the decapsulation.
///
/// - `encapsulation`   : `CoverCrypt` encapsulation of a symmetric key
/// - `ciphertext`      : `CoverCrypt` DEM encryption of additional data
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedHeader<
    const TAG_LENGTH: usize,
    const SYM_KEY_LENGTH: usize,
    const PK_LENGTH: usize,
    const SK_LENGTH: usize,
    KeyPair,
    DEM,
    CoverCryptScheme,
> where
    KeyPair: DhKeyPair<PK_LENGTH, SK_LENGTH>,
    DEM: Dem<SYM_KEY_LENGTH>,
    KeyPair::PublicKey: From<KeyPair::PrivateKey>,
    for<'a, 'b> &'a KeyPair::PublicKey: Add<&'b KeyPair::PublicKey, Output = KeyPair::PublicKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PublicKey>,
    for<'a, 'b> &'a KeyPair::PrivateKey: Add<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Sub<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Div<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>,
    CoverCryptScheme: CoverCrypt<TAG_LENGTH, SYM_KEY_LENGTH, PK_LENGTH, SK_LENGTH, KeyPair, DEM>,
{
    pub encapsulation: CoverCryptScheme::Encapsulation,
    pub ciphertext: Vec<u8>,
}

impl<
        const TAG_LENGTH: usize,
        const SYM_KEY_LENGTH: usize,
        const PK_LENGTH: usize,
        const SK_LENGTH: usize,
        KeyPair,
        DEM,
        CoverCryptScheme,
    >
    EncryptedHeader<
        TAG_LENGTH,
        SYM_KEY_LENGTH,
        PK_LENGTH,
        SK_LENGTH,
        KeyPair,
        DEM,
        CoverCryptScheme,
    >
where
    KeyPair: DhKeyPair<PK_LENGTH, SK_LENGTH>,
    DEM: Dem<SYM_KEY_LENGTH>,
    KeyPair::PublicKey: From<KeyPair::PrivateKey>,
    for<'a, 'b> &'a KeyPair::PublicKey: Add<&'b KeyPair::PublicKey, Output = KeyPair::PublicKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PublicKey>,
    for<'a, 'b> &'a KeyPair::PrivateKey: Add<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Sub<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Mul<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>
        + Div<&'b KeyPair::PrivateKey, Output = KeyPair::PrivateKey>,
    CoverCryptScheme: CoverCrypt<TAG_LENGTH, SYM_KEY_LENGTH, PK_LENGTH, SK_LENGTH, KeyPair, DEM>,
{
    /// Generates an encrypted header for a random key and the given metadata. Returns the
    /// encrypted header along with the symmetric key encapsulated in this header.
    ///
    /// - `cover_crypt`         : `CoverCrypt` object
    /// - `policy`              : global policy
    /// - `public_key`          : `CoverCrypt` public key
    /// - `encryption_policy`   : access policy used for the encapsulation
    /// - `header_metadata`     : additional data symmetrically encrypted in the header
    /// - `authentication_data` : authentication data used in the DEM encryption
    pub fn generate(
        cover_crypt: &CoverCryptScheme,
        policy: &Policy,
        public_key: &CoverCryptScheme::PublicKey,
        encryption_policy: &AccessPolicy,
        header_metadata: Option<&[u8]>,
        authentication_data: Option<&[u8]>,
    ) -> Result<(DEM::Key, Self), Error> {
        // generate a symmetric key and its encapsulation
        let (symmetric_key, encapsulation) =
            cover_crypt.encaps(policy, public_key, encryption_policy)?;

        // encrypt the metadata using the DEM with the authentication_data and the encapsulated key
        let ciphertext = match header_metadata {
            Some(d) => cover_crypt.encrypt(&symmetric_key, d, authentication_data)?,
            None => vec![],
        };

        Ok((
            symmetric_key,
            Self {
                encapsulation,
                ciphertext,
            },
        ))
    }

    /// Decrypts the header with the given user secret key.
    ///
    /// - `cover_crypt`         : `CoverCrypt` object
    /// - `usk`                 : `CoverCrypt` user secret key
    /// - `authentication_data` : authentication data used in the DEM encryption
    pub fn decrypt(
        &self,
        cover_crypt: &CoverCryptScheme,
        usk: &CoverCryptScheme::UserSecretKey,
        authentication_data: Option<&[u8]>,
    ) -> Result<CleartextHeader<SYM_KEY_LENGTH, DEM>, Error> {
        let symmetric_key = cover_crypt.decaps(usk, &self.encapsulation)?;
        let header_metadata = if self.ciphertext.is_empty() {
            vec![]
        } else {
            cover_crypt.decrypt(&symmetric_key, &self.ciphertext, authentication_data)?
        };
        Ok(CleartextHeader {
            symmetric_key,
            header_metadata,
        })
    }
}

/// Structure containing all data encrypted in an `EncryptedHeader`.
///
/// - `symmetric_key`   : DEM key
/// - `header_metadata` : additional data symmetrically encrypted in a header
#[derive(Debug, PartialEq, Eq)]
pub struct CleartextHeader<const KEY_LENGTH: usize, DEM>
where
    DEM: Dem<KEY_LENGTH>,
{
    pub symmetric_key: DEM::Key,
    pub header_metadata: Vec<u8>,
}
