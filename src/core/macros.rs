//! Defines useful macros.

pub use cosmian_crypto_core::symmetric_crypto::Dem;
pub use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Hashes and extends the given bytes into a tag of size `TAG_LENGTH` and a
/// key of size `KEY_LENGTH`.
///
/// # Security
///
/// This hash is based on SHAKE256.
///
/// # Parameters
///
/// - `bytes`   : input bytes
macro_rules! eakem_hash {
    ($TAG_LENGTH: ident, $KEY_LENGTH: ident, $($bytes: expr),+) => {
        {
            let mut hasher = $crate::core::macros::Shake256::default();
            $(
                <$crate::core::macros::Shake256 as $crate::core::macros::Update>::update(&mut hasher, $bytes);
            )*
            let mut reader =
                <$crate::core::macros::Shake256 as $crate::core::macros::ExtendableOutput>::finalize_xof(hasher);
            let mut tag = [0; $TAG_LENGTH];
            let mut key = [0; $KEY_LENGTH];
            <<$crate::core::macros::Shake256 as $crate::core::macros::ExtendableOutput>::Reader as
                $crate::core::macros::XofReader>::read(&mut reader, &mut tag);
            <<$crate::core::macros::Shake256 as $crate::core::macros::ExtendableOutput>::Reader as
                $crate::core::macros::XofReader>::read(&mut reader, &mut key);
            (tag, key)
        }
    };
}

/// Macro calling CoverCrypt [`setup()`](crate::core::primitives::setup) with the correct
/// generic parameters.
///
/// *NOTE*: the following objects should be defined
/// - `type CsRng: `[`CryptRngCore`](cosmian_crypto_core::reexport::rand_core::CryptoRngCore)
/// - `type KeyPair: `[`DhKeyPair`](cosmian_crypto_core::asymmetric_crypto::DhKeyPair)
#[macro_export]
macro_rules! setup {
    ($rng: expr, $partition_set: expr) => {
        $crate::core::primitives::setup::<
            { KeyPair::PUBLIC_KEY_LENGTH },
            { KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            KeyPair,
        >($rng, $partition_set)
    };
}

/// Macro calling CoverCrypt [`join()`](crate::core::primitives::join) with the correct
/// generic parameters.
///
/// *NOTE*: the following objects should be defined
/// - `type CsRng: `[`CryptRngCore`](cosmian_crypto_core::reexport::rand_core::CryptoRngCore)
/// - `type KeyPair: `[`DhKeyPair`](cosmian_crypto_core::asymmetric_crypto::DhKeyPair)
#[macro_export]
macro_rules! join {
    ($rng: expr, $msk: expr, $user_set: expr) => {
        $crate::core::primitives::join::<
            { KeyPair::PUBLIC_KEY_LENGTH },
            { KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            KeyPair,
        >($rng, $msk, $user_set)
    };
}

/// Macro calling CoverCrypt [`encaps()`](crate::core::primitives::encaps) with the correct
/// generic parameters.
///
/// *NOTE*: the following objects should be defined
/// - `type CsRng: `[`CryptRngCore`](cosmian_crypto_core::reexport::rand_core::CryptoRngCore)
/// - `const TAG_LENGTH: usize` the length of the EAKEM TAG
/// - `const SYM_KEY_LENGTH: usize` the length of the symmetric key
/// - `type KeyPair: `[`DhKeyPair`](cosmian_crypto_core::asymmetric_crypto::DhKeyPair)
/// - `type DEM: `[`Dem`](cosmian_crypto_core::symmetric_crypto::Dem)
#[macro_export]
macro_rules! encaps {
    ($rng: expr, $pk: expr, $target_set: expr) => {
        $crate::core::primitives::encaps::<
            TAG_LENGTH,
            SYM_KEY_LENGTH,
            { KeyPair::PUBLIC_KEY_LENGTH },
            { KeyPair::PRIVATE_KEY_LENGTH },
            <DEM as $crate::core::macros::Dem<SYM_KEY_LENGTH>>::Key,
            KeyPair,
        >($rng, $pk, $target_set)
    };
}

/// Macro calling CoverCrypt [`decaps()`](crate::core::primitives::decaps) with the correct
/// generic parameters.
///
/// *NOTE*: the following objects should be defined
/// - `type CsRng: `[`CryptRngCore`](cosmian_crypto_core::reexport::rand_core::CryptoRngCore)
/// - `const TAG_LENGTH: usize` the length of the EAKEM TAG
/// - `const SYM_KEY_LENGTH: usize` the length of the symmetric key
/// - `type KeyPair: `[`DhKeyPair`](cosmian_crypto_core::asymmetric_crypto::DhKeyPair)
/// - `type DEM: `[`Dem`](cosmian_crypto_core::symmetric_crypto::Dem)
#[macro_export]
macro_rules! decaps {
    ($sk: expr, $encapsulation: expr ) => {
        $crate::core::primitives::decaps::<
            TAG_LENGTH,
            SYM_KEY_LENGTH,
            { KeyPair::PUBLIC_KEY_LENGTH },
            { KeyPair::PRIVATE_KEY_LENGTH },
            <DEM as $crate::core::macros::Dem<SYM_KEY_LENGTH>>::Key,
            KeyPair,
        >($sk, $encapsulation)
    };
}

/// Macro calling CoverCrypt [`update()`](crate::core::primitives::update) with the correct
/// generic parameters.
///
/// *NOTE*: the following objects should be defined
/// - `type CsRng: `[`CryptRngCore`](cosmian_crypto_core::reexport::rand_core::CryptoRngCore)
/// - `type KeyPair: `[`DhKeyPair`](cosmian_crypto_core::asymmetric_crypto::DhKeyPair)
#[macro_export]
macro_rules! update {
    ($rng: expr, $msk: expr, $mpk: expr, $partition_set: expr) => {
        $crate::core::primitives::update::<
            { KeyPair::PUBLIC_KEY_LENGTH },
            { KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            KeyPair,
        >($rng, $msk, $mpk, $partition_set)
    };
}

/// Macro calling CoverCrypt [`refresh()`](crate::core::primitives::refresh) with the correct
/// generic parameters.
///
/// *NOTE*: the following objects should be defined
/// - `type KeyPair: `[`DhKeyPair`](cosmian_crypto_core::asymmetric_crypto::DhKeyPair)
#[macro_export]
macro_rules! refresh {
    ($msk: expr, $usk: expr, $user_set: expr, $keep_old_access: expr) => {
        $crate::core::primitives::refresh::<
            { KeyPair::PRIVATE_KEY_LENGTH },
            <KeyPair as DhKeyPair<
                { KeyPair::PUBLIC_KEY_LENGTH },
                { KeyPair::PRIVATE_KEY_LENGTH },
            >>::PrivateKey,
        >($msk, $usk, $user_set, $keep_old_access)
    };
}
