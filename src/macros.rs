//! Defines macro used in this module.
#[cfg(feature = "hybrid")]
pub use pqc_kyber::KYBER_INDCPA_BYTES;
pub use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Hashes and extends the given bytes into a tag of size `TAG_LENGTH` and a
/// key of size `KEY_LENGTH`.
///
/// - `bytes`   : input bytes
#[macro_export]
macro_rules! eakem_hash {
    ($TAG_LENGTH: ident, $KEY_LENGTH: ident, $($bytes: expr),+) => {
        {
            let mut hasher = $crate::macros::Shake256::default();
            $(
                <$crate::macros::Shake256 as $crate::macros::Update>::update(&mut hasher, $bytes);
            )*
            let mut reader =
                <$crate::macros::Shake256 as $crate::macros::ExtendableOutput>::finalize_xof(hasher);
            let mut tag = [0; $TAG_LENGTH];
            let mut key = [0; $KEY_LENGTH];
            <<$crate::macros::Shake256 as $crate::macros::ExtendableOutput>::Reader as $crate::macros::XofReader>::read(&mut reader, &mut tag);
            <<$crate::macros::Shake256 as $crate::macros::ExtendableOutput>::Reader as $crate::macros::XofReader>::read(&mut reader, &mut key);
            (tag, key)
        }
    };
}

/// Macro inserting the correct name for the encapsulation length.
#[cfg(feature = "hybrid")]
#[macro_export]
macro_rules! encapsulation_length {
    () => {
        $crate::macros::KYBER_INDCPA_BYTES
    };
}

/// Macro inserting the correct name for the encapsulation length.
///
/// *NOTE*: `SYM_KEY_LENGTH` should be defined.
#[cfg(not(feature = "hybrid"))]
#[macro_export]
macro_rules! encapsulation_length {
    () => {
        SYM_KEY_LENGTH
    };
}

/// Macro calling `cover_crypt_core::setup()` with the correct generic
/// parameters.
///
/// *NOTE*: `CsRng`, `TAG_LENGTH`, `KeyPair` and `DEM` should be defined.
#[macro_export]
macro_rules! setup {
    ($rng: expr, $partition_set: expr) => {
        $crate::cover_crypt_core::setup::<
            { KeyPair::PUBLIC_KEY_LENGTH },
            { KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            KeyPair,
        >($rng, $partition_set)
    };
}

/// Macro calling `cover_crypt_core::join()` with the correct generic
/// parameters.
///
/// *NOTE*: `CsRng`, `TAG_LENGTH`, `KeyPair` and `DEM` should be defined.
#[macro_export]
macro_rules! join {
    ($rng: expr, $msk: expr, $user_set: expr) => {
        $crate::cover_crypt_core::join::<
            { KeyPair::PUBLIC_KEY_LENGTH },
            { KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            KeyPair,
        >($rng, $msk, $user_set)
    };
}

/// Macro calling `cover_crypt_core::encaps()` with the correct generic
/// parameters.
///
/// *NOTE*: `CsRng`, `TAG_LENGTH`, `KeyPair` and `DEM` should be defined.
#[cfg(feature = "hybrid")]
#[macro_export]
macro_rules! encaps {
    ($rng: expr, $pk: expr, $target_set: expr) => {
        $crate::cover_crypt_core::encaps::<
            TAG_LENGTH,
            { KeyPair::PUBLIC_KEY_LENGTH },
            { KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            <DEM as Dem<{ DEM::KEY_LENGTH }>>::Key,
            KeyPair,
        >($rng, $pk, $target_set)
    };
}
#[cfg(not(feature = "hybrid"))]
#[macro_export]
macro_rules! encaps {
    ($rng: expr, $pk: expr, $target_set: expr) => {
        $crate::cover_crypt_core::encaps::<
            TAG_LENGTH,
            SYM_KEY_LENGTH,
            { KeyPair::PUBLIC_KEY_LENGTH },
            { KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            <DEM as Dem<{ Aes256GcmCrypto::KEY_LENGTH }>>::Key,
            KeyPair,
        >($rng, $pk, $target_set)
    };
}

/// Macro calling `cover_crypt_core::decaps()` with the correct generic
/// parameters.
///
/// *NOTE*: `CsRng`, `TAG_LENGTH`, `KeyPair` and `DEM` should be defined.
#[cfg(feature = "hybrid")]
#[macro_export]
macro_rules! decaps {
    ($sk: expr, $encapsulation: expr ) => {
        $crate::cover_crypt_core::decaps::<
            TAG_LENGTH,
            { KeyPair::PUBLIC_KEY_LENGTH },
            { KeyPair::PRIVATE_KEY_LENGTH },
            <DEM as Dem<{ DEM::KEY_LENGTH }>>::Key,
            KeyPair,
        >($sk, $encapsulation)
    };
}
#[cfg(not(feature = "hybrid"))]
#[macro_export]
macro_rules! decaps {
    ($sk: expr, $encapsulation: expr ) => {
        $crate::cover_crypt_core::decaps::<
            TAG_LENGTH,
            SYM_KEY_LENGTH,
            { KeyPair::PUBLIC_KEY_LENGTH },
            { KeyPair::PRIVATE_KEY_LENGTH },
            <DEM as Dem<{ DEM::KEY_LENGTH }>>::Key,
            KeyPair,
        >($sk, $encapsulation)
    };
}

/// Macro calling `cover_crypt_core::update()` with the correct generic
/// parameters.
///
/// *NOTE*: `CsRng`, `KeyPair` should be defined.
#[macro_export]
macro_rules! update {
    ($rng: expr, $msk: expr, $mpk: expr, $partition_set: expr) => {
        $crate::cover_crypt_core::update::<
            { KeyPair::PUBLIC_KEY_LENGTH },
            { KeyPair::PRIVATE_KEY_LENGTH },
            CsRng,
            KeyPair,
        >($rng, $msk, $mpk, $partition_set)
    };
}

/// Macro calling `cover_crypt_core::refresh()` with the correct generic
/// parameters.
///
/// *NOTE*: `KeyPair` should be defined.
#[macro_export]
macro_rules! refresh {
    ($msk: expr, $usk: expr, $user_set: expr, $keep_old_access: expr) => {
        $crate::cover_crypt_core::refresh::<
            { KeyPair::PRIVATE_KEY_LENGTH },
            <KeyPair as DhKeyPair<
                { KeyPair::PUBLIC_KEY_LENGTH },
                { KeyPair::PRIVATE_KEY_LENGTH },
            >>::PrivateKey,
        >($msk, $usk, $user_set, $keep_old_access)
    };
}
