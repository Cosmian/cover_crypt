//! Defines useful macros.

pub use cosmian_crypto_core::{RandomFixedSizeCBytes, SymmetricKey};
pub use tiny_keccak::{Hasher, Shake, Xof};

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
            let mut hasher = $crate::core::macros::Shake::v256();
            $(
                <$crate::core::macros::Shake as $crate::core::macros::Hasher>::update(&mut hasher, $bytes);
            )*
            let mut tag = [0; $TAG_LENGTH];
            let mut key = $crate::core::macros::SymmetricKey::try_from_bytes([0; $KEY_LENGTH])?;
            <$crate::core::macros::Shake as $crate::core::macros::Xof>::squeeze(&mut hasher, &mut tag);
            <$crate::core::macros::Shake as $crate::core::macros::Hasher>::finalize(hasher, &mut key);
            Ok((tag, key))
        }
    };
}
