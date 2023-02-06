use std::sync::Mutex;

pub use cosmian_crypto_core::{
    asymmetric_crypto::curve25519::X25519KeyPair as KeyPair,
    symmetric_crypto::aes_256_gcm_pure::{
        Aes256GcmCrypto as DEM, KEY_LENGTH as SYM_KEY_LENGTH, MAC_LENGTH as TAG_LENGTH,
    },
    CsRng,
};
use cosmian_crypto_core::{
    asymmetric_crypto::DhKeyPair, reexport::rand_core::SeedableRng, symmetric_crypto::Dem,
};

use crate::{
    abe_policy::{AccessPolicy, Policy},
    core, decaps, encaps, keygen, refresh, setup, update, CoverCrypt, Error,
};

/// Instantiate a `CoverCrypt` type with AES GCM 256 as DEM
#[derive(Debug)]
pub struct CoverCryptX25519Aes256 {
    rng: Mutex<CsRng>,
}

impl PartialEq for CoverCryptX25519Aes256 {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl
    CoverCrypt<
        TAG_LENGTH,
        { DEM::KEY_LENGTH },
        { KeyPair::PUBLIC_KEY_LENGTH },
        { KeyPair::PRIVATE_KEY_LENGTH },
        KeyPair,
        DEM,
    > for CoverCryptX25519Aes256
{
    type Encapsulation =
        core::Encapsulation<
            TAG_LENGTH,
            { Self::SYM_KEY_LENGTH },
            { Self::PUBLIC_KEY_LENGTH },
            <KeyPair as DhKeyPair<
                { Self::PUBLIC_KEY_LENGTH },
                { Self::PRIVATE_KEY_LENGTH },
            >>::PublicKey,
        >;
    type MasterSecretKey =
        core::MasterSecretKey<
            { Self::PRIVATE_KEY_LENGTH },
            <KeyPair as DhKeyPair<
                { Self::PUBLIC_KEY_LENGTH },
                { Self::PRIVATE_KEY_LENGTH },
            >>::PrivateKey,
        >;
    type PublicKey =
        core::PublicKey<
            { Self::PUBLIC_KEY_LENGTH },
            <KeyPair as DhKeyPair<
                { Self::PUBLIC_KEY_LENGTH },
                { Self::PRIVATE_KEY_LENGTH },
            >>::PublicKey,
        >;
    type SymmetricKey = <DEM as Dem<{ Self::SYM_KEY_LENGTH }>>::Key;
    type UserSecretKey =
        core::UserSecretKey<
            { Self::PRIVATE_KEY_LENGTH },
            <KeyPair as DhKeyPair<
                { Self::PUBLIC_KEY_LENGTH },
                { Self::PRIVATE_KEY_LENGTH },
            >>::PrivateKey,
        >;

    const SYM_KEY_LENGTH: usize = DEM::KEY_LENGTH;

    fn generate_master_keys(
        &self,
        policy: &Policy,
    ) -> Result<(Self::MasterSecretKey, Self::PublicKey), Error> {
        Ok(setup!(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            &policy.generate_all_partitions()?
        ))
    }

    fn update_master_keys(
        &self,
        policy: &Policy,
        msk: &mut Self::MasterSecretKey,
        mpk: &mut Self::PublicKey,
    ) -> Result<(), Error> {
        update!(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            mpk,
            &policy.generate_all_partitions()?
        )
    }

    fn generate_user_secret_key(
        &self,
        msk: &Self::MasterSecretKey,
        access_policy: &AccessPolicy,
        policy: &Policy,
    ) -> Result<Self::UserSecretKey, Error> {
        Ok(keygen!(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            &policy.access_policy_to_current_partitions(access_policy, true)?
        ))
    }

    fn refresh_user_secret_key(
        &self,
        usk: &mut Self::UserSecretKey,
        access_policy: &AccessPolicy,
        msk: &Self::MasterSecretKey,
        policy: &Policy,
        keep_old_accesses: bool,
    ) -> Result<(), Error> {
        refresh!(
            msk,
            usk,
            &policy.access_policy_to_current_partitions(access_policy, true)?,
            keep_old_accesses
        );
        Ok(())
    }

    fn encaps(
        &self,
        policy: &Policy,
        pk: &Self::PublicKey,
        access_policy: &AccessPolicy,
    ) -> Result<
        (
            <DEM as Dem<{ Self::SYM_KEY_LENGTH }>>::Key,
            Self::Encapsulation,
        ),
        Error,
    > {
        Ok(encaps!(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            pk,
            &policy.access_policy_to_current_partitions(access_policy, false)?
        ))
    }

    fn decaps(
        &self,
        usk: &Self::UserSecretKey,
        encapsulation: &Self::Encapsulation,
    ) -> Result<<DEM as Dem<{ Self::SYM_KEY_LENGTH }>>::Key, Error> {
        decaps!(usk, encapsulation)
    }

    fn encrypt(
        &self,
        symmetric_key: &<DEM as Dem<{ Self::SYM_KEY_LENGTH }>>::Key,
        plaintext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        <DEM as Dem<{ Self::SYM_KEY_LENGTH }>>::encrypt(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            symmetric_key,
            plaintext,
            authentication_data,
        )
        .map_err(Error::CryptoCoreError)
    }

    fn decrypt(
        &self,
        symmetric_key: &<DEM as Dem<{ Self::SYM_KEY_LENGTH }>>::Key,
        ciphertext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        <DEM as Dem<{ Self::SYM_KEY_LENGTH }>>::decrypt(
            symmetric_key,
            ciphertext,
            authentication_data,
        )
        .map_err(Error::CryptoCoreError)
    }
}

impl Default for CoverCryptX25519Aes256 {
    fn default() -> Self {
        Self {
            rng: Mutex::new(CsRng::from_entropy()),
        }
    }
}

/// Convenience type
pub type EncryptedHeader = crate::core::api::EncryptedHeader<
    TAG_LENGTH,
    { DEM::KEY_LENGTH },
    { KeyPair::PUBLIC_KEY_LENGTH },
    { KeyPair::PRIVATE_KEY_LENGTH },
    KeyPair,
    DEM,
    CoverCryptX25519Aes256,
>;

/// Convenience type
pub type CleartextHeader = crate::core::api::CleartextHeader<{ DEM::KEY_LENGTH }, DEM>;

/// Convenience type: `CoverCryptX25519Aes256` master secret key
pub type MasterSecretKey = <CoverCryptX25519Aes256 as CoverCrypt<
    TAG_LENGTH,
    { DEM::KEY_LENGTH },
    { KeyPair::PUBLIC_KEY_LENGTH },
    { KeyPair::PRIVATE_KEY_LENGTH },
    KeyPair,
    DEM,
>>::MasterSecretKey;

/// Convenience type: `CoverCryptX25519Aes256` public key
pub type PublicKey = <CoverCryptX25519Aes256 as CoverCrypt<
    TAG_LENGTH,
    { DEM::KEY_LENGTH },
    { KeyPair::PUBLIC_KEY_LENGTH },
    { KeyPair::PRIVATE_KEY_LENGTH },
    KeyPair,
    DEM,
>>::PublicKey;

/// Convenience type: `CoverCryptX25519Aes256` user secret key
pub type UserSecretKey = <CoverCryptX25519Aes256 as CoverCrypt<
    TAG_LENGTH,
    { DEM::KEY_LENGTH },
    { KeyPair::PUBLIC_KEY_LENGTH },
    { KeyPair::PRIVATE_KEY_LENGTH },
    KeyPair,
    DEM,
>>::UserSecretKey;

/// Convenience type: `CoverCryptX25519Aes256` encapsulation
pub type Encapsulation = <CoverCryptX25519Aes256 as CoverCrypt<
    TAG_LENGTH,
    { DEM::KEY_LENGTH },
    { KeyPair::PUBLIC_KEY_LENGTH },
    { KeyPair::PRIVATE_KEY_LENGTH },
    KeyPair,
    DEM,
>>::Encapsulation;
