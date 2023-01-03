use crate::{
    core::{self, partitions},
    decaps, encaps, join, refresh, setup, update, CoverCrypt, Error,
};
use abe_policy::{AccessPolicy, Policy};
use cosmian_crypto_core::{
    asymmetric_crypto::{curve25519::X25519KeyPair, DhKeyPair},
    reexport::rand_core::SeedableRng,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Dem},
    CsRng,
};
use std::{ops::DerefMut, sync::Mutex};

pub const TAG_LENGTH: usize = 32;
pub const SYM_KEY_LENGTH: usize = 32;
pub type KeyPair = X25519KeyPair;
#[allow(clippy::upper_case_acronyms)]
pub type DEM = Aes256GcmCrypto;

/// Instantiate a CoverCrypt type with AES GCM 256 as DEM
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
    const SYM_KEY_LENGTH: usize = DEM::KEY_LENGTH;

    type MasterSecretKey =
        core::MasterSecretKey<
            { Self::PRIVATE_KEY_LENGTH },
            <X25519KeyPair as DhKeyPair<
                { Self::PUBLIC_KEY_LENGTH },
                { Self::PRIVATE_KEY_LENGTH },
            >>::PrivateKey,
        >;

    type UserSecretKey =
        core::UserSecretKey<
            { Self::PRIVATE_KEY_LENGTH },
            <X25519KeyPair as DhKeyPair<
                { Self::PUBLIC_KEY_LENGTH },
                { Self::PRIVATE_KEY_LENGTH },
            >>::PrivateKey,
        >;

    type PublicKey =
        core::PublicKey<
            { Self::PUBLIC_KEY_LENGTH },
            <X25519KeyPair as DhKeyPair<
                { Self::PUBLIC_KEY_LENGTH },
                { Self::PRIVATE_KEY_LENGTH },
            >>::PublicKey,
        >;

    type Encapsulation =
        core::Encapsulation<
            TAG_LENGTH,
            { Self::SYM_KEY_LENGTH },
            { Self::PUBLIC_KEY_LENGTH },
            <X25519KeyPair as DhKeyPair<
                { Self::PUBLIC_KEY_LENGTH },
                { Self::PRIVATE_KEY_LENGTH },
            >>::PublicKey,
        >;

    type SymmetricKey = <DEM as Dem<{ Self::SYM_KEY_LENGTH }>>::Key;

    fn generate_master_keys(
        &self,
        policy: &Policy,
    ) -> Result<(Self::MasterSecretKey, Self::PublicKey), Error> {
        Ok(setup!(
            self.rng.lock().expect("Mutex lock failed!").deref_mut(),
            &partitions::all_partitions(policy)?
                .into_iter()
                .map(|partition| (partition, true))
                .collect()
        ))
    }

    fn update_master_keys(
        &self,
        policy: &Policy,
        msk: &mut Self::MasterSecretKey,
        mpk: &mut Self::PublicKey,
    ) -> Result<(), Error> {
        update!(
            self.rng.lock().expect("Mutex lock failed!").deref_mut(),
            msk,
            mpk,
            &partitions::all_partitions(policy)?
                .into_iter()
                .map(|partition| (partition, true))
                .collect()
        )
    }

    fn generate_user_secret_key(
        &self,
        msk: &Self::MasterSecretKey,
        access_policy: &AccessPolicy,
        policy: &Policy,
    ) -> Result<Self::UserSecretKey, Error> {
        join!(
            self.rng.lock().expect("Mutex lock failed!").deref_mut(),
            msk,
            &partitions::access_policy_to_current_partitions(access_policy, policy, true)?
        )
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
            &partitions::access_policy_to_current_partitions(access_policy, policy, true)?,
            keep_old_accesses
        )
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
        encaps!(
            self.rng.lock().expect("Mutex lock failed!").deref_mut(),
            pk,
            &partitions::access_policy_to_current_partitions(access_policy, policy, false)?
        )
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
        <Aes256GcmCrypto as Dem<{ Self::SYM_KEY_LENGTH }>>::encrypt(
            self.rng.lock().expect("Mutex lock failed!").deref_mut(),
            symmetric_key,
            plaintext,
            authentication_data,
        )
        .map_err(|e| Error::CryptoError(e.to_string()))
    }

    fn decrypt(
        &self,
        symmetric_key: &<DEM as Dem<{ Self::SYM_KEY_LENGTH }>>::Key,
        ciphertext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        <Aes256GcmCrypto as Dem<{ Self::SYM_KEY_LENGTH }>>::decrypt(
            symmetric_key,
            ciphertext,
            authentication_data,
        )
        .map_err(|e| Error::CryptoError(e.to_string()))
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
    { Aes256GcmCrypto::KEY_LENGTH },
    { X25519KeyPair::PUBLIC_KEY_LENGTH },
    { X25519KeyPair::PRIVATE_KEY_LENGTH },
    X25519KeyPair,
    Aes256GcmCrypto,
    CoverCryptX25519Aes256,
>;

/// Convenience type
pub type CleartextHeader =
    crate::core::api::CleartextHeader<{ Aes256GcmCrypto::KEY_LENGTH }, Aes256GcmCrypto>;

/// Convenience type: CoverCryptX25519Aes256 master secret key
pub type MasterSecretKey = <CoverCryptX25519Aes256 as CoverCrypt<
    TAG_LENGTH,
    { Aes256GcmCrypto::KEY_LENGTH },
    { X25519KeyPair::PUBLIC_KEY_LENGTH },
    { X25519KeyPair::PRIVATE_KEY_LENGTH },
    X25519KeyPair,
    Aes256GcmCrypto,
>>::MasterSecretKey;

/// Convenience type: CoverCryptX25519Aes256 public key
pub type PublicKey = <CoverCryptX25519Aes256 as CoverCrypt<
    TAG_LENGTH,
    { Aes256GcmCrypto::KEY_LENGTH },
    { X25519KeyPair::PUBLIC_KEY_LENGTH },
    { X25519KeyPair::PRIVATE_KEY_LENGTH },
    X25519KeyPair,
    Aes256GcmCrypto,
>>::PublicKey;

/// Convenience type: CoverCryptX25519Aes256 user secret key
pub type UserSecretKey = <CoverCryptX25519Aes256 as CoverCrypt<
    TAG_LENGTH,
    { Aes256GcmCrypto::KEY_LENGTH },
    { X25519KeyPair::PUBLIC_KEY_LENGTH },
    { X25519KeyPair::PRIVATE_KEY_LENGTH },
    X25519KeyPair,
    Aes256GcmCrypto,
>>::UserSecretKey;

/// Convenience type: CoverCryptX25519Aes256 encapsulation
pub type Encapsulation = <CoverCryptX25519Aes256 as CoverCrypt<
    TAG_LENGTH,
    { Aes256GcmCrypto::KEY_LENGTH },
    { X25519KeyPair::PUBLIC_KEY_LENGTH },
    { X25519KeyPair::PRIVATE_KEY_LENGTH },
    X25519KeyPair,
    Aes256GcmCrypto,
>>::Encapsulation;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{core::partitions::Partition, CoverCrypt, Error};
    use abe_policy::{AccessPolicy, Attribute, Policy, PolicyAxis};

    fn policy() -> Result<Policy, Error> {
        let sec_level = PolicyAxis::new(
            "Security Level",
            &[
                "Protected",
                "Low Secret",
                "Medium Secret",
                "High Secret",
                "Top Secret",
            ],
            true,
        );
        let department = PolicyAxis::new("Department", &["R&D", "HR", "MKG", "FIN"], false);
        let mut policy = Policy::new(100);
        policy.add_axis(&sec_level)?;
        policy.add_axis(&department)?;
        Ok(policy)
    }

    #[test]
    fn test_update_master_keys() -> Result<(), Error> {
        let mut policy = policy()?;
        let cover_crypt = CoverCryptX25519Aes256::default();
        let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy)?;
        let partitions_msk: Vec<Partition> = msk.x.clone().into_keys().collect();
        let partitions_mpk: Vec<Partition> = mpk.H.clone().into_keys().collect();
        assert_eq!(partitions_msk.len(), partitions_mpk.len());
        for p in &partitions_msk {
            assert!(partitions_mpk.contains(p));
        }
        // rotate he FIN department
        policy.rotate(&Attribute::new("Department", "FIN"))?;
        // update the master keys
        cover_crypt.update_master_keys(&policy, &mut msk, &mut mpk)?;
        let new_partitions_msk: Vec<Partition> = msk.x.clone().into_keys().collect();
        let new_partitions_mpk: Vec<Partition> = mpk.H.clone().into_keys().collect();
        assert_eq!(new_partitions_msk.len(), new_partitions_mpk.len());
        for p in &new_partitions_msk {
            assert!(new_partitions_mpk.contains(p));
        }
        // 5 is the size of the security level axis
        assert_eq!(new_partitions_msk.len(), partitions_msk.len() + 5);
        Ok(())
    }

    #[test]
    fn test_refresh_user_key() -> Result<(), Error> {
        let mut policy = policy()?;
        let cover_crypt = CoverCryptX25519Aes256::default();
        let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy)?;
        let access_policy = AccessPolicy::from_boolean_expression(
            "Department::MKG && Security Level::Medium Secret",
        )?;
        let mut usk = cover_crypt.generate_user_secret_key(&msk, &access_policy, &policy)?;
        let original_usk = usk.clone();
        // rotate he FIN department
        policy.rotate(&Attribute::new("Department", "MKG"))?;
        // update the master keys
        cover_crypt.update_master_keys(&policy, &mut msk, &mut mpk)?;
        // refresh the user key and preserve access to old partitions
        cover_crypt.refresh_user_secret_key(&mut usk, &access_policy, &msk, &policy, true)?;
        // 3 partitions accessed by the user were rotated (MKG Medium Secret and MKG
        // Protected)
        assert_eq!(usk.x.len(), original_usk.x.len() + 3);
        for x_i in &original_usk.x {
            assert!(usk.x.contains(x_i));
        }
        // refresh the user key but do NOT preserve access to old partitions
        cover_crypt.refresh_user_secret_key(&mut usk, &access_policy, &msk, &policy, false)?;
        // the user should still have access to the same number of partitions
        println!("{usk:?}");
        assert_eq!(usk.x.len(), original_usk.x.len());
        for x_i in &original_usk.x {
            assert!(!usk.x.contains(x_i));
        }
        Ok(())
    }

    #[test]
    fn encrypt_decrypt_sym_key() -> Result<(), Error> {
        let mut policy = policy()?;
        policy.rotate(&Attribute::new("Department", "FIN"))?;
        println!("{:?}", &policy);
        let access_policy = (AccessPolicy::new("Department", "R&D")
            | AccessPolicy::new("Department", "FIN"))
            & AccessPolicy::new("Security Level", "Top Secret");
        let cover_crypt = CoverCryptX25519Aes256::default();
        let (msk, mpk) = cover_crypt.generate_master_keys(&policy)?;
        let (sym_key, encrypted_key) = cover_crypt.encaps(
            &policy,
            &mpk,
            &AccessPolicy::from_boolean_expression(
                "Department::R&D && Security Level::Top Secret",
            )?,
        )?;
        let usk = cover_crypt.generate_user_secret_key(&msk, &access_policy, &policy)?;
        let recovered_key = cover_crypt.decaps(&usk, &encrypted_key)?;
        assert_eq!(sym_key, recovered_key, "Wrong decryption of the key!");
        Ok(())
    }

    #[test]
    fn test_single_attribute_in_access_policy() -> Result<(), Error> {
        //
        // Declare policy
        let policy = policy()?;

        //
        // Setup CoverCrypt
        let cover_crypt = CoverCryptX25519Aes256::default();
        let (msk, _master_public_key) = cover_crypt.generate_master_keys(&policy)?;

        //
        // New user secret key
        let _user_key = cover_crypt.generate_user_secret_key(
            &msk,
            &AccessPolicy::from_boolean_expression("Security Level::Top Secret")?,
            &policy,
        )?;

        Ok(())
    }

    #[test]
    fn test_rotate_then_encrypt() -> Result<(), Error> {
        //
        // Declare policy
        let mut policy = policy()?;
        let top_secret_ap = AccessPolicy::from_boolean_expression("Security Level::Top Secret")?;

        //
        // Setup CoverCrypt
        let cover_crypt = CoverCryptX25519Aes256::default();
        let (mut msk, mut master_public_key) = cover_crypt.generate_master_keys(&policy)?;

        //
        // New user secret key
        let mut top_secret_fin_usk = cover_crypt.generate_user_secret_key(
            &msk,
            &AccessPolicy::from_boolean_expression(
                "Security Level::Top Secret && Department::FIN",
            )?,
            &policy,
        )?;

        //
        // Encrypt
        let (_, encrypted_header) = EncryptedHeader::generate(
            &cover_crypt,
            &policy,
            &master_public_key,
            &top_secret_ap,
            None,
            None,
        )?;

        let _plaintext_header =
            encrypted_header.decrypt(&cover_crypt, &top_secret_fin_usk, None)?;

        //
        // Rotate argument (must update master keys)
        policy.rotate(&Attribute::from(("Security Level", "Top Secret")))?;
        cover_crypt.update_master_keys(&policy, &mut msk, &mut master_public_key)?;

        //
        // Encrypt with new attribute
        let (_, encrypted_header) = EncryptedHeader::generate(
            &cover_crypt,
            &policy,
            &master_public_key,
            &top_secret_ap,
            None,
            None,
        )?;

        // Decryption fails without refreshing the user key
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .is_err());

        cover_crypt.refresh_user_secret_key(
            &mut top_secret_fin_usk,
            &AccessPolicy::from_boolean_expression(
                "Security Level::Top Secret && Department::FIN",
            )?,
            &msk,
            &policy,
            false,
        )?;

        // The refreshed key can decrypt the header
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .is_ok());

        Ok(())
    }
}
