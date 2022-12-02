use std::sync::Mutex;

use abe_policy::{AccessPolicy, Policy};
use cosmian_crypto_core::{
    asymmetric_crypto::{curve25519::X25519KeyPair, DhKeyPair},
    reexport::rand_core::SeedableRng,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Dem},
    CsRng, KeyTrait,
};

use crate::{
    api::{self, CoverCrypt},
    cover_crypt_core,
    error::Error,
    partitions,
};

const TAG_LENGTH: usize = 32;

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
        { Aes256GcmCrypto::KEY_LENGTH },
        { X25519KeyPair::PUBLIC_KEY_LENGTH },
        { X25519KeyPair::PRIVATE_KEY_LENGTH },
        X25519KeyPair,
        Aes256GcmCrypto,
    > for CoverCryptX25519Aes256
{
    type Dem = Aes256GcmCrypto;
    type Encapsulation =
        cover_crypt_core::Encapsulation<
            TAG_LENGTH,
            { Self::SYM_KEY_LENGTH },
            { Self::PUBLIC_KEY_LENGTH },
            <Self::Dem as Dem<{ Self::SYM_KEY_LENGTH }>>::Key,
            <X25519KeyPair as DhKeyPair<
                { Self::PUBLIC_KEY_LENGTH },
                { Self::PRIVATE_KEY_LENGTH },
            >>::PublicKey,
        >;
    type MasterSecretKey =
        cover_crypt_core::MasterSecretKey<
            { Self::PRIVATE_KEY_LENGTH },
            <X25519KeyPair as DhKeyPair<
                { Self::PUBLIC_KEY_LENGTH },
                { Self::PRIVATE_KEY_LENGTH },
            >>::PrivateKey,
        >;
    type PublicKey =
        cover_crypt_core::PublicKey<
            { Self::PUBLIC_KEY_LENGTH },
            <X25519KeyPair as DhKeyPair<
                { Self::PUBLIC_KEY_LENGTH },
                { Self::PRIVATE_KEY_LENGTH },
            >>::PublicKey,
        >;
    type UserSecretKey =
        cover_crypt_core::UserSecretKey<
            { Self::PRIVATE_KEY_LENGTH },
            <X25519KeyPair as DhKeyPair<
                { Self::PUBLIC_KEY_LENGTH },
                { Self::PRIVATE_KEY_LENGTH },
            >>::PrivateKey,
        >;

    fn generate_master_keys(
        &self,
        policy: &Policy,
    ) -> Result<(Self::MasterSecretKey, Self::PublicKey), Error> {
        Ok(cover_crypt_core::setup::<
            { Self::PUBLIC_KEY_LENGTH },
            { Self::PRIVATE_KEY_LENGTH },
            CsRng,
            X25519KeyPair,
        >(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            &partitions::all_partitions(policy)?,
        ))
    }

    fn update_master_keys(
        &self,
        policy: &Policy,
        msk: &mut Self::MasterSecretKey,
        mpk: &mut Self::PublicKey,
    ) -> Result<(), Error> {
        cover_crypt_core::update::<
            { Self::PUBLIC_KEY_LENGTH },
            { Self::PRIVATE_KEY_LENGTH },
            CsRng,
            X25519KeyPair,
        >(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            mpk,
            &partitions::all_partitions(policy)?,
        )
    }

    fn generate_user_secret_key(
        &self,
        msk: &Self::MasterSecretKey,
        access_policy: &AccessPolicy,
        policy: &Policy,
    ) -> Result<Self::UserSecretKey, Error> {
        cover_crypt_core::join::<
            { Self::PUBLIC_KEY_LENGTH },
            { Self::PRIVATE_KEY_LENGTH },
            CsRng,
            X25519KeyPair,
        >(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            msk,
            &partitions::access_policy_to_current_partitions(access_policy, policy, true)?,
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
        cover_crypt_core::refresh::<
            { Self::PRIVATE_KEY_LENGTH },
            <X25519KeyPair as DhKeyPair<
                { Self::PUBLIC_KEY_LENGTH },
                { Self::PRIVATE_KEY_LENGTH },
            >>::PrivateKey,
        >(
            msk,
            usk,
            &partitions::access_policy_to_current_partitions(access_policy, policy, true)?,
            keep_old_accesses,
        )
    }

    fn encaps(
        &self,
        policy: &Policy,
        pk: &Self::PublicKey,
        access_policy: &AccessPolicy,
    ) -> Result<
        (
            <Self::Dem as Dem<{ Self::SYM_KEY_LENGTH }>>::Key,
            Self::Encapsulation,
        ),
        Error,
    > {
        let sym_key = <Self::Dem as Dem<{ Self::SYM_KEY_LENGTH }>>::Key::new(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
        );
        let encapsulation = cover_crypt_core::encaps::<
            TAG_LENGTH,
            { Self::SYM_KEY_LENGTH },
            { Self::PUBLIC_KEY_LENGTH },
            { Self::PRIVATE_KEY_LENGTH },
            CsRng,
            <Self::Dem as Dem<{ Self::SYM_KEY_LENGTH }>>::Key,
            X25519KeyPair,
        >(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            pk,
            &partitions::access_policy_to_current_partitions(access_policy, policy, false)?,
            &sym_key,
        )?;
        Ok((sym_key, encapsulation))
    }

    fn decaps(
        &self,
        usk: &Self::UserSecretKey,
        encapsulation: &Self::Encapsulation,
    ) -> Result<<Self::Dem as Dem<{ Self::SYM_KEY_LENGTH }>>::Key, Error> {
        cover_crypt_core::decaps::<
            TAG_LENGTH,
            { Self::SYM_KEY_LENGTH },
            { Self::PUBLIC_KEY_LENGTH },
            { Self::PRIVATE_KEY_LENGTH },
            <Self::Dem as Dem<{ Self::SYM_KEY_LENGTH }>>::Key,
            X25519KeyPair,
        >(usk, encapsulation)
    }

    fn encrypt(
        &self,
        symmetric_key: &<Self::Dem as Dem<{ Self::SYM_KEY_LENGTH }>>::Key,
        plaintext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        <Aes256GcmCrypto as Dem<{ Self::SYM_KEY_LENGTH }>>::encrypt(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            symmetric_key,
            plaintext,
            authentication_data,
        )
        .map_err(Error::CryptoError)
    }

    fn decrypt(
        &self,
        symmetric_key: &<Self::Dem as Dem<{ Self::SYM_KEY_LENGTH }>>::Key,
        ciphertext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        <Aes256GcmCrypto as Dem<{ Self::SYM_KEY_LENGTH }>>::decrypt(
            symmetric_key,
            ciphertext,
            authentication_data,
        )
        .map_err(Error::CryptoError)
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
pub type EncryptedHeader = api::EncryptedHeader<
    TAG_LENGTH,
    { Aes256GcmCrypto::KEY_LENGTH },
    { X25519KeyPair::PUBLIC_KEY_LENGTH },
    { X25519KeyPair::PRIVATE_KEY_LENGTH },
    X25519KeyPair,
    Aes256GcmCrypto,
    CoverCryptX25519Aes256,
>;

pub type ClearTextHeader = api::CleartextHeader<{ Aes256GcmCrypto::KEY_LENGTH }, Aes256GcmCrypto>;

/// Convenience type: `CoverCryptX25519Aes256` master secret key
pub type MasterSecretKey = <CoverCryptX25519Aes256 as CoverCrypt<
    TAG_LENGTH,
    { Aes256GcmCrypto::KEY_LENGTH },
    { X25519KeyPair::PUBLIC_KEY_LENGTH },
    { X25519KeyPair::PRIVATE_KEY_LENGTH },
    X25519KeyPair,
    Aes256GcmCrypto,
>>::MasterSecretKey;

/// Convenience type: `CoverCryptX25519Aes256` public key
pub type PublicKey = <CoverCryptX25519Aes256 as CoverCrypt<
    TAG_LENGTH,
    { Aes256GcmCrypto::KEY_LENGTH },
    { X25519KeyPair::PUBLIC_KEY_LENGTH },
    { X25519KeyPair::PRIVATE_KEY_LENGTH },
    X25519KeyPair,
    Aes256GcmCrypto,
>>::PublicKey;

/// Convenience type: `CoverCryptX25519Aes256` user secret key
pub type UserSecretKey = <CoverCryptX25519Aes256 as CoverCrypt<
    TAG_LENGTH,
    { Aes256GcmCrypto::KEY_LENGTH },
    { X25519KeyPair::PUBLIC_KEY_LENGTH },
    { X25519KeyPair::PRIVATE_KEY_LENGTH },
    X25519KeyPair,
    Aes256GcmCrypto,
>>::UserSecretKey;

/// Convenience type: `CoverCryptX25519Aes256` encapsulation
pub type Encapsulation = <CoverCryptX25519Aes256 as CoverCrypt<
    TAG_LENGTH,
    { Aes256GcmCrypto::KEY_LENGTH },
    { X25519KeyPair::PUBLIC_KEY_LENGTH },
    { X25519KeyPair::PRIVATE_KEY_LENGTH },
    X25519KeyPair,
    Aes256GcmCrypto,
>>::Encapsulation;

pub type CoverCryptDem = <CoverCryptX25519Aes256 as CoverCrypt<
    TAG_LENGTH,
    { Aes256GcmCrypto::KEY_LENGTH },
    { X25519KeyPair::PUBLIC_KEY_LENGTH },
    { X25519KeyPair::PRIVATE_KEY_LENGTH },
    X25519KeyPair,
    Aes256GcmCrypto,
>>::Dem;

pub type SymmetricKey = <CoverCryptDem as Dem<{ CoverCryptDem::KEY_LENGTH }>>::Key;

#[cfg(test)]
mod tests {
    use abe_policy::{AccessPolicy, Attribute, Policy, PolicyAxis};
    use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable};
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::{partitions::Partition, CoverCrypt, Error};

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

    #[derive(Debug, Serialize, Deserialize)]
    struct EncryptionTestVector {
        encryption_policy: String,
        plaintext: String,
        ciphertext: String,
        header_metadata: String,
        authentication_data: String,
    }

    impl EncryptionTestVector {
        fn decrypt(&self, user_key: &str) -> Result<(), Error> {
            let user_key = UserSecretKey::try_from_bytes(&base64::decode(user_key).unwrap())?;

            let ciphertext = base64::decode(&self.ciphertext).unwrap();
            let expected_plaintext = base64::decode(&self.plaintext).unwrap();

            let header_metadata = if !self.header_metadata.is_empty() {
                base64::decode(&self.header_metadata).unwrap()
            } else {
                vec![]
            };

            let authentication_data = if !self.authentication_data.is_empty() {
                base64::decode(&self.authentication_data).unwrap()
            } else {
                vec![]
            };
            let authentication_data = if authentication_data.is_empty() {
                None
            } else {
                Some(authentication_data.as_slice())
            };

            let mut de = Deserializer::new(ciphertext.as_slice());
            let encrypted_header = EncryptedHeader::read(&mut de)?;
            let ciphertext = de.finalize();
            let cover_crypt = CoverCryptX25519Aes256::default();

            let plaintext_header =
                encrypted_header.decrypt(&cover_crypt, &user_key, authentication_data)?;
            assert_eq!(plaintext_header.additional_data, header_metadata);
            let plaintext = cover_crypt.decrypt(
                &plaintext_header.symmetric_key,
                &ciphertext,
                authentication_data,
            )?;
            assert_eq!(expected_plaintext, plaintext);

            Ok(())
        }

        pub fn new(
            mpk: &PublicKey,
            policy: &Policy,
            encryption_policy: &str,
            plaintext: &str,
            header_metadata: Option<&[u8]>,
            authentication_data: Option<&[u8]>,
        ) -> Result<Self, Error> {
            let cover_crypt = CoverCryptX25519Aes256::default();
            let (symmetric_key, encrypted_header) = EncryptedHeader::generate(
                &cover_crypt,
                policy,
                mpk,
                &AccessPolicy::from_boolean_expression(encryption_policy)?,
                header_metadata,
                authentication_data,
            )?;

            let mut aes_ciphertext =
                cover_crypt.encrypt(&symmetric_key, plaintext.as_bytes(), authentication_data)?;
            let mut encrypted_bytes = encrypted_header.try_to_bytes()?;
            encrypted_bytes.append(&mut aes_ciphertext);
            let header_metadata = match header_metadata {
                Some(ad) => base64::encode(ad),
                None => String::new(),
            };
            let authentication_data = match authentication_data {
                Some(ad) => base64::encode(ad),
                None => String::new(),
            };
            Ok(Self {
                encryption_policy: encryption_policy.to_string(),
                plaintext: base64::encode(plaintext),
                ciphertext: base64::encode(encrypted_bytes),
                header_metadata,
                authentication_data,
            })
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct UserSecretKeyTestVector {
        access_policy: String,
        key: String,
    }
    impl UserSecretKeyTestVector {
        pub fn new(
            msk: &MasterSecretKey,
            policy: &Policy,
            access_policy: &str,
        ) -> Result<Self, Error> {
            Ok(Self {
                key: base64::encode(
                    CoverCryptX25519Aes256::default()
                        .generate_user_secret_key(
                            msk,
                            &AccessPolicy::from_boolean_expression(access_policy)?,
                            policy,
                        )?
                        .try_to_bytes()?,
                ),
                access_policy: access_policy.to_string(),
            })
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct NonRegressionTestVector {
        public_key: String,
        master_secret_key: String,
        policy: String,
        top_secret_mkg_fin_key: UserSecretKeyTestVector,
        medium_secret_mkg_key: UserSecretKeyTestVector,
        top_secret_fin_key: UserSecretKeyTestVector,
        low_secret_mkg_test_vector: EncryptionTestVector,
        top_secret_mkg_test_vector: EncryptionTestVector,
        low_secret_fin_test_vector: EncryptionTestVector,
    }

    impl NonRegressionTestVector {
        pub fn new() -> Result<Self, Error> {
            //
            // Policy settings
            //
            let mut policy = policy()?;
            policy.rotate(&Attribute::new("Department", "FIN"))?;

            //
            // CoverCrypt setup
            //
            let cover_crypt = CoverCryptX25519Aes256::default();
            let (msk, mpk) = cover_crypt.generate_master_keys(&policy)?;

            //
            // Encryption header metadata
            let header_metadata = 1u32.to_be_bytes().to_vec();
            let authentication_data = 2u32.to_be_bytes().to_vec();

            let reg_vectors = Self {
                public_key: base64::encode(mpk.try_to_bytes()?),
                master_secret_key: base64::encode(msk.try_to_bytes()?),
                policy: base64::encode(serde_json::to_vec(&policy)?),
                //
                // Create user decryption keys
                top_secret_mkg_fin_key: UserSecretKeyTestVector::new(
                    &msk,
                    &policy,
                    "(Department::MKG || Department:: FIN) && Security Level::Top Secret",
                )?,
                medium_secret_mkg_key: UserSecretKeyTestVector::new(
                    &msk,
                    &policy,
                    "Security Level::Medium Secret && Department::MKG",
                )?,
                top_secret_fin_key: UserSecretKeyTestVector::new(
                    &msk,
                    &policy,
                    "Security Level::Top Secret && Department::FIN",
                )?,
                //
                // Generate ciphertexts
                top_secret_mkg_test_vector: EncryptionTestVector::new(
                    &mpk,
                    &policy,
                    "Department::MKG && Security Level::Top Secret",
                    "top_secret_mkg_plaintext",
                    Some(&header_metadata),
                    Some(&authentication_data),
                )?,

                low_secret_mkg_test_vector: EncryptionTestVector::new(
                    &mpk,
                    &policy,
                    "Department::MKG && Security Level::Low Secret",
                    "low_secret_mkg_plaintext",
                    Some(&header_metadata),
                    None,
                )?,

                low_secret_fin_test_vector: EncryptionTestVector::new(
                    &mpk,
                    &policy,
                    "Department::FIN && Security Level::Low Secret",
                    "low_secret_fin_plaintext",
                    None,
                    None,
                )?,
            };
            Ok(reg_vectors)
        }

        fn verify(&self) -> Result<(), Error> {
            // top_secret_fin_key
            self.low_secret_fin_test_vector
                .decrypt(&self.top_secret_fin_key.key)?;
            assert!(self
                .low_secret_mkg_test_vector
                .decrypt(&self.top_secret_fin_key.key)
                .is_err());
            assert!(self
                .top_secret_mkg_test_vector
                .decrypt(&self.top_secret_fin_key.key)
                .is_err());

            // top_secret_mkg_fin_key
            self.low_secret_fin_test_vector
                .decrypt(&self.top_secret_mkg_fin_key.key)?;
            self.low_secret_mkg_test_vector
                .decrypt(&self.top_secret_mkg_fin_key.key)?;
            self.top_secret_mkg_test_vector
                .decrypt(&self.top_secret_mkg_fin_key.key)?;

            // medium_secret_mkg_key
            assert!(self
                .low_secret_fin_test_vector
                .decrypt(&self.medium_secret_mkg_key.key)
                .is_err());
            self.low_secret_mkg_test_vector
                .decrypt(&self.medium_secret_mkg_key.key)?;
            assert!(self
                .top_secret_mkg_test_vector
                .decrypt(&self.medium_secret_mkg_key.key)
                .is_err());
            Ok(())
        }
    }

    #[test]
    fn test_generate_non_regression_vector() -> Result<(), Error> {
        let reg_vector = NonRegressionTestVector::new()?;

        // this non-regression vector will be used later by other projects
        std::fs::write(
            "target/non_regression_vector.json",
            serde_json::to_string(&reg_vector).unwrap(),
        )
        .unwrap();

        Ok(())
    }

    #[test]
    fn test_non_regression() -> Result<(), Error> {
        let reg_vector: NonRegressionTestVector =
            serde_json::from_str(include_str!("../../tests_data/non_regression_vector.json"))?;
        reg_vector.verify()
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
