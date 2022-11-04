use crate::{
    api::{self, CoverCrypt},
    cover_crypt_core,
    error::Error,
    partitions,
};
use abe_policy::{AccessPolicy, Policy};
use cosmian_crypto_core::{
    asymmetric_crypto::{curve25519::X25519KeyPair, DhKeyPair},
    reexport::rand_core::SeedableRng,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Dem},
    CsRng, KeyTrait,
};
use std::{ops::DerefMut, sync::Mutex};

const TAG_LENGTH: usize = 32;

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
            self.rng.lock().expect("Mutex lock failed!").deref_mut(),
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
            self.rng.lock().expect("Mutex lock failed!").deref_mut(),
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
            self.rng.lock().expect("Mutex lock failed!").deref_mut(),
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
            self.rng.lock().expect("Mutex lock failed!").deref_mut(),
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
            self.rng.lock().expect("Mutex lock failed!").deref_mut(),
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
        authenticated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        <Aes256GcmCrypto as Dem<{ Self::SYM_KEY_LENGTH }>>::encrypt(
            self.rng.lock().expect("Mutex lock failed!").deref_mut(),
            symmetric_key,
            plaintext,
            authenticated_data,
        )
        .map_err(Error::CryptoError)
    }

    fn decrypt(
        &self,
        symmetric_key: &<Self::Dem as Dem<{ Self::SYM_KEY_LENGTH }>>::Key,
        ciphertext: &[u8],
        authenticated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        <Aes256GcmCrypto as Dem<{ Self::SYM_KEY_LENGTH }>>::decrypt(
            symmetric_key,
            ciphertext,
            authenticated_data,
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
    use super::*;
    use crate::{partitions::Partition, CoverCrypt, Error};
    use abe_policy::{AccessPolicy, Attribute, Policy, PolicyAxis};
    use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable};
    use serde::{Deserialize, Serialize};

    fn policy() -> Result<Policy, Error> {
        let sec_level = PolicyAxis::new(
            "Security Level",
            &["Protected", "Confidential", "Top Secret"],
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
        // 3 is the size of the security level axis
        assert_eq!(new_partitions_msk.len(), partitions_msk.len() + 3);
        Ok(())
    }

    #[test]
    fn test_refresh_user_key() -> Result<(), Error> {
        let mut policy = policy()?;
        let cover_crypt = CoverCryptX25519Aes256::default();
        let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy)?;
        let access_policy = AccessPolicy::from_boolean_expression(
            "Department::MKG && Security Level::Confidential",
        )?;
        let mut usk = cover_crypt.generate_user_secret_key(&msk, &access_policy, &policy)?;
        let original_usk = usk.clone();
        // rotate he FIN department
        policy.rotate(&Attribute::new("Department", "MKG"))?;
        // update the master keys
        cover_crypt.update_master_keys(&policy, &mut msk, &mut mpk)?;
        // refresh the user key and preserve access to old partitions
        cover_crypt.refresh_user_secret_key(&mut usk, &access_policy, &msk, &policy, true)?;
        // 2 partitions accessed by the user were rotated (MKG Confidential and MKG
        // Protected)
        assert_eq!(usk.x.len(), original_usk.x.len() + 2);
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
    struct NonRegressionTestVector {
        public_key: String,
        msk: String,
        policy: String,
        user_decryption_key: String,
        user_decryption_key_2: String,
        encrypted_bytes: String,
        plaintext: String,
        additional_data: String,
    }

    #[test]
    fn test_hybrid_encryption_decryption() -> Result<(), Error> {
        //
        // Policy settings
        //
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
        policy.rotate(&Attribute::new("Department", "FIN"))?;
        let access_policy = AccessPolicy::from_boolean_expression(
            "(Department::HR || Department:: FIN) && Security Level::Low Secret",
        )?;

        //
        // CoverCrypt setup
        //
        let cover_crypt = CoverCryptX25519Aes256::default();
        let (msk, mpk) = cover_crypt.generate_master_keys(&policy)?;
        let top_secret_mkg_fin_user =
            cover_crypt.generate_user_secret_key(&msk, &access_policy, &policy)?;

        //
        // Encrypt/decrypt header
        //
        let additional_data = 1u32.to_be_bytes().to_vec();
        let authenticated_data = None;

        let (symmetric_key, encrypted_header) = EncryptedHeader::generate(
            &cover_crypt,
            &policy,
            &mpk,
            &access_policy,
            Some(&additional_data),
            authenticated_data,
        )?;
        let res =
            encrypted_header.decrypt(&cover_crypt, &top_secret_mkg_fin_user, authenticated_data)?;

        assert_eq!(additional_data, res.additional_data);

        let message = b"My secret message";
        // we need mut in the commented lines below
        #[allow(unused_mut)]
        let mut ctx = cover_crypt.encrypt(&symmetric_key, message, authenticated_data)?;

        let res = cover_crypt.decrypt(&symmetric_key, &ctx, authenticated_data)?;

        assert_eq!(message.to_vec(), res);

        //
        // Uncomment the following code to write a new regression vector
        //

        //let mut encrypted_bytes = encrypted_header.try_to_bytes()?;
        //encrypted_bytes.append(&mut ctx);

        //let access_policy_2 = AccessPolicy::new("Security Level", "Medium Secret")
        //& AccessPolicy::new("Department", "MKG");

        //let medium_secret_mkg_user =
        //cover_crypt.generate_user_secret_key(&msk, &access_policy_2, &policy)?;

        //let reg_vectors = NonRegressionTestVector {
        //public_key: hex::encode(mpk.try_to_bytes()?),
        //msk: hex::encode(msk.try_to_bytes()?),
        //policy: hex::encode(serde_json::to_vec(&policy)?),
        //user_decryption_key: hex::encode(top_secret_mkg_fin_user.try_to_bytes()?),
        //user_decryption_key_2: hex::encode(medium_secret_mkg_user.try_to_bytes()?),
        //encrypted_bytes: hex::encode(encrypted_bytes),
        //plaintext: hex::encode(message),
        //additional_data: hex::encode(additional_data),
        //};

        //std::fs::write(
        //"non_regression_vector.json",
        //serde_json::to_string(&reg_vectors).unwrap(),
        //)
        //.unwrap();

        Ok(())
    }

    #[test]
    fn test_non_regregression() {
        let reg_vector: NonRegressionTestVector =
            serde_json::from_str(include_str!("../../non_regression_vector.json")).unwrap();
        let top_secret_mkg_fin_user =
            UserSecretKey::try_from_bytes(&hex::decode(reg_vector.user_decryption_key).unwrap())
                .unwrap();
        let medium_secret_mkg_user =
            UserSecretKey::try_from_bytes(&hex::decode(reg_vector.user_decryption_key_2).unwrap())
                .unwrap();
        let encrypted_bytes = &hex::decode(reg_vector.encrypted_bytes).unwrap();
        let mut de = Deserializer::new(encrypted_bytes.as_slice());
        let encrypted_header = EncryptedHeader::read(&mut de).unwrap();
        let ciphertext = de.finalize();
        let cover_crypt = CoverCryptX25519Aes256::default();
        assert!(encrypted_header
            .decrypt(&cover_crypt, &medium_secret_mkg_user, None)
            .is_err());
        let cleartext_header = encrypted_header
            .decrypt(&cover_crypt, &top_secret_mkg_fin_user, None)
            .unwrap();
        let plaintext = cover_crypt
            .decrypt(&cleartext_header.symmetric_key, &ciphertext, None)
            .unwrap();
        assert_eq!(hex::decode(&reg_vector.plaintext).unwrap(), plaintext);
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

        let _cleartext_header =
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

        cover_crypt.refresh_user_secret_key(&mut top_secret_fin_usk, 
            &AccessPolicy::from_boolean_expression(
                "Security Level::Top Secret && Department::FIN",
            )?,
            &msk,
            &policy,
            false
        )?;

        // The refreshed key can decrypt the header
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .is_ok());

        Ok(())
    }
}
