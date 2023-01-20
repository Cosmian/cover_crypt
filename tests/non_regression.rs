#![cfg(feature = "interface")]

use abe_policy::{AccessPolicy, Attribute, EncryptionHint, Policy, PolicyAxis};
use cosmian_cover_crypt::{
    statics::{CoverCryptX25519Aes256, EncryptedHeader, MasterSecretKey, PublicKey, UserSecretKey},
    CoverCrypt, Error,
};
use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable};

pub fn policy() -> Result<Policy, Error> {
    let sec_level = PolicyAxis::new(
        "Security Level",
        vec![
            ("Protected", EncryptionHint::Classic),
            ("Confidential", EncryptionHint::Classic),
            ("Top Secret", EncryptionHint::Hybridized),
        ],
        true,
    );
    let department = PolicyAxis::new(
        "Department",
        vec![
            ("R&D", EncryptionHint::Classic),
            ("HR", EncryptionHint::Classic),
            ("MKG", EncryptionHint::Classic),
            ("FIN", EncryptionHint::Classic),
        ],
        false,
    );
    let mut policy = Policy::new(100);
    policy.add_axis(sec_level)?;
    policy.add_axis(department)?;
    Ok(policy)
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
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
        assert_eq!(plaintext_header.metadata, header_metadata);
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
    ) -> Result<EncryptionTestVector, Error> {
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
        Ok(EncryptionTestVector {
            encryption_policy: encryption_policy.to_string(),
            plaintext: base64::encode(plaintext),
            ciphertext: base64::encode(encrypted_bytes),
            header_metadata,
            authentication_data,
        })
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct UserSecretKeyTestVector {
    access_policy: String,
    key: String,
}

impl UserSecretKeyTestVector {
    pub fn new(msk: &MasterSecretKey, policy: &Policy, access_policy: &str) -> Result<Self, Error> {
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

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct NonRegressionTestVector {
    public_key: String,
    master_secret_key: String,
    policy: String,
    top_secret_mkg_fin_key: UserSecretKeyTestVector,
    confidential_mkg_key: UserSecretKeyTestVector,
    top_secret_fin_key: UserSecretKeyTestVector,
    protected_mkg_test_vector: EncryptionTestVector,
    top_secret_mkg_test_vector: EncryptionTestVector,
    protected_fin_test_vector: EncryptionTestVector,
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

        let reg_vectors = NonRegressionTestVector {
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
            confidential_mkg_key: UserSecretKeyTestVector::new(
                &msk,
                &policy,
                "Security Level::Confidential && Department::MKG",
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

            protected_mkg_test_vector: EncryptionTestVector::new(
                &mpk,
                &policy,
                "Department::MKG && Security Level::Protected",
                "protected_mkg_plaintext",
                Some(&header_metadata),
                None,
            )?,

            protected_fin_test_vector: EncryptionTestVector::new(
                &mpk,
                &policy,
                "Department::FIN && Security Level::Protected",
                "protected_fin_plaintext",
                None,
                None,
            )?,
        };
        Ok(reg_vectors)
    }

    fn verify(&self) -> Result<(), Error> {
        // top_secret_fin_key
        self.protected_fin_test_vector
            .decrypt(&self.top_secret_fin_key.key)?;
        assert!(self
            .protected_mkg_test_vector
            .decrypt(&self.top_secret_fin_key.key)
            .is_err());
        assert!(self
            .top_secret_mkg_test_vector
            .decrypt(&self.top_secret_fin_key.key)
            .is_err());

        // top_secret_mkg_fin_key
        self.protected_fin_test_vector
            .decrypt(&self.top_secret_mkg_fin_key.key)?;
        self.protected_mkg_test_vector
            .decrypt(&self.top_secret_mkg_fin_key.key)?;
        self.top_secret_mkg_test_vector
            .decrypt(&self.top_secret_mkg_fin_key.key)?;

        // confidential_mkg_key
        assert!(self
            .protected_fin_test_vector
            .decrypt(&self.confidential_mkg_key.key)
            .is_err());
        self.protected_mkg_test_vector
            .decrypt(&self.confidential_mkg_key.key)?;
        assert!(self
            .top_secret_mkg_test_vector
            .decrypt(&self.confidential_mkg_key.key)
            .is_err());
        Ok(())
    }
}

#[test]
fn test_generate_non_regression_vector() -> Result<(), Error> {
    let _reg_vector = NonRegressionTestVector::new()?;
    // uncomment this to regenerate new test vector
    //std::fs::write(
    //"tests_data/non_regression_vector.json",
    //serde_json::to_string(&_reg_vector).unwrap(),
    //)
    //.unwrap();

    Ok(())
}

#[test]
fn test_non_regression() -> Result<(), Error> {
    let reg_vector: NonRegressionTestVector =
        serde_json::from_str(include_str!("../tests_data/non_regression_vector.json"))?;
    reg_vector.verify()
}
