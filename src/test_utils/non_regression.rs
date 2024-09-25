use base64::{
    alphabet::STANDARD,
    engine::{GeneralPurpose, GeneralPurposeConfig},
    Engine,
};
use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable};

use super::policy;
use crate::{
    abe_policy::{AccessPolicy, Policy},
    core::{MasterPublicKey, MasterSecretKey, UserSecretKey},
    Covercrypt, EncryptedHeader, Error,
};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EncryptionTestVector {
    encryption_policy: String,
    plaintext: String,
    ciphertext: String,
    header_metadata: String,
    authentication_data: String,
}

impl EncryptionTestVector {
    pub fn decrypt(&self, user_key: &str) -> Result<(), Error> {
        let config: GeneralPurposeConfig = GeneralPurposeConfig::default();
        let transcoder: GeneralPurpose = GeneralPurpose::new(&STANDARD, config);

        let user_key = UserSecretKey::deserialize(&transcoder.decode(user_key).unwrap())?;

        let ciphertext = transcoder.decode(&self.ciphertext).unwrap();
        let expected_plaintext = transcoder.decode(&self.plaintext).unwrap();

        let header_metadata = if !self.header_metadata.is_empty() {
            Some(transcoder.decode(&self.header_metadata).unwrap())
        } else {
            None
        };

        let authentication_data = if !self.authentication_data.is_empty() {
            transcoder.decode(&self.authentication_data).unwrap()
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
        let cover_crypt = Covercrypt::default();

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
        mpk: &MasterPublicKey,
        policy: &Policy,
        encryption_policy: &str,
        plaintext: &str,
        header_metadata: Option<&[u8]>,
        authentication_data: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let config: GeneralPurposeConfig = GeneralPurposeConfig::default();
        let transcoder: GeneralPurpose = GeneralPurpose::new(&STANDARD, config);

        let cover_crypt = Covercrypt::default();
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
        let mut encrypted_bytes = encrypted_header.serialize()?;
        encrypted_bytes.append(&mut aes_ciphertext);
        let header_metadata = match header_metadata {
            Some(ad) => transcoder.encode(ad),
            None => String::new(),
        };
        let authentication_data = match authentication_data {
            Some(ad) => transcoder.encode(ad),
            None => String::new(),
        };
        Ok(Self {
            encryption_policy: encryption_policy.to_string(),
            plaintext: transcoder.encode(plaintext),
            ciphertext: transcoder.encode(encrypted_bytes),
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
    pub fn new(msk: &MasterSecretKey, access_policy: &str) -> Result<Self, Error> {
        let config: GeneralPurposeConfig = GeneralPurposeConfig::default();
        let transcoder: GeneralPurpose = GeneralPurpose::new(&STANDARD, config);
        Ok(Self {
            key: transcoder.encode(
                Covercrypt::default()
                    .generate_user_secret_key(
                        msk,
                        &AccessPolicy::from_boolean_expression(access_policy)?,
                        policy,
                    )?
                    .serialize()?,
            ),
            access_policy: access_policy.to_string(),
        })
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct NonRegressionTestVector {
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
        let config: GeneralPurposeConfig = GeneralPurposeConfig::default();
        let transcoder: GeneralPurpose = GeneralPurpose::new(&STANDARD, config);

        //
        // Policy settings
        //
        let policy = policy()?;
        //policy.rotate(&Attribute::new("Department", "FIN"))?;

        //
        // Covercrypt setup
        //
        let cover_crypt = Covercrypt::default();
        let (msk, mpk) = cover_crypt.generate_master_keys(&policy)?;

        //
        // Encryption header metadata
        let header_metadata = 1u32.to_be_bytes().to_vec();
        let authentication_data = 2u32.to_be_bytes().to_vec();

        let reg_vectors = Self {
            public_key: transcoder.encode(mpk.serialize()?),
            master_secret_key: transcoder.encode(msk.serialize()?),
            policy: transcoder.encode(<Vec<u8>>::try_from(&policy).unwrap()),
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

    pub fn verify(&self) {
        // top_secret_fin_key
        self.low_secret_fin_test_vector
            .decrypt(&self.top_secret_fin_key.key)
            .unwrap();
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
            .decrypt(&self.top_secret_mkg_fin_key.key)
            .unwrap();
        self.low_secret_mkg_test_vector
            .decrypt(&self.top_secret_mkg_fin_key.key)
            .unwrap();
        self.top_secret_mkg_test_vector
            .decrypt(&self.top_secret_mkg_fin_key.key)
            .unwrap();

        assert!(self
            .low_secret_fin_test_vector
            .decrypt(&self.medium_secret_mkg_key.key)
            .is_err());
        self.low_secret_mkg_test_vector
            .decrypt(&self.medium_secret_mkg_key.key)
            .unwrap();
        assert!(self
            .top_secret_mkg_test_vector
            .decrypt(&self.medium_secret_mkg_key.key)
            .is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_non_regression_vector() -> Result<(), Error> {
        let _reg_vector = NonRegressionTestVector::new()?;
        std::fs::write(
            "target/non_regression_vector.json",
            serde_json::to_string(&_reg_vector).unwrap(),
        )
        .unwrap();

        Ok(())
    }

    #[test]
    fn test_non_regression() {
        let reg_vector: NonRegressionTestVector =
            serde_json::from_str(include_str!("./tests_data/non_regression_vector.json")).unwrap();
        reg_vector.verify();
    }
}
