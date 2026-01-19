use cosmian_crypto_core::{
    kdf256, Aes256Gcm, CryptoCoreError, Dem, FixedSizeCBytes, Instantiable, Nonce,
    RandomFixedSizeCBytes, Secret, SymmetricKey,
};

use crate::{
    abe::{
        core::{XEnc, SHARED_SECRET_LENGTH},
        traits::KemAc,
        AccessPolicy, Covercrypt, MasterPublicKey, UserSecretKey,
    },
    Error,
};

/// Encrypted header holding a `Covercrypt` encapsulation of a 256-byte secret, and metadata
/// encrypted under the scheme AES256Gcm using a key derived from the encapsulated secret.
#[derive(Debug, PartialEq)]
pub struct EncryptedHeader {
    pub encapsulation: XEnc,
    pub encrypted_metadata: Option<Vec<u8>>,
}

impl EncryptedHeader {
    /// Generates a new encrypted header for a random secret and the given metadata.
    /// Returns the encrypted header along with the secret.
    ///
    /// - `cc`                  : `Covercrypt` object
    /// - `mpk`                 : `Covercrypt` public key
    /// - `ap`                  : access policy used for the encapsulation
    /// - `header_metadata`     : additional data symmetrically encrypted in the header
    /// - `authentication_data` : authentication data used in the DEM encryption
    pub fn generate(
        cc: &Covercrypt,
        mpk: &MasterPublicKey,
        ap: &AccessPolicy,
        metadata: Option<&[u8]>,
        authentication_data: Option<&[u8]>,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, Self), Error> {
        let (seed, encapsulation) = cc.encaps(mpk, ap)?;

        let encrypted_metadata = metadata
            .map(|bytes| {
                let key = SymmetricKey::derive(&seed, &[0u8])?;
                let nonce = Nonce::new(&mut *cc.rng());
                let ctx = Aes256Gcm::new(&key).encrypt(&nonce, bytes, authentication_data)?;
                Ok::<_, Error>([nonce.as_bytes(), &ctx].concat())
            })
            .transpose()?;

        let mut secret = Secret::default();
        kdf256!(&mut *secret, &*seed, &[1u8]);

        Ok((
            secret,
            Self {
                encapsulation,
                encrypted_metadata,
            },
        ))
    }

    /// Decrypts the header with the given user secret key.
    ///
    /// - `cc`                  : `Covercrypt` object
    /// - `usk`                 : `Covercrypt` user secret key
    /// - `authentication_data` : authentication data used in the DEM encryption
    pub fn decrypt(
        &self,
        cc: &Covercrypt,
        usk: &UserSecretKey,
        authentication_data: Option<&[u8]>,
    ) -> Result<Option<CleartextHeader>, Error> {
        cc.decaps(usk, &self.encapsulation)?
            .map(|seed| {
                let metadata = self
                    .encrypted_metadata
                    .as_ref()
                    .map(|ctx| {
                        if ctx.len() < Aes256Gcm::NONCE_LENGTH {
                            Err(CryptoCoreError::CiphertextTooSmallError {
                                ciphertext_len: ctx.len(),
                                min: Aes256Gcm::NONCE_LENGTH as u64,
                            })
                        } else {
                            let key = SymmetricKey::derive(&seed, &[0u8])?;
                            Aes256Gcm::new(&key).decrypt(
                                &Nonce::try_from_slice(&ctx[..Aes256Gcm::NONCE_LENGTH])?,
                                &ctx[Aes256Gcm::NONCE_LENGTH..],
                                authentication_data,
                            )
                        }
                    })
                    .transpose()?;

                let mut secret = Secret::<SHARED_SECRET_LENGTH>::default();
                kdf256!(&mut *secret, &*seed, &[1u8]);

                Ok(CleartextHeader { secret, metadata })
            })
            .transpose()
    }
}

/// Structure containing all data encrypted in an `EncryptedHeader`.
#[derive(Debug, PartialEq, Eq)]
pub struct CleartextHeader {
    pub secret: Secret<SHARED_SECRET_LENGTH>,
    pub metadata: Option<Vec<u8>>,
}

mod serialization {

    use super::*;
    use cosmian_crypto_core::bytes_ser_de::{
        to_leb128_len, Deserializer, Serializable, Serializer,
    };

    impl Serializable for EncryptedHeader {
        type Error = Error;

        fn length(&self) -> usize {
            self.encapsulation.length()
                + if let Some(metadata) = &self.encrypted_metadata {
                    to_leb128_len(metadata.len()) + metadata.len()
                } else {
                    1
                }
        }

        fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
            let mut n = self.encapsulation.write(ser)?;
            match &self.encrypted_metadata {
                Some(bytes) => n += ser.write_vec(bytes)?,
                None => n += ser.write_vec(&[])?,
            }
            Ok(n)
        }

        fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
            let encapsulation = de.read::<XEnc>()?;
            let ciphertext = de.read_vec()?;
            let encrypted_metadata = if ciphertext.is_empty() {
                None
            } else {
                Some(ciphertext)
            };
            Ok(Self {
                encapsulation,
                encrypted_metadata,
            })
        }
    }

    impl Serializable for CleartextHeader {
        type Error = Error;

        fn length(&self) -> usize {
            SHARED_SECRET_LENGTH
                + to_leb128_len(
                    self.metadata
                        .as_ref()
                        .map(std::vec::Vec::len)
                        .unwrap_or_default(),
                )
                + self
                    .metadata
                    .as_ref()
                    .map(std::vec::Vec::len)
                    .unwrap_or_default()
        }

        fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
            let mut n = ser.write_array(&self.secret[..SHARED_SECRET_LENGTH])?;
            match &self.metadata {
                Some(bytes) => n += ser.write_vec(bytes)?,
                None => n += ser.write_vec(&[])?,
            }
            Ok(n)
        }

        fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
            let seed =
                Secret::from_unprotected_bytes(&mut de.read_array::<SHARED_SECRET_LENGTH>()?);
            let metadata = de.read_vec()?;
            let metadata = if metadata.is_empty() {
                None
            } else {
                Some(metadata)
            };
            Ok(Self {
                secret: seed,
                metadata,
            })
        }
    }

    #[test]
    fn test_ser() {
        use crate::test_utils::cc_keygen;
        use cosmian_crypto_core::bytes_ser_de::test_serialization;

        let cc = Covercrypt::default();
        let (mut msk, mpk) = cc_keygen(&cc, false).unwrap();

        let ap = AccessPolicy::parse("(DPT::MKG || DPT::FIN) && SEC::TOP").unwrap();
        let usk = cc.generate_user_secret_key(&mut msk, &ap).unwrap();

        //
        // Simple ciphertext.
        //

        let test_encrypted_header = |ap, metadata, authentication_data| {
            let (secret, encrypted_header) =
                EncryptedHeader::generate(&cc, &mpk, &ap, metadata, authentication_data).unwrap();
            test_serialization(&encrypted_header)
                .expect("failed serialization test for the encrypted header");
            let decrypted_header = encrypted_header
                .decrypt(&cc, &usk, authentication_data)
                .unwrap();
            let decrypted_header = decrypted_header.unwrap();
            test_serialization(&decrypted_header)
                .expect("failed serialization test for the cleartext header");
            assert_eq!(
                secret, decrypted_header.secret,
                "failed secret equality test"
            );
            assert_eq!(
                metadata,
                decrypted_header.metadata.as_deref(),
                "failed metadata equality test"
            );
        };

        test_encrypted_header(AccessPolicy::parse("DPT::MKG").unwrap(), None, None);
        test_encrypted_header(
            AccessPolicy::parse("DPT::MKG").unwrap(),
            Some("metadata".as_bytes()),
            None,
        );
        test_encrypted_header(
            AccessPolicy::parse("DPT::MKG").unwrap(),
            Some("metadata".as_bytes()),
            Some("authentication data".as_bytes()),
        );
        test_encrypted_header(
            AccessPolicy::parse("DPT::MKG").unwrap(),
            None,
            Some("authentication data".as_bytes()),
        );
    }
}
