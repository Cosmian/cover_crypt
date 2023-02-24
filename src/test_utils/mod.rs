use crate::{
    abe_policy::{EncryptionHint, Policy, PolicyAxis},
    Error,
};

#[cfg(feature = "interface")]
pub mod non_regression;

pub fn policy() -> Result<Policy, Error> {
    let sec_level = PolicyAxis::new(
        "Security Level",
        vec![
            ("Protected", EncryptionHint::Classic),
            ("Low Secret", EncryptionHint::Classic),
            ("Medium Secret", EncryptionHint::Classic),
            ("High Secret", EncryptionHint::Classic),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        abe_policy::{AccessPolicy, Attribute, LegacyPolicy, Partition},
        statics::CoverCryptX25519Aes256,
        CoverCrypt, EncryptedHeader,
    };

    #[test]
    fn write_policy() {
        let _policy = policy().unwrap();
        std::fs::write("target/policy.json", serde_json::to_vec(&_policy).unwrap()).unwrap();
    }

    /// Read policy from a file. Assert `LegacyPolicy` is convertible into a
    /// `Policy`.
    #[test]
    fn read_policy() {
        // Can read a `Policy`
        let policy_str = include_bytes!("../../tests_data/policy.json");
        Policy::try_from(policy_str.as_slice()).unwrap();

        // Can read a `LegacyPolicy`
        let legacy_policy_str = include_bytes!("../../tests_data/legacy_policy.json");
        serde_json::from_slice::<LegacyPolicy>(legacy_policy_str).unwrap();

        // Can read `LegacyPolicy` as `Policy`
        Policy::try_from(legacy_policy_str.as_slice()).unwrap();
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
        let decryption_policy = AccessPolicy::from_boolean_expression(
            "Department::MKG && Security Level::High Secret",
        )?;
        let mut usk = cover_crypt.generate_user_secret_key(&msk, &decryption_policy, &policy)?;
        let original_usk = usk.clone();
        // rotate he FIN department
        policy.rotate(&Attribute::new("Department", "MKG"))?;
        // update the master keys
        cover_crypt.update_master_keys(&policy, &mut msk, &mut mpk)?;
        // refresh the user key and preserve access to old partitions
        cover_crypt.refresh_user_secret_key(&mut usk, &decryption_policy, &msk, &policy, true)?;
        // 4 partitions accessed by the user were rotated (MKG Protected, Low Secret,
        // Medium Secret and High Secret)
        assert_eq!(usk.x.len(), original_usk.x.len() + 4);
        for x_i in &original_usk.x {
            assert!(usk.x.contains(x_i));
        }
        // refresh the user key but do NOT preserve access to old partitions
        cover_crypt.refresh_user_secret_key(&mut usk, &decryption_policy, &msk, &policy, false)?;
        // the user should still have access to the same number of partitions
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
