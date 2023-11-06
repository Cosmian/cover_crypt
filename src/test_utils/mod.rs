use crate::{
    abe_policy::{DimensionBuilder, EncryptionHint, Policy},
    Error,
};

#[cfg(feature = "serialization")]
pub mod non_regression;

pub fn policy() -> Result<Policy, Error> {
    let sec_level = DimensionBuilder::new(
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
    let department = DimensionBuilder::new(
        "Department",
        vec![
            ("R&D", EncryptionHint::Classic),
            ("HR", EncryptionHint::Classic),
            ("MKG", EncryptionHint::Classic),
            ("FIN", EncryptionHint::Classic),
        ],
        false,
    );
    let mut policy = Policy::new();
    policy.add_dimension(sec_level)?;
    policy.add_dimension(department)?;
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::bytes_ser_de::Serializable;

    use super::*;
    use crate::{
        abe_policy::{AccessPolicy, Attribute, LegacyPolicy, Partition},
        Covercrypt, EncryptedHeader, UserSecretKey,
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
        // Can read a `Policy` V2
        let policy_v2_str = include_bytes!("./tests_data/policy_v2.json");
        Policy::try_from(policy_v2_str.as_slice()).unwrap();

        // Can read a `Policy` V1
        let policy_v1_str = include_bytes!("./tests_data/policy_v1.json");
        Policy::try_from(policy_v1_str.as_slice()).unwrap();

        // Can read a `LegacyPolicy`
        let legacy_policy_str = include_bytes!("./tests_data/legacy_policy.json");
        serde_json::from_slice::<LegacyPolicy>(legacy_policy_str).unwrap();

        // Can read `LegacyPolicy` as `Policy`
        Policy::try_from(legacy_policy_str.as_slice()).unwrap();
    }

    #[test]
    fn test_update_master_keys() -> Result<(), Error> {
        let mut policy = policy()?;
        let cover_crypt = Covercrypt::default();
        let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy)?;
        let partitions_msk: Vec<Partition> = msk.subkeys.clone().into_keys().collect();
        let partitions_mpk: Vec<Partition> = mpk.subkeys.clone().into_keys().collect();
        assert_eq!(partitions_msk.len(), partitions_mpk.len());
        for p in &partitions_msk {
            assert!(partitions_mpk.contains(p));
        }
        // rotate he FIN department
        policy.rotate(&Attribute::new("Department", "FIN"))?;
        // update the master keys
        cover_crypt.update_master_keys(&policy, &mut msk, &mut mpk)?;
        let new_partitions_msk: Vec<Partition> = msk.subkeys.clone().into_keys().collect();
        let new_partitions_mpk: Vec<Partition> = mpk.subkeys.clone().into_keys().collect();
        assert_eq!(new_partitions_msk.len(), new_partitions_mpk.len());
        for p in &new_partitions_msk {
            assert!(new_partitions_mpk.contains(p));
        }
        // 5 is the size of the security level dimension
        assert_eq!(new_partitions_msk.len(), partitions_msk.len() + 5);

        // Clear old rotations will reduce master keys size
        policy.clear_old_attribute_values(&Attribute::new("Department", "FIN"))?;
        // update the master keys
        cover_crypt.update_master_keys(&policy, &mut msk, &mut mpk)?;
        let new_partitions_msk: Vec<Partition> = msk.subkeys.clone().into_keys().collect();
        let new_partitions_mpk: Vec<Partition> = mpk.subkeys.clone().into_keys().collect();
        assert_eq!(new_partitions_msk.len(), new_partitions_mpk.len());
        for p in &new_partitions_msk {
            assert!(new_partitions_mpk.contains(p));
        }
        // 5 is the size of the security level dimension
        assert_eq!(new_partitions_msk.len(), partitions_msk.len());

        Ok(())
    }

    #[test]
    fn test_refresh_user_key() -> Result<(), Error> {
        let mut policy = policy()?;
        let cover_crypt = Covercrypt::default();
        let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy)?;
        let decryption_policy = AccessPolicy::from_boolean_expression(
            "Department::MKG && Security Level::High Secret",
        )?;
        let mut usk = cover_crypt.generate_user_secret_key(&msk, &decryption_policy, &policy)?;
        let original_usk = UserSecretKey::deserialize(usk.serialize()?.as_slice())?;
        // rotate he FIN department
        policy.rotate(&Attribute::new("Department", "MKG"))?;
        // update the master keys
        cover_crypt.update_master_keys(&policy, &mut msk, &mut mpk)?;
        // refresh the user key and preserve access to old partitions
        cover_crypt.refresh_user_secret_key(&mut usk, &decryption_policy, &msk, &policy, true)?;
        // 4 partitions accessed by the user were rotated (MKG Protected, Low Secret,
        // Medium Secret and High Secret)
        assert_eq!(usk.subkeys.len(), original_usk.subkeys.len() + 4);
        for x_i in &original_usk.subkeys {
            assert!(usk.subkeys.contains(x_i));
        }
        // refresh the user key but do NOT preserve access to old partitions
        cover_crypt.refresh_user_secret_key(&mut usk, &decryption_policy, &msk, &policy, false)?;
        // the user should still have access to the same number of partitions
        assert_eq!(usk.subkeys.len(), original_usk.subkeys.len());
        for x_i in &original_usk.subkeys {
            assert!(!usk.subkeys.contains(x_i));
        }

        // try to modify the user key and refresh
        let part = Partition::from(vec![1, 6]);
        usk.subkeys.push(msk.subkeys.get(&part).unwrap().clone());
        assert!(cover_crypt
            .refresh_user_secret_key(&mut usk, &decryption_policy, &msk, &policy, false)
            .is_err());

        Ok(())
    }

    #[test]
    fn test_add_attribute() -> Result<(), Error> {
        let mut policy = policy()?;
        let cover_crypt = Covercrypt::default();
        let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy)?;

        let partitions_msk: Vec<Partition> = msk.subkeys.clone().into_keys().collect();
        let partitions_mpk: Vec<Partition> = mpk.subkeys.clone().into_keys().collect();
        assert_eq!(partitions_msk.len(), partitions_mpk.len());
        for p in &partitions_msk {
            assert!(partitions_mpk.contains(p));
        }

        //
        // User secret key
        let decryption_policy =
            AccessPolicy::from_boolean_expression("Security Level::Low Secret")?;
        let mut low_secret_usk =
            cover_crypt.generate_user_secret_key(&msk, &decryption_policy, &policy)?;

        // add sales department
        policy.add_attribute(
            Attribute::new("Department", "Sales"),
            EncryptionHint::Classic,
        )?;
        // update the master keys
        cover_crypt.update_master_keys(&policy, &mut msk, &mut mpk)?;
        let new_partitions_msk: Vec<Partition> = msk.subkeys.clone().into_keys().collect();
        let new_partitions_mpk: Vec<Partition> = mpk.subkeys.clone().into_keys().collect();
        assert_eq!(new_partitions_msk.len(), new_partitions_mpk.len());
        for p in &new_partitions_msk {
            assert!(new_partitions_mpk.contains(p));
        }
        // 5 is the size of the security level dimension
        assert_eq!(new_partitions_msk.len(), partitions_msk.len() + 5);

        //
        // Encrypt
        let secret_sales_ap = AccessPolicy::from_boolean_expression(
            "Security Level::Low Secret && Department::Sales",
        )?;
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &secret_sales_ap, None, None)?;

        // User cannot decrypt new message without refreshing its key
        assert!(encrypted_header
            .decrypt(&cover_crypt, &low_secret_usk, None)
            .is_err());

        cover_crypt.refresh_user_secret_key(
            &mut low_secret_usk,
            &decryption_policy,
            &msk,
            &policy,
            false,
        )?;

        assert!(encrypted_header
            .decrypt(&cover_crypt, &low_secret_usk, None)
            .is_ok());

        Ok(())
    }

    #[test]
    fn test_delete_attribute() -> Result<(), Error> {
        let mut policy = policy()?;
        let cover_crypt = Covercrypt::default();
        let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy)?;

        let partitions_msk: Vec<Partition> = msk.subkeys.clone().into_keys().collect();
        let partitions_mpk: Vec<Partition> = mpk.subkeys.clone().into_keys().collect();
        assert_eq!(partitions_msk.len(), partitions_mpk.len());
        for p in &partitions_msk {
            assert!(partitions_mpk.contains(p));
        }

        //
        // New user secret key
        let decryption_policy = AccessPolicy::from_boolean_expression(
            "Security Level::Top Secret && (Department::FIN || Department::HR)",
        )?;
        let mut top_secret_fin_usk =
            cover_crypt.generate_user_secret_key(&msk, &decryption_policy, &policy)?;

        //
        // Encrypt
        let top_secret_ap =
            AccessPolicy::from_boolean_expression("Security Level::Top Secret && Department::FIN")?;
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &top_secret_ap, None, None)?;

        // remove the FIN department
        policy.remove_attribute(&Attribute::new("Department", "FIN"))?;

        // update the master keys
        cover_crypt.update_master_keys(&policy, &mut msk, &mut mpk)?;
        let new_partitions_msk: Vec<Partition> = msk.subkeys.clone().into_keys().collect();
        let new_partitions_mpk: Vec<Partition> = mpk.subkeys.clone().into_keys().collect();
        assert_eq!(new_partitions_msk.len(), new_partitions_mpk.len());
        for p in &new_partitions_msk {
            assert!(new_partitions_mpk.contains(p));
        }
        // 5 is the size of the security level dimension
        assert_eq!(new_partitions_msk.len(), partitions_msk.len() - 5);

        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .is_ok());

        // refresh the user key and preserve access to old partitions
        let new_decryption_policy =
            AccessPolicy::from_boolean_expression("Security Level::Top Secret && Department::HR")?;

        // refreshing the user key will remove access to removed partitions even if we
        // keep old rotations
        cover_crypt.refresh_user_secret_key(
            &mut top_secret_fin_usk,
            &new_decryption_policy,
            &msk,
            &policy,
            true,
        )?;
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .is_err());

        Ok(())
    }

    #[test]
    fn test_deactivate_attribute() -> Result<(), Error> {
        let mut policy = policy()?;
        let cover_crypt = Covercrypt::default();
        let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy)?;

        let partitions_msk: Vec<Partition> = msk.subkeys.clone().into_keys().collect();
        let partitions_mpk: Vec<Partition> = mpk.subkeys.clone().into_keys().collect();
        assert_eq!(partitions_msk.len(), partitions_mpk.len());
        for p in &partitions_msk {
            assert!(partitions_mpk.contains(p));
        }

        //
        // New user secret key
        let decryption_policy = AccessPolicy::from_boolean_expression(
            "Security Level::Top Secret && (Department::FIN || Department::HR)",
        )?;
        let mut top_secret_fin_usk =
            cover_crypt.generate_user_secret_key(&msk, &decryption_policy, &policy)?;

        //
        // Encrypt
        let top_secret_ap =
            AccessPolicy::from_boolean_expression("Security Level::Top Secret && Department::FIN")?;
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &top_secret_ap, None, None)?;

        // remove the FIN department
        policy.disable_attribute(&Attribute::new("Department", "FIN"))?;

        // update the master keys
        cover_crypt.update_master_keys(&policy, &mut msk, &mut mpk)?;
        let new_partitions_msk: Vec<Partition> = msk.subkeys.clone().into_keys().collect();
        let new_partitions_mpk: Vec<Partition> = mpk.subkeys.clone().into_keys().collect();
        // the disabled partition have been removed from mpk
        assert_eq!(new_partitions_msk.len() - 5, new_partitions_mpk.len());
        // msk hasn't changed
        assert_eq!(new_partitions_msk.len(), partitions_msk.len());

        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .is_ok());

        // Can not encrypt using deactivated attribute
        let top_secret_ap =
            AccessPolicy::from_boolean_expression("Security Level::Top Secret && Department::FIN")?;

        assert!(
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &top_secret_ap, None, None)
                .is_err()
        );

        // refresh the user key and preserve access to old partitions
        let new_decryption_policy =
            AccessPolicy::from_boolean_expression("Security Level::Top Secret && Department::FIN")?;
        cover_crypt.refresh_user_secret_key(
            &mut top_secret_fin_usk,
            &new_decryption_policy,
            &msk,
            &policy,
            true,
        )?;
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .is_ok());

        // refresh the user key and remove access to old partitions
        cover_crypt.refresh_user_secret_key(
            &mut top_secret_fin_usk,
            &new_decryption_policy,
            &msk,
            &policy,
            false,
        )?;
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .is_ok());

        //
        // Rotating the disabled attribute should only change the msk
        policy.rotate(&Attribute::new("Department", "FIN"))?;
        cover_crypt.update_master_keys(&policy, &mut msk, &mut mpk)?;
        let new_partitions_msk: Vec<Partition> = msk.subkeys.clone().into_keys().collect();
        let new_partitions_mpk: Vec<Partition> = mpk.subkeys.clone().into_keys().collect();
        // 5 new partitions added to the msk
        assert_eq!(new_partitions_msk.len() - 10, new_partitions_mpk.len());
        assert_eq!(new_partitions_msk.len(), partitions_msk.len() + 5);

        Ok(())
    }

    #[test]
    fn test_rename_attribute() -> Result<(), Error> {
        let mut policy = policy()?;
        let cover_crypt = Covercrypt::default();
        let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy)?;

        //
        // New user secret key
        let decryption_policy =
            AccessPolicy::from_boolean_expression("Security Level::Top Secret && Department::FIN")?;
        let mut top_secret_fin_usk =
            cover_crypt.generate_user_secret_key(&msk, &decryption_policy, &policy)?;

        //
        // Encrypt
        let top_secret_ap =
            AccessPolicy::from_boolean_expression("Security Level::Top Secret && Department::FIN")?;
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &top_secret_ap, None, None)?;

        // remove the FIN department
        policy.rename_attribute(&Attribute::new("Department", "FIN"), "Finance")?;

        // update the master keys
        cover_crypt.update_master_keys(&policy, &mut msk, &mut mpk)?;

        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .is_ok());

        // refresh the user key and preserve access to old partitions
        let new_decryption_policy = AccessPolicy::from_boolean_expression(
            "Security Level::Top Secret && Department::Finance",
        )?;
        cover_crypt.refresh_user_secret_key(
            &mut top_secret_fin_usk,
            &new_decryption_policy,
            &msk,
            &policy,
            false,
        )?;
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .is_ok());

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_sym_key() -> Result<(), Error> {
        let mut policy = policy()?;
        policy.rotate(&Attribute::new("Department", "FIN"))?;
        let access_policy = (AccessPolicy::new("Department", "R&D")
            | AccessPolicy::new("Department", "FIN"))
            & AccessPolicy::new("Security Level", "Top Secret");
        let cover_crypt = Covercrypt::default();
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
        // Setup Covercrypt
        let cover_crypt = Covercrypt::default();
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
        // Setup Covercrypt
        let cover_crypt = Covercrypt::default();
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
