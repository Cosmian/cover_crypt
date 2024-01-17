use crate::{
    abe_policy::{DimensionBuilder, EncryptionHint, Policy},
    Error,
};

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
        Covercrypt, EncryptedHeader,
    };

    use crate::UserSecretKey;

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
        let policy = policy()?;
        let cover_crypt = Covercrypt::default();
        let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy)?;
        // same number of subkeys in public and secret key
        assert_eq!(mpk.subkeys.len(), 30);
        assert_eq!(msk.subkeys.count_elements(), 30);

        // rekey all partitions which include `Department::FIN`
        let rekey_access_policy = AccessPolicy::Attr(Attribute::new("Department", "FIN"));
        cover_crypt.rekey_master_keys(&rekey_access_policy, &policy, &mut msk, &mut mpk)?;
        // public key contains only the last subkeys
        assert_eq!(mpk.subkeys.len(), 30);
        // secret key stores the 2 old subkeys
        assert_eq!(msk.subkeys.count_elements(), 32);

        // remove older subkeys for `Department::FIN`
        cover_crypt.prune_master_secret_key(&rekey_access_policy, &policy, &mut msk)?;
        // we only keep the last subkeys in the secret key
        assert_eq!(msk.subkeys.count_elements(), 30);

        Ok(())
    }

    #[test]
    fn test_master_rekey() -> Result<(), Error> {
        let d1 = DimensionBuilder::new(
            "D1",
            vec![
                ("A", EncryptionHint::Classic),
                ("B", EncryptionHint::Classic),
            ],
            false,
        );
        let d2 = DimensionBuilder::new(
            "D2",
            vec![
                ("A", EncryptionHint::Classic),
                ("B", EncryptionHint::Classic),
            ],
            false,
        );
        let mut policy = Policy::new();
        policy.add_dimension(d1)?;
        policy.add_dimension(d2)?;

        let cover_crypt = Covercrypt::default();
        let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy)?;

        // There is one key per coordinate.
        let mut n_keys = (2 + 1) * (2 + 1);
        assert_eq!(msk.subkeys.count_elements(), n_keys);

        let rekey_access_policy = AccessPolicy::Attr(Attribute::new("D1", "A"));
        cover_crypt.rekey_master_keys(&rekey_access_policy, &policy, &mut msk, &mut mpk)?;
        n_keys += 2;
        assert_eq!(msk.subkeys.count_elements(), n_keys);

        let rekey_access_policy = AccessPolicy::Attr(Attribute::new("D1", "B"));
        cover_crypt.rekey_master_keys(&rekey_access_policy, &policy, &mut msk, &mut mpk)?;
        n_keys += 2;
        assert_eq!(msk.subkeys.count_elements(), n_keys);

        let rekey_access_policy = AccessPolicy::Attr(Attribute::new("D2", "A"));
        cover_crypt.rekey_master_keys(&rekey_access_policy, &policy, &mut msk, &mut mpk)?;
        n_keys += 2;
        assert_eq!(msk.subkeys.count_elements(), n_keys);

        Ok(())
    }

    #[test]
    fn test_refresh_user_key() -> Result<(), Error> {
        let policy = policy()?;
        let cover_crypt = Covercrypt::default();
        let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy)?;

        let ap = AccessPolicy::from_boolean_expression(
            "Department::MKG && Security Level::High Secret",
        )?;
        let mut usk = cover_crypt.generate_user_secret_key(&msk, &ap, &policy)?;
        let original_usk = UserSecretKey::deserialize(usk.serialize()?.as_slice())?;

        // Re-key the access policy associated to the user key.
        cover_crypt.rekey_master_keys(&ap, &policy, &mut msk, &mut mpk)?;

        cover_crypt.refresh_user_secret_key(&mut usk, &msk, true)?;
        assert_eq!(
            usk.subkeys.borrow().count_elements(),
            2 * original_usk.subkeys.borrow().count_elements()
        );
        for x_i in original_usk.subkeys.borrow().flat_iter() {
            assert!(usk.subkeys.borrow().flat_iter().any(|x| x == x_i));
        }
        // refresh the user key but do NOT preserve access to old partitions
        cover_crypt.refresh_user_secret_key(&mut usk, &msk, false)?;
        // the user should still have access to the same number of partitions
        assert_eq!(
            usk.subkeys.borrow().count_elements(),
            original_usk.subkeys.borrow().count_elements()
        );
        for x_i in original_usk.subkeys.borrow().flat_iter() {
            assert!(!usk.subkeys.borrow().flat_iter().any(|x| x == x_i));
        }

        // try to modify the user key and refresh
        let part = Partition::from(vec![1, 6]);
        usk.subkeys.borrow_mut().create_chain_with_single_value(
            part.clone(),
            msk.subkeys.get_latest(&part).unwrap().clone(),
        );
        assert!(cover_crypt
            .refresh_user_secret_key(&mut usk, &msk, false)
            .is_err());

        Ok(())
    }

    #[test]
    fn test_add_attribute() -> Result<(), Error> {
        let mut policy = policy()?;
        let cover_crypt = Covercrypt::default();
        let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy)?;

        let partitions_msk: Vec<Partition> = msk.subkeys.keys().cloned().collect();
        let partitions_mpk: Vec<Partition> = mpk.subkeys.keys().cloned().collect();
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
        let new_partitions_msk: Vec<Partition> = msk.subkeys.keys().cloned().collect();
        let new_partitions_mpk: Vec<Partition> = mpk.subkeys.keys().cloned().collect();
        assert_eq!(new_partitions_msk.len(), new_partitions_mpk.len());
        for p in &new_partitions_msk {
            assert!(new_partitions_mpk.contains(p));
        }
        assert_eq!(new_partitions_msk.len(), partitions_msk.len() + 6);

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

        cover_crypt.refresh_user_secret_key(&mut low_secret_usk, &msk, false)?;

        // TODO: fix this behavior?
        assert!(encrypted_header
            .decrypt(&cover_crypt, &low_secret_usk, None)
            .is_err());

        Ok(())
    }

    #[test]
    fn test_delete_attribute() -> Result<(), Error> {
        let mut policy = policy()?;
        let cover_crypt = Covercrypt::default();
        let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy)?;

        let partitions_msk: Vec<Partition> = msk.subkeys.keys().cloned().collect();
        let partitions_mpk: Vec<Partition> = mpk.subkeys.keys().cloned().collect();
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
        let new_partitions_msk: Vec<Partition> = msk.subkeys.keys().cloned().collect();
        let new_partitions_mpk: Vec<Partition> = mpk.subkeys.keys().cloned().collect();
        assert_eq!(new_partitions_msk.len(), new_partitions_mpk.len());
        for p in &new_partitions_msk {
            assert!(new_partitions_mpk.contains(p));
        }
        // 5 is the size of the security level dimension
        assert_eq!(new_partitions_msk.len(), partitions_msk.len() - 6);

        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .is_ok());

        // refresh the user key and preserve access to old partitions
        let _new_decryption_policy =
            AccessPolicy::from_boolean_expression("Security Level::Top Secret && Department::HR")?;

        // refreshing the user key will remove access to removed partitions even if we
        // keep old rotations
        cover_crypt.refresh_user_secret_key(&mut top_secret_fin_usk, &msk, true)?;
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

        let partitions_msk: Vec<Partition> = msk.subkeys.keys().cloned().collect();
        let partitions_mpk: Vec<Partition> = mpk.subkeys.keys().cloned().collect();
        assert_eq!(partitions_msk.len(), partitions_mpk.len());

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
        let new_partitions_msk: Vec<Partition> = msk.subkeys.keys().cloned().collect();
        let new_partitions_mpk: Vec<Partition> = mpk.subkeys.keys().cloned().collect();
        // the disabled partition have been removed from mpk
        assert_eq!(new_partitions_msk.len() - 6, new_partitions_mpk.len());
        // msk has not changed
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
        cover_crypt.refresh_user_secret_key(&mut top_secret_fin_usk, &msk, true)?;
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .is_ok());

        // refresh the user key and remove access to old partitions should still work
        cover_crypt.refresh_user_secret_key(&mut top_secret_fin_usk, &msk, false)?;
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .is_ok());

        //
        // Rotating the disabled attribute should only change the msk
        let rekey_ap = AccessPolicy::Attr(Attribute::new("Department", "FIN"));
        cover_crypt.rekey_master_keys(&rekey_ap, &policy, &mut msk, &mut mpk)?;
        assert_eq!(msk.subkeys.count_elements() - 8, mpk.subkeys.len());

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
        policy.rename_attribute(&Attribute::new("Department", "FIN"), "Finance".to_string())?;

        // update the master keys
        cover_crypt.update_master_keys(&policy, &mut msk, &mut mpk)?;

        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .is_ok());

        // refresh the user key and preserve access to old partitions
        let _new_decryption_policy = AccessPolicy::from_boolean_expression(
            "Security Level::Top Secret && Department::Finance",
        )?;
        cover_crypt.refresh_user_secret_key(&mut top_secret_fin_usk, &msk, false)?;
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .is_ok());

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_sym_key() -> Result<(), Error> {
        let policy = policy()?;
        let access_policy = (AccessPolicy::new("Department", "MKG")
            | AccessPolicy::new("Department", "FIN"))
            & AccessPolicy::new("Security Level", "Top Secret");
        let cover_crypt = Covercrypt::default();
        let (msk, mpk) = cover_crypt.generate_master_keys(&policy)?;
        let (sym_key, encrypted_key) = cover_crypt.encaps(
            &policy,
            &mpk,
            AccessPolicy::from_boolean_expression("Department::MKG && Security Level::Top Secret")?,
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
        let policy = policy()?;
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
        let rekey_ap = AccessPolicy::Attr(Attribute::from(("Security Level", "Top Secret")));
        cover_crypt.rekey_master_keys(&rekey_ap, &policy, &mut msk, &mut master_public_key)?;

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

        cover_crypt.refresh_user_secret_key(&mut top_secret_fin_usk, &msk, false)?;

        // The refreshed key can decrypt the header
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .is_ok());

        Ok(())
    }
}
