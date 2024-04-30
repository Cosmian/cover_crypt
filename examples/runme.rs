<<<<<<< HEAD
use crate::{
    abe_policy::{DimensionBuilder, EncryptionHint, Policy},
    Error,
=======
//! This is the demo given in `README.md` and `lib.rs`

use cosmian_cover_crypt::{
    abe_policy::{AccessPolicy, DimensionBuilder, EncryptionHint, Policy},
    api::{Covercrypt, EncryptedHeaderAes256},
>>>>>>> a901c33 (fix examples and clippy warning)
};

// pub mod non_regression;

/// Creates the test policy.
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
<<<<<<< HEAD
    policy.add_dimension(sec_level)?;
    policy.add_dimension(department)?;
    Ok(policy)
=======

    // Add the two generated axes to the policy
    policy.add_dimension(sec_level).unwrap();
    policy.add_dimension(department).unwrap();

    // Setup Covercrypt and generate master keys
    let cover_crypt = Covercrypt::default();
    let (mut msk, _) = cover_crypt.setup().unwrap();
    let mpk = cover_crypt.update_master_keys(&policy, &mut msk).unwrap();

    // The user has a security clearance `Security Level::Top Secret`,
    // and belongs to the finance department (`Department::FIN`).
    let access_policy =
        AccessPolicy::parse("Security Level::Top Secret && Department::FIN").unwrap();
    let mut usk = cover_crypt
        .generate_user_secret_key(&mut msk, &access_policy, &policy)
        .unwrap();

    // Encrypt
    let (_, encrypted_header) = EncryptedHeaderAes256::generate(
        &cover_crypt,
        &policy,
        &mpk,
        &access_policy.clone(),
        None,
        None,
    )
    .unwrap();

    // The user is able to decrypt the encrypted header.
    assert!(encrypted_header
        .decrypt(&cover_crypt, &usk, None)
        .unwrap()
        .is_some());

    //
    // Rekey the user access policy.
    let mpk = cover_crypt
        .rekey(&access_policy, &policy, &mut msk)
        .unwrap();

    let enc_policy = AccessPolicy::parse("Security Level::Top Secret").unwrap();
    // Encrypt with rotated attribute
    let (_, new_encrypted_header) =
        EncryptedHeaderAes256::generate(&cover_crypt, &policy, &mpk, &enc_policy, None, None)
            .unwrap();

    // user cannot decrypt the newly encrypted header
    assert!(new_encrypted_header
        .decrypt(&cover_crypt, &usk, None)
        .unwrap()
        .is_none());

    // refresh user secret key, do not grant old encryption access
    cover_crypt.refresh_usk(&mut usk, &mut msk, false).unwrap();

    // The user with refreshed key is able to decrypt the newly encrypted header.
    assert!(new_encrypted_header
        .decrypt(&cover_crypt, &usk, None)
        .unwrap()
        .is_some());

    // But it cannot decrypt old ciphertexts
<<<<<<< HEAD
    assert!(
        EncryptionHeaderAes256::decrypt(&encrypted_header, &cover_crypt, &usk, None)
            .expect("must not fail")
            .is_none()
    );
>>>>>>> 94eee8d (implementing theo's comments)
=======
    assert!(encrypted_header
        .decrypt(&cover_crypt, &usk, None)
        .unwrap()
        .is_none());
>>>>>>> a901c33 (fix examples and clippy warning)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        abe_policy::{AccessPolicy, Attribute, LegacyPolicy},
        api::{Covercrypt, CovercryptKEM},
        core::EncryptedHeader,
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
    fn test_add_attribute() -> Result<(), Error> {
        let mut policy = policy()?;
        let cover_crypt = Covercrypt::default();
        let (mut msk, _) = cover_crypt.setup()?;
        let _ = cover_crypt.update_master_keys(&policy, &mut msk)?;

        let decryption_policy = AccessPolicy::parse("Security Level::Low Secret")?;
        let mut low_secret_usk =
            cover_crypt.generate_user_secret_key(&mut msk, &decryption_policy, &policy)?;

        policy.add_attribute(
            Attribute::new("Department", "Sales"),
            EncryptionHint::Classic,
        )?;
        let mpk = cover_crypt.update_master_keys(&policy, &mut msk)?;

        let secret_sales_ap =
            AccessPolicy::parse("Security Level::Low Secret && Department::Sales")?;
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &secret_sales_ap, None, None)?;

        // User cannot decrypt new message without refreshing its key
        assert!(encrypted_header
            .decrypt(&cover_crypt, &low_secret_usk, None)
            .unwrap()
            .is_none());

        cover_crypt.refresh_usk(&mut low_secret_usk, &mut msk, false)?;

        assert!(encrypted_header
            .decrypt(&cover_crypt, &low_secret_usk, None)
            .unwrap()
            .is_none());

        Ok(())
    }

    #[test]
    fn test_delete_attribute() -> Result<(), Error> {
        let mut policy = policy()?;
        let cover_crypt = Covercrypt::default();
        let (mut msk, _) = cover_crypt.setup()?;
        let mpk = cover_crypt.update_master_keys(&policy, &mut msk)?;

        // New user secret key
        let decryption_policy = AccessPolicy::parse(
            "Security Level::Top Secret && (Department::FIN || Department::HR)",
        )?;
        let mut top_secret_fin_usk =
            cover_crypt.generate_user_secret_key(&mut msk, &decryption_policy, &policy)?;

        // Encrypt
        let top_secret_ap = AccessPolicy::parse("Security Level::Top Secret && Department::FIN")?;
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &top_secret_ap, None, None)?;

        // remove the FIN department
        policy.remove_attribute(&Attribute::new("Department", "FIN"))?;

        // update the master keys
        let _ = cover_crypt.update_master_keys(&policy, &mut msk)?;

        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        // refresh the user key and preserve access to old coordinates
        let _new_decryption_policy =
            AccessPolicy::parse("Security Level::Top Secret && Department::HR")?;

        // refreshing the user key will remove access to removed coordinates even if we
        // keep old rotations
        cover_crypt.refresh_usk(&mut top_secret_fin_usk, &mut msk, true)?;
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .unwrap()
            .is_none());

        Ok(())
    }

    #[test]
    fn test_deactivate_attribute() -> Result<(), Error> {
        let mut policy = policy()?;
        let cover_crypt = Covercrypt::default();
        let (mut msk, _) = cover_crypt.setup()?;
        let mpk = cover_crypt.update_master_keys(&policy, &mut msk)?;

        //
        // New user secret key
        let decryption_policy = AccessPolicy::parse(
            "Security Level::Top Secret && (Department::FIN || Department::HR)",
        )?;
        let mut top_secret_fin_usk =
            cover_crypt.generate_user_secret_key(&mut msk, &decryption_policy, &policy)?;

        //
        // Encrypt
        let top_secret_ap = AccessPolicy::parse("Security Level::Top Secret && Department::FIN")?;
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &top_secret_ap, None, None)?;

        // remove the FIN department
        policy.disable_attribute(&Attribute::new("Department", "FIN"))?;

        // update the master keys
        let mpk = cover_crypt.update_master_keys(&policy, &mut msk)?;

        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        // Can not encrypt using deactivated attribute
        let top_secret_ap = AccessPolicy::parse("Security Level::Top Secret && Department::FIN")?;

        assert!(
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &top_secret_ap, None, None)
                .is_err()
        );

        // refresh the user key and preserve access to old coordinates
        cover_crypt.refresh_usk(&mut top_secret_fin_usk, &mut msk, true)?;
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        // refresh the user key and remove access to old coordinates should still work
        cover_crypt.refresh_usk(&mut top_secret_fin_usk, &mut msk, false)?;
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        Ok(())
    }

    #[test]
    fn test_rename_attribute() -> Result<(), Error> {
        let mut policy = policy()?;
        let cover_crypt = Covercrypt::default();
        let (mut msk, _) = cover_crypt.setup()?;
        let mpk = cover_crypt.update_master_keys(&policy, &mut msk)?;

        // New user secret key
        let decryption_policy =
            AccessPolicy::parse("Security Level::Top Secret && Department::FIN")?;
        let mut top_secret_fin_usk =
            cover_crypt.generate_user_secret_key(&mut msk, &decryption_policy, &policy)?;

        // Encrypt
        let top_secret_ap = AccessPolicy::parse("Security Level::Top Secret && Department::FIN")?;
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cover_crypt, &policy, &mpk, &top_secret_ap, None, None)?;

        // remove the FIN department
        policy.rename_attribute(&Attribute::new("Department", "FIN"), "Finance".to_string())?;

        // update the master keys
        let _ = cover_crypt.update_master_keys(&policy, &mut msk)?;

        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        // refresh the user key and preserve access to old coordinates
        let _new_decryption_policy =
            AccessPolicy::parse("Security Level::Top Secret && Department::Finance")?;
        cover_crypt.refresh_usk(&mut top_secret_fin_usk, &mut msk, false)?;
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_sym_key() -> Result<(), Error> {
        let policy = policy()?;
        let access_policy = AccessPolicy::parse(
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        )
        .unwrap();
        let cover_crypt = Covercrypt::default();
        let (mut msk, _) = cover_crypt.setup()?;
        let mpk = cover_crypt.update_master_keys(&policy, &mut msk)?;
        let ap = AccessPolicy::parse("Department::MKG && Security Level::Top Secret")?;
        let (sym_key, encrypted_key) = cover_crypt.encaps(&mpk, &policy, &ap)?;
        let usk = cover_crypt.generate_user_secret_key(&mut msk, &access_policy, &policy)?;
        let recovered_key = cover_crypt.decaps(&usk, &encrypted_key)?;
        assert_eq!(Some(sym_key), recovered_key, "Wrong decryption of the key!");
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
        let (mut msk, _) = cover_crypt.setup()?;
        let _ = cover_crypt.update_master_keys(&policy, &mut msk)?;

        //
        // New user secret key
        let _user_key = cover_crypt.generate_user_secret_key(
            &mut msk,
            &AccessPolicy::parse("Security Level::Top Secret")?,
            &policy,
        )?;

        Ok(())
    }

    #[test]
    fn test_rotate_then_encrypt() -> Result<(), Error> {
        //
        // Declare policy
        let policy = policy()?;
        let top_secret_ap = &AccessPolicy::parse("Security Level::Top Secret")?;

        //
        // Setup Covercrypt
        let cover_crypt = Covercrypt::default();
        let (mut msk, _) = cover_crypt.setup()?;
        let mpk = cover_crypt.update_master_keys(&policy, &mut msk)?;

        //
        // New user secret key
        let mut top_secret_fin_usk = cover_crypt.generate_user_secret_key(
            &mut msk,
            &AccessPolicy::parse("Security Level::Top Secret && Department::FIN")?,
            &policy,
        )?;

        //
        // Encrypt
        let (_, encrypted_header) = EncryptedHeader::generate(
            &cover_crypt,
            &policy,
            &mpk,
            &top_secret_ap.clone(),
            None,
            None,
        )?;

        let _plaintext_header =
            encrypted_header.decrypt(&cover_crypt, &top_secret_fin_usk, None)?;

        //
        // Rotate argument (must update master keys)
        let rekey_ap = AccessPolicy::Attr(Attribute::from(("Security Level", "Top Secret")));
        let mpk = cover_crypt.rekey(&rekey_ap, &policy, &mut msk)?;

        //
        // Encrypt with new attribute
        let (_, encrypted_header) = EncryptedHeader::generate(
            &cover_crypt,
            &policy,
            &mpk,
            &top_secret_ap.clone(),
            None,
            None,
        )?;

        // Decryption fails without refreshing the user key
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .unwrap()
            .is_none());

        cover_crypt.refresh_usk(&mut top_secret_fin_usk, &mut msk, false)?;

        // The refreshed key can decrypt the header
        assert!(encrypted_header
            .decrypt(&cover_crypt, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        Ok(())
    }
}