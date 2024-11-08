use crate::{abe_policy::gen_policy, api::Covercrypt, Error, MasterPublicKey, MasterSecretKey};

//pub mod non_regression;

/// Creates the test policy.
pub fn cc_keygen(cc: &Covercrypt) -> Result<(MasterSecretKey, MasterPublicKey), Error> {
    let (mut msk, _) = cc.setup()?;
    gen_policy(&mut msk.policy)?;
    let mpk = cc.update_msk(&mut msk)?;
    Ok((msk, mpk))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        abe_policy::{AccessPolicy, EncryptionHint, QualifiedAttribute},
        api::{Covercrypt, KemAc},
        EncryptedHeader,
    };

    #[test]
    fn test_add_attribute() -> Result<(), Error> {
        let cc = Covercrypt::default();
        let (mut msk, _mpk) = cc_keygen(&cc)?;

        let decryption_policy = AccessPolicy::parse("Security Level::Low Secret")?;
        let mut low_secret_usk = cc.generate_user_secret_key(&mut msk, &decryption_policy)?;

        let _ = &mut msk.policy.add_attribute(
            QualifiedAttribute::new("Department", "Sales"),
            EncryptionHint::Classic,
            None,
        )?;
        let mpk = cc.update_msk(&mut msk)?;

        let secret_sales_ap =
            AccessPolicy::parse("Security Level::Low Secret && Department::Sales")?;
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cc, &mpk, &secret_sales_ap, None, None)?;

        // User cannot decrypt new message without refreshing its key
        assert!(encrypted_header
            .decrypt(&cc, &low_secret_usk, None)
            .unwrap()
            .is_none());

        cc.refresh_usk(&mut msk, &mut low_secret_usk, false)?;

        assert!(encrypted_header
            .decrypt(&cc, &low_secret_usk, None)
            .unwrap()
            .is_none());

        Ok(())
    }

    #[test]
    fn test_delete_attribute() -> Result<(), Error> {
        let cc = Covercrypt::default();
        let (mut msk, mpk) = cc_keygen(&cc)?;

        // New user secret key
        let decryption_policy = AccessPolicy::parse(
            "Security Level::Top Secret && (Department::FIN || Department::HR)",
        )?;
        let mut top_secret_fin_usk = cc.generate_user_secret_key(&mut msk, &decryption_policy)?;

        // Encrypt
        let top_secret_ap = AccessPolicy::parse("Security Level::Top Secret && Department::FIN")?;
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cc, &mpk, &top_secret_ap, None, None)?;

        // remove the FIN department
        msk.policy
            .del_attribute(&QualifiedAttribute::new("Department", "FIN"))?;

        // update the master keys
        let _ = cc.update_msk(&mut msk)?;

        assert!(encrypted_header
            .decrypt(&cc, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        // refresh the user key and preserve access to old coordinates
        let _new_decryption_policy =
            AccessPolicy::parse("Security Level::Top Secret && Department::HR")?;

        // refreshing the user key will remove access to removed coordinates even if we
        // keep old rotations
        cc.refresh_usk(&mut msk, &mut top_secret_fin_usk, true)?;
        assert!(encrypted_header
            .decrypt(&cc, &top_secret_fin_usk, None)
            .unwrap()
            .is_none());

        Ok(())
    }

    #[test]
    fn test_deactivate_attribute() -> Result<(), Error> {
        let cc = Covercrypt::default();
        let (mut msk, mpk) = cc_keygen(&cc)?;

        //
        // New user secret key
        let decryption_policy = AccessPolicy::parse(
            "Security Level::Top Secret && (Department::FIN || Department::HR)",
        )?;
        let mut top_secret_fin_usk = cc.generate_user_secret_key(&mut msk, &decryption_policy)?;

        //
        // Encrypt
        let top_secret_ap = AccessPolicy::parse("Security Level::Top Secret && Department::FIN")?;
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cc, &mpk, &top_secret_ap, None, None)?;

        // remove the FIN department
        msk.policy
            .disable_attribute(&QualifiedAttribute::new("Department", "FIN"))?;

        // update the master keys
        let mpk = cc.update_msk(&mut msk)?;

        assert!(encrypted_header
            .decrypt(&cc, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        // Can not encrypt using deactivated attribute
        let top_secret_ap = AccessPolicy::parse("Security Level::Top Secret && Department::FIN")?;

        assert!(EncryptedHeader::generate(&cc, &mpk, &top_secret_ap, None, None).is_err());

        // refresh the user key and preserve access to old coordinates
        cc.refresh_usk(&mut msk, &mut top_secret_fin_usk, true)?;
        assert!(encrypted_header
            .decrypt(&cc, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        // refresh the user key and remove access to old coordinates should still work
        cc.refresh_usk(&mut msk, &mut top_secret_fin_usk, false)?;
        assert!(encrypted_header
            .decrypt(&cc, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        Ok(())
    }

    #[test]
    fn test_rename_attribute() -> Result<(), Error> {
        let cc = Covercrypt::default();
        let (mut msk, mpk) = cc_keygen(&cc)?;

        // New user secret key
        let decryption_policy =
            AccessPolicy::parse("Security Level::Top Secret && Department::FIN")?;
        let mut top_secret_fin_usk = cc.generate_user_secret_key(&mut msk, &decryption_policy)?;

        // Encrypt
        let top_secret_ap = AccessPolicy::parse("Security Level::Top Secret && Department::FIN")?;
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cc, &mpk, &top_secret_ap, None, None)?;

        // remove the FIN department
        msk.policy.rename_attribute(
            &QualifiedAttribute::new("Department", "FIN"),
            "Finance".to_string(),
        )?;

        // update the master keys
        let _ = cc.update_msk(&mut msk)?;

        assert!(encrypted_header
            .decrypt(&cc, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        // refresh the user key and preserve access to old coordinates
        let _new_decryption_policy =
            AccessPolicy::parse("Security Level::Top Secret && Department::Finance")?;
        cc.refresh_usk(&mut msk, &mut top_secret_fin_usk, false)?;
        assert!(encrypted_header
            .decrypt(&cc, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_sym_key() -> Result<(), Error> {
        let access_policy = AccessPolicy::parse(
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        )
        .unwrap();
        let cc = Covercrypt::default();
        let (mut msk, mpk) = cc_keygen(&cc)?;
        let ap = AccessPolicy::parse("Department::MKG && Security Level::Top Secret")?;
        let (sym_key, encrypted_key) = cc.encaps(&mpk, &ap)?;
        let usk = cc.generate_user_secret_key(&mut msk, &access_policy)?;
        let recovered_key = cc.decaps(&usk, &encrypted_key)?;
        assert_eq!(Some(sym_key), recovered_key, "Wrong decryption of the key!");
        Ok(())
    }

    #[test]
    fn test_single_attribute_in_access_policy() -> Result<(), Error> {
        let cc = Covercrypt::default();
        let (mut msk, _mpk) = cc_keygen(&cc)?;

        //
        // New user secret key
        let _user_key = cc.generate_user_secret_key(
            &mut msk,
            &AccessPolicy::parse("Security Level::Top Secret")?,
        )?;

        Ok(())
    }

    #[test]
    fn test_rotate_then_encrypt() -> Result<(), Error> {
        //
        // Declare policy
        let top_secret_ap = &AccessPolicy::parse("Security Level::Top Secret")?;

        let cc = Covercrypt::default();
        let (mut msk, mpk) = cc_keygen(&cc)?;

        //
        // New user secret key
        let mut top_secret_fin_usk = cc.generate_user_secret_key(
            &mut msk,
            &AccessPolicy::parse("Security Level::Top Secret && Department::FIN")?,
        )?;

        //
        // Encrypt
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cc, &mpk, &top_secret_ap.clone(), None, None)?;

        let _plaintext_header = encrypted_header.decrypt(&cc, &top_secret_fin_usk, None)?;

        assert!(_plaintext_header.is_some());

        //
        // Rotate argument (must update master keys)
        let rekey_ap =
            AccessPolicy::Attr(QualifiedAttribute::from(("Security Level", "Top Secret")));
        let mpk = cc.rekey(&mut msk, &rekey_ap)?;

        //
        // Encrypt with new attribute
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cc, &mpk, &top_secret_ap.clone(), None, None)?;

        // Decryption fails without refreshing the user key
        assert!(encrypted_header
            .decrypt(&cc, &top_secret_fin_usk, None)
            .unwrap()
            .is_none());

        cc.refresh_usk(&mut msk, &mut top_secret_fin_usk, false)?;

        // The refreshed key can decrypt the header
        assert!(encrypted_header
            .decrypt(&cc, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        Ok(())
    }
}
