use crate::{
    abe::gen_structure,
    abe::{Covercrypt, MasterPublicKey, MasterSecretKey},
    Error,
};

/// Creates the test access structure.
pub fn cc_keygen(
    cc: &Covercrypt,
    complete: bool,
) -> Result<(MasterSecretKey, MasterPublicKey), Error> {
    let (mut msk, _) = cc.setup()?;
    gen_structure(&mut msk.access_structure, complete)?;
    let mpk = cc.update_msk(&mut msk)?;
    Ok((msk, mpk))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::abe::{
        encrypted_header::EncryptedHeader, AccessPolicy, Covercrypt, EncryptionHint, KemAc,
        QualifiedAttribute,
    };

    #[test]
    fn test_add_attribute() -> Result<(), Error> {
        let cc = Covercrypt::default();
        let (mut msk, _mpk) = cc_keygen(&cc, false)?;

        let decryption_policy = AccessPolicy::parse("SEC::LOW")?;
        let mut low_secret_usk = cc.generate_user_secret_key(&mut msk, &decryption_policy)?;

        let _ = &mut msk.access_structure.add_attribute(
            QualifiedAttribute::new("DPT", "Sales"),
            EncryptionHint::PreQuantum,
            None,
        )?;
        let mpk = cc.update_msk(&mut msk)?;

        let secret_sales_ap = AccessPolicy::parse("SEC::LOW && DPT::Sales")?;
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
        let (mut msk, mpk) = cc_keygen(&cc, false)?;

        // New user secret key
        let decryption_policy = AccessPolicy::parse("SEC::TOP && (DPT::FIN || DPT::HR)")?;
        let mut top_secret_fin_usk = cc.generate_user_secret_key(&mut msk, &decryption_policy)?;

        // Encrypt
        let top_secret_ap = AccessPolicy::parse("SEC::TOP && DPT::FIN")?;
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cc, &mpk, &top_secret_ap, None, None)?;

        // remove the FIN department
        msk.access_structure
            .del_attribute(&QualifiedAttribute::new("DPT", "FIN"))?;

        // update the master keys
        let _ = cc.update_msk(&mut msk)?;

        assert!(encrypted_header
            .decrypt(&cc, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        let _new_decryption_policy = AccessPolicy::parse("SEC::TOP && DPT::HR")?;

        // Refreshing the USK removes the keys associated to rights that do not exist anymore in
        // the MSK, even if it is asked to preserve the old secrets.
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
        let (mut msk, mpk) = cc_keygen(&cc, false)?;

        //
        // New user secret key
        let decryption_policy = AccessPolicy::parse("SEC::TOP && (DPT::FIN || DPT::HR)")?;
        let mut top_secret_fin_usk = cc.generate_user_secret_key(&mut msk, &decryption_policy)?;

        //
        // Encrypt
        let top_secret_ap = AccessPolicy::parse("SEC::TOP && DPT::FIN")?;
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cc, &mpk, &top_secret_ap, None, None)?;

        // remove the FIN department
        msk.access_structure
            .disable_attribute(&QualifiedAttribute::new("DPT", "FIN"))?;

        // update the master keys
        let mpk = cc.update_msk(&mut msk)?;

        assert!(encrypted_header
            .decrypt(&cc, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        // Can not encrypt using deactivated attribute
        let top_secret_ap = AccessPolicy::parse("SEC::TOP && DPT::FIN")?;

        assert!(EncryptedHeader::generate(&cc, &mpk, &top_secret_ap, None, None).is_err());

        // refresh the user key and preserve old secrets
        cc.refresh_usk(&mut msk, &mut top_secret_fin_usk, true)?;
        assert!(encrypted_header
            .decrypt(&cc, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        // refresh the user key and remove old secrets
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
        let (mut msk, mpk) = cc_keygen(&cc, false)?;

        // New user secret key
        let decryption_policy = AccessPolicy::parse("SEC::TOP && DPT::FIN")?;
        let mut top_secret_fin_usk = cc.generate_user_secret_key(&mut msk, &decryption_policy)?;

        // Encrypt
        let top_secret_ap = AccessPolicy::parse("SEC::TOP && DPT::FIN")?;
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cc, &mpk, &top_secret_ap, None, None)?;

        // remove the FIN department
        msk.access_structure.rename_attribute(
            &QualifiedAttribute::new("DPT", "FIN"),
            "Finance".to_string(),
        )?;

        // update the master keys
        let _ = cc.update_msk(&mut msk)?;

        assert!(encrypted_header
            .decrypt(&cc, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        // refresh the user key and preserve old secrets
        let _new_decryption_policy = AccessPolicy::parse("SEC::TOP && DPT::Finance")?;
        cc.refresh_usk(&mut msk, &mut top_secret_fin_usk, false)?;
        assert!(encrypted_header
            .decrypt(&cc, &top_secret_fin_usk, None)
            .unwrap()
            .is_some());

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_sym_key() -> Result<(), Error> {
        let access_policy = AccessPolicy::parse("(DPT::MKG || DPT::FIN) && SEC::TOP").unwrap();
        let cc = Covercrypt::default();
        let (mut msk, mpk) = cc_keygen(&cc, false)?;
        let ap = AccessPolicy::parse("DPT::MKG && SEC::TOP")?;
        let (sym_key, encrypted_key) = cc.encaps(&mpk, &ap)?;
        let usk = cc.generate_user_secret_key(&mut msk, &access_policy)?;
        let recovered_key = cc.decaps(&usk, &encrypted_key)?;
        assert_eq!(Some(sym_key), recovered_key, "Wrong decryption of the key!");
        Ok(())
    }

    #[test]
    fn test_single_attribute_in_access_policy() -> Result<(), Error> {
        let cc = Covercrypt::default();
        let (mut msk, _mpk) = cc_keygen(&cc, false)?;

        //
        // New user secret key
        let _user_key = cc.generate_user_secret_key(&mut msk, &AccessPolicy::parse("SEC::TOP")?)?;

        Ok(())
    }

    #[test]
    fn test_rotate_then_encrypt() -> Result<(), Error> {
        let top_secret_ap = &AccessPolicy::parse("SEC::TOP")?;

        let cc = Covercrypt::default();
        let (mut msk, mpk) = cc_keygen(&cc, false)?;

        //
        // New user secret key
        let mut top_secret_fin_usk =
            cc.generate_user_secret_key(&mut msk, &AccessPolicy::parse("SEC::TOP && DPT::FIN")?)?;

        //
        // Encrypt
        let (_, encrypted_header) =
            EncryptedHeader::generate(&cc, &mpk, &top_secret_ap.clone(), None, None)?;

        let _plaintext_header = encrypted_header.decrypt(&cc, &top_secret_fin_usk, None)?;

        assert!(_plaintext_header.is_some());

        //
        // Rotate argument (must update master keys)
        let rekey_ap = AccessPolicy::Term(QualifiedAttribute::from(("SEC", "TOP")));
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

    #[test]
    fn test_broadcast() {
        let cc = Covercrypt::default();
        let ap = AccessPolicy::parse("*").unwrap();
        let (mut msk, mpk) = cc.setup().unwrap();
        let usk = cc.generate_user_secret_key(&mut msk, &ap).unwrap();
        let (secret, bc) = cc.encaps(&mpk, &ap).unwrap();
        let res = cc.decaps(&usk, &bc).unwrap();
        assert_eq!(Some(secret), res);
    }
}
