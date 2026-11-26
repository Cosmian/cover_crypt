use crate::{
    Error,
    abe::gen_structure,
    abe::{Covercrypt, MasterSecretKey, PublicKey},
};
use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;

/// Creates the test access structure.
pub fn cc_keygen(
    rng: &mut impl CryptoRngCore,
    complete: bool,
) -> Result<(MasterSecretKey, PublicKey), Error> {
    let mut msk = Covercrypt::setup(rng)?;
    Covercrypt::edit_msk(&mut msk, |access_structure| {
        gen_structure(access_structure, complete)
    })?;
    let pk = Covercrypt::gen_pk(&msk, None)?;
    Ok((msk, pk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abe::{
        AccessPolicy, Covercrypt, HybridizationStatus, QualifiedAttribute,
        encrypted_header::EncryptedHeader, traits::KemAc,
    };
    use cosmian_crypto_core::{CsRng, reexport::rand_core::SeedableRng};

    #[test]
    fn test_add_attribute() -> Result<(), Error> {
        let mut rng = CsRng::from_entropy();
        let (mut msk, _) = cc_keygen(&mut rng, false)?;

        let mut low_secret_usk = Covercrypt::gen_usk(
            &mut rng,
            &mut msk,
            AccessPolicy::parse("SEC::LOW")?,
        )?;

        Covercrypt::edit_msk(&mut msk, |access_structure| {
            access_structure.add_attribute(
                QualifiedAttribute::new("DPT".to_owned(), "Sales".to_owned()),
                HybridizationStatus::Classic,
                None,
            )
        })?;

        let pk = Covercrypt::gen_pk(&msk, None)?;

        let (_, encrypted_header) = EncryptedHeader::generate(
            &mut rng,
            &pk,
            &AccessPolicy::parse("SEC::LOW && DPT::Sales")?,
            None,
            None,
        )?;

        // User cannot decrypt new message without refreshing its key
        assert!(
            encrypted_header
                .decrypt(&mut rng, &low_secret_usk, None)
                .unwrap()
                .is_none()
        );

        Covercrypt::refresh_usk(
            &mut rng,
            &mut msk,
            &mut low_secret_usk,
            false,
        )?;

        assert!(
            encrypted_header
                .decrypt(&mut rng, &low_secret_usk, None)
                .unwrap()
                .is_none()
        );

        Ok(())
    }

    #[test]
    fn test_delete_attribute() -> Result<(), Error> {
        let mut rng = CsRng::from_entropy();
        let (mut msk, pk) = cc_keygen(&mut rng, false)?;

        // New user secret key
        let mut top_secret_fin_usk = Covercrypt::gen_usk(
            &mut rng,
            &mut msk,
            AccessPolicy::parse("SEC::TOP && (DPT::FIN || DPT::HR)")?,
        )?;

        // Encrypt
        let (_, encrypted_header) = EncryptedHeader::generate(
            &mut rng,
            &pk,
            &AccessPolicy::parse("SEC::TOP && DPT::FIN")?,
            None,
            None,
        )?;

        // remove the FIN department
        Covercrypt::edit_msk(&mut msk, |access_structure| {
            access_structure.del_attribute(&QualifiedAttribute::new(
                "DPT".to_owned(),
                "FIN".to_owned(),
            ))
        })?;

        assert!(
            encrypted_header
                .decrypt(&mut rng, &top_secret_fin_usk, None)
                .unwrap()
                .is_some()
        );

        // Refreshing the USK removes the keys associated to rights that do not
        // exist anymore in the MSK, even if it is asked to preserve the old
        // secrets.
        Covercrypt::refresh_usk(
            &mut rng,
            &mut msk,
            &mut top_secret_fin_usk,
            true,
        )?;

        assert!(
            encrypted_header
                .decrypt(&mut rng, &top_secret_fin_usk, None)
                .unwrap()
                .is_none()
        );

        Ok(())
    }

    #[test]
    fn test_deactivate_attribute() -> Result<(), Error> {
        let mut rng = CsRng::from_entropy();
        let (mut msk, pk) = cc_keygen(&mut rng, false)?;

        // New user secret key
        let mut top_secret_fin_usk = Covercrypt::gen_usk(
            &mut rng,
            &mut msk,
            AccessPolicy::parse("SEC::TOP && (DPT::FIN || DPT::HR)")?,
        )?;

        // Encrypt
        let (_, encrypted_header) = EncryptedHeader::generate(
            &mut rng,
            &pk,
            &AccessPolicy::parse("SEC::TOP && DPT::FIN")?,
            None,
            None,
        )?;

        // remove the FIN department
        Covercrypt::edit_msk(&mut msk, |access_structure| {
            access_structure.disable_attribute(&QualifiedAttribute::new(
                "DPT".to_owned(),
                "FIN".to_owned(),
            ))
        })?;

        // update the master keys
        let pk = Covercrypt::gen_pk(&msk, None)?;

        assert!(
            encrypted_header
                .decrypt(&mut rng, &top_secret_fin_usk, None)
                .unwrap()
                .is_some()
        );

        // Can not encrypt using deactivated attribute
        assert!(
            EncryptedHeader::generate(
                &mut rng,
                &pk,
                &AccessPolicy::parse("SEC::TOP && DPT::FIN")?,
                None,
                None
            )
            .is_err()
        );

        // refresh the user key and preserve old secrets
        Covercrypt::refresh_usk(
            &mut rng,
            &mut msk,
            &mut top_secret_fin_usk,
            true,
        )?;

        assert!(
            encrypted_header
                .decrypt(&mut rng, &top_secret_fin_usk, None)
                .unwrap()
                .is_some()
        );

        // refresh the user key and remove old secrets
        Covercrypt::refresh_usk(
            &mut rng,
            &mut msk,
            &mut top_secret_fin_usk,
            false,
        )?;

        assert!(
            encrypted_header
                .decrypt(&mut rng, &top_secret_fin_usk, None)
                .unwrap()
                .is_some()
        );

        Ok(())
    }

    #[test]
    fn test_rename_attribute() -> Result<(), Error> {
        let mut rng = CsRng::from_entropy();
        let (mut msk, pk) = cc_keygen(&mut rng, false)?;

        // New user secret key
        let mut top_secret_fin_usk = Covercrypt::gen_usk(
            &mut rng,
            &mut msk,
            AccessPolicy::parse("SEC::TOP && DPT::FIN")?,
        )?;

        // Encrypt
        let (_, encrypted_header) = EncryptedHeader::generate(
            &mut rng,
            &pk,
            &AccessPolicy::parse("SEC::TOP && DPT::FIN")?,
            None,
            None,
        )?;

        // remove the FIN department
        Covercrypt::edit_msk(&mut msk, |access_structure| {
            access_structure.rename_attribute(
                &QualifiedAttribute::new("DPT".to_owned(), "FIN".to_owned()),
                "Finance".to_string(),
            )
        })?;

        assert!(
            encrypted_header
                .decrypt(&mut rng, &top_secret_fin_usk, None)
                .unwrap()
                .is_some()
        );

        // refresh the user key and preserve old secrets
        Covercrypt::refresh_usk(
            &mut rng,
            &mut msk,
            &mut top_secret_fin_usk,
            false,
        )?;

        assert!(
            encrypted_header
                .decrypt(&mut rng, &top_secret_fin_usk, None)
                .unwrap()
                .is_some()
        );

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_sym_key() -> Result<(), Error> {
        let mut rng = CsRng::from_entropy();
        let (mut msk, pk) = cc_keygen(&mut rng, false)?;

        let (sym_key, encrypted_key) = Covercrypt::encaps(
            &mut rng,
            &pk,
            &AccessPolicy::parse("DPT::MKG && SEC::TOP").unwrap(),
        )?;

        // A user secret key with matching access policy is able to open an
        // encapsulation.
        let usk = Covercrypt::gen_usk(
            &mut rng,
            &mut msk,
            AccessPolicy::parse("(DPT::MKG || DPT::FIN) && SEC::TOP").unwrap(),
        )?;
        let recovered_key = Covercrypt::decaps(&mut rng, &usk, &encrypted_key)?;
        assert_eq!(Some(&sym_key), recovered_key.as_ref());

        // When left implicit, the bottom element of a hierarchical dimension is
        // derived for user secret keys, which prevent them from opening
        // encapsulations for higher attributes.
        let usk = Covercrypt::gen_usk(
            &mut rng,
            &mut msk,
            AccessPolicy::parse("DPT::MKG || DPT::FIN").unwrap(),
        )?;
        let recovered_key = Covercrypt::decaps(&mut rng, &usk, &encrypted_key)?;
        assert!(recovered_key.is_none());

        // When left implicit, the bottom element of a hierarchical dimension is
        // derived for encapsulation, and acts as a broadcast, allowing all user
        // secret keys to open it.
        let (sym_key, encrypted_key) = Covercrypt::encaps(
            &mut rng,
            &pk,
            &AccessPolicy::parse("DPT::MKG").unwrap(),
        )?;

        let usk = Covercrypt::gen_usk(
            &mut rng,
            &mut msk,
            AccessPolicy::parse("(DPT::MKG || DPT::FIN) && SEC::TOP").unwrap(),
        )?;

        let recovered_key = Covercrypt::decaps(&mut rng, &usk, &encrypted_key)?;
        assert_eq!(Some(&sym_key), recovered_key.as_ref());

        let usk = Covercrypt::gen_usk(
            &mut rng,
            &mut msk,
            AccessPolicy::parse("(DPT::MKG || DPT::FIN) && SEC::LOW").unwrap(),
        )?;
        let recovered_key = Covercrypt::decaps(&mut rng, &usk, &encrypted_key)?;
        assert_eq!(Some(&sym_key), recovered_key.as_ref());

        let usk = Covercrypt::gen_usk(
            &mut rng,
            &mut msk,
            AccessPolicy::parse("(DPT::MKG || DPT::FIN)").unwrap(),
        )?;
        let recovered_key = Covercrypt::decaps(&mut rng, &usk, &encrypted_key)?;
        assert_eq!(Some(&sym_key), recovered_key.as_ref());

        Ok(())
    }

    #[test]
    fn test_single_attribute_in_access_policy() -> Result<(), Error> {
        let mut rng = CsRng::from_entropy();
        let (mut msk, _pk) = cc_keygen(&mut rng, false)?;

        //
        // New user secret key
        let _user_key = Covercrypt::gen_usk(
            &mut rng,
            &mut msk,
            AccessPolicy::parse("SEC::TOP")?,
        )?;

        Ok(())
    }

    #[test]
    fn test_rotate_then_encrypt() -> Result<(), Error> {
        let top_secret_ap = &AccessPolicy::parse("SEC::TOP")?;

        let mut rng = CsRng::from_entropy();
        let (mut msk, pk) = cc_keygen(&mut rng, false)?;

        //
        // New user secret key
        let mut top_secret_fin_usk = Covercrypt::gen_usk(
            &mut rng,
            &mut msk,
            AccessPolicy::parse("SEC::TOP && DPT::FIN")?,
        )?;

        //
        // Encrypt
        let (_, encrypted_header) = EncryptedHeader::generate(
            &mut rng,
            &pk,
            &top_secret_ap.clone(),
            None,
            None,
        )?;

        let _plaintext_header =
            encrypted_header.decrypt(&mut rng, &top_secret_fin_usk, None)?;

        assert!(_plaintext_header.is_some());

        //
        // Rotate argument (must update master keys)
        Covercrypt::rekey(
            &mut msk,
            AccessPolicy::Term(QualifiedAttribute::from(("SEC", "TOP"))),
        )?;

        let pk = Covercrypt::gen_pk(&msk, None)?;

        //
        // Encrypt with new attribute
        let (_, encrypted_header) = EncryptedHeader::generate(
            &mut rng,
            &pk,
            &top_secret_ap.clone(),
            None,
            None,
        )?;

        // Decryption fails without refreshing the user key
        assert!(
            encrypted_header
                .decrypt(&mut rng, &top_secret_fin_usk, None)
                .unwrap()
                .is_none()
        );

        Covercrypt::refresh_usk(
            &mut rng,
            &mut msk,
            &mut top_secret_fin_usk,
            false,
        )?;

        // The refreshed key can decrypt the header
        assert!(
            encrypted_header
                .decrypt(&mut rng, &top_secret_fin_usk, None)
                .unwrap()
                .is_some()
        );

        Ok(())
    }

    #[test]
    fn test_broadcast() {
        let mut rng = CsRng::from_entropy();
        let ap = AccessPolicy::parse("*").unwrap();
        let mut msk = Covercrypt::setup(&mut rng).unwrap();
        let pk = Covercrypt::gen_pk(&msk, None).unwrap();
        let usk = Covercrypt::gen_usk(&mut rng, &mut msk, ap.clone()).unwrap();
        let (secret, bc) = Covercrypt::encaps(&mut rng, &pk, &ap).unwrap();
        let res = Covercrypt::decaps(&mut rng, &usk, &bc).unwrap();
        assert_eq!(Some(secret), res);
    }
}
