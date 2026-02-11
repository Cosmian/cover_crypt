#![allow(clippy::type_complexity)]
use crate::{
    providers::kem::mlkem::{MlKem512, MlKem768},
    traits::KemAc,
    AccessPolicy, AccessStructure, Covercrypt, Error, MasterPublicKey, MasterSecretKey,
    UserSecretKey, XEnc,
};
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    reexport::rand_core::{CryptoRngCore, SeedableRng},
    traits::{cyclic_group_to_kem::GenericKem, KEM},
    CsRng, SymmetricKey,
};
use cosmian_openssl_provider::{hash::Sha256, kem::MonadicKEM, p256::P256};
use cosmian_rust_curve25519_provider::R25519;
use zeroize::Zeroizing;

// In order to avoid defining one enumeration type per KEM object with one
// variant per concrete KEM option, this module uses dynamic typing on the
// concrete key and encapsulation types by to consuming and returning byte
// strings. Serialization can be used once the concrete KEM is chosen to
// retrieve the typed objects.
//
// The following functions implement this logic: they are parametric on a KEM
// type -- and thus need to be called once the concrete KEM implementation is
// known, and perform both the KEM operation and serialization/deserialization
// of the key and encapsulation objects.

#[allow(clippy::type_complexity)]
fn generic_keygen<const KEY_LENGTH: usize, Kem: KEM<KEY_LENGTH>>(
    rng: &mut impl CryptoRngCore,
) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), Error>
where
    Kem::DecapsulationKey: Serializable,
{
    let (dk, ek) = Kem::keygen(rng).map_err(|e| Error::Kem(e.to_string()))?;
    Ok((
        dk.serialize()
            .map_err(|e| Error::ConversionFailed(format!("DK serialization error in KEM: {e}")))?,
        ek.serialize()
            .map_err(|e| Error::ConversionFailed(format!("EK serialization error in KEM: {e}")))?,
    ))
}

fn generic_enc<const KEY_LENGTH: usize, Kem: KEM<KEY_LENGTH>>(
    ek: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<(SymmetricKey<KEY_LENGTH>, Zeroizing<Vec<u8>>), Error> {
    let ek = <Kem as KEM<KEY_LENGTH>>::EncapsulationKey::deserialize(ek)
        .map_err(|e| Error::ConversionFailed(format!("EK deserialization error in KEM: {e}")))?;
    let (key, enc) = Kem::enc(&ek, rng).map_err(|e| Error::Kem(e.to_string()))?;
    Ok((
        key,
        enc.serialize().map_err(|e| {
            Error::ConversionFailed(format!("encapsulation serialization error in KEM: {e}"))
        })?,
    ))
}

fn generic_dec<const KEY_LENGTH: usize, Kem: KEM<KEY_LENGTH>>(
    dk: &[u8],
    enc: &[u8],
) -> Result<SymmetricKey<KEY_LENGTH>, Error>
where
    Kem::DecapsulationKey: Serializable,
{
    let dk = <Kem as KEM<KEY_LENGTH>>::DecapsulationKey::deserialize(dk)
        .map_err(|e| Error::ConversionFailed(format!("DK deserialization error in KEM: {e}")))?;
    let enc = <Kem as KEM<KEY_LENGTH>>::Encapsulation::deserialize(enc).map_err(|e| {
        Error::ConversionFailed(format!("encapsulation deserialization error in KEM: {e}"))
    })?;
    Kem::dec(&dk, &enc).map_err(|e| Error::Kem(e.to_string()))
}

// However, in order to enforce type safety, KEM objects must be tagged by the
// concrete KEM used.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PreQuantumKemTag {
    P256,
    R25519,
}

impl Serializable for PreQuantumKemTag {
    type Error = Error;

    fn length(&self) -> usize {
        1
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        match self {
            Self::P256 => ser.write(&1_u64),
            Self::R25519 => ser.write(&2_u64),
        }
        .map_err(Error::from)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        match de.read::<u64>()? {
            1 => Ok(Self::P256),
            2 => Ok(Self::R25519),
            n => Err(Error::ConversionFailed(format!(
                "{n} is not a valid pre-quantum-KEM tag"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PostQuantumKemTag {
    MlKem512,
    MlKem768,
}

impl Serializable for PostQuantumKemTag {
    type Error = Error;

    fn length(&self) -> usize {
        1
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        match self {
            Self::MlKem512 => ser.write(&1_u64),
            Self::MlKem768 => ser.write(&2_u64),
        }
        .map_err(Error::from)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        match de.read::<u64>()? {
            1 => Ok(Self::MlKem512),
            2 => Ok(Self::MlKem768),
            n => Err(Error::ConversionFailed(format!(
                "{n} is not a valid post-quantum-KEM tag"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KemTag {
    PreQuantum(PreQuantumKemTag),
    PostQuantum(PostQuantumKemTag),
    Hybridized(PreQuantumKemTag, PostQuantumKemTag),
    Abe,
}

impl Serializable for KemTag {
    type Error = Error;

    fn length(&self) -> usize {
        match self {
            Self::PreQuantum(_) | Self::PostQuantum(_) => 2,
            Self::Hybridized(_, _) => 3,
            Self::Abe => 1,
        }
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        match self {
            Self::PreQuantum(tag) => Ok(ser.write(&1_u64)? + ser.write(tag)?),
            Self::PostQuantum(tag) => Ok(ser.write(&2_u64)? + ser.write(tag)?),
            Self::Hybridized(tag1, tag2) => {
                Ok(ser.write(&3_u64)? + ser.write(tag1)? + ser.write(tag2)?)
            }
            Self::Abe => Ok(ser.write(&4_u64)?),
        }
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        match de.read::<usize>()? {
            1 => de.read::<PreQuantumKemTag>().map(Self::PreQuantum),
            2 => de.read::<PostQuantumKemTag>().map(Self::PostQuantum),
            3 => de
                .read::<(PreQuantumKemTag, PostQuantumKemTag)>()
                .map(|(tag1, tag2)| Self::Hybridized(tag1, tag2))
                .map_err(Self::Error::from),
            4 => Ok(Self::Abe),
            n => Err(Error::ConversionFailed(format!(
                "{n} is not a valid KEM tag"
            ))),
        }
    }
}

// Finally, we can implement a KEM-like interface for our configurable KEM which
// deserializes KEM objects as couple (tag, bytes), checks tag legality and
// compatibility across objects before the KEM operation with corresponding
// implementation, and finally serializes returned objects as (tag, bytes)
// couples.

type P256Kem = MonadicKEM<32, P256, Sha256>;
type R25519Kem = GenericKem<32, R25519, Sha256>;

// Even though lengths of the keys encapsulated by the two combined KEM schemes
// can vary, it is much simpler to enforce their equality, which is performed
// here by binding the three key lengths required by the KEM combiner to the
// same one.
type KemCombiner<const LENGTH: usize, Kem1, Kem2> =
    cosmian_crypto_core::traits::kem_combiner::KemCombiner<
        LENGTH,
        LENGTH,
        LENGTH,
        Kem1,
        Kem2,
        Sha256, // SHA256 from the OpenSSL provider.
    >;

pub struct ConfigurableKEM;

impl ConfigurableKEM {
    #[allow(clippy::too_many_arguments)]
    pub fn keygen(
        tag: KemTag,
        access_structure: Option<AccessStructure>,
    ) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), Error> {
        let rng = &mut CsRng::from_entropy();

        let (dk_bytes, ek_bytes) = match tag {
            KemTag::PreQuantum(PreQuantumKemTag::P256) => {
                generic_keygen::<{ P256Kem::KEY_LENGTH }, P256Kem>(rng)
            }
            KemTag::PreQuantum(PreQuantumKemTag::R25519) => {
                generic_keygen::<{ R25519Kem::KEY_LENGTH }, R25519Kem>(rng)
            }
            KemTag::PostQuantum(PostQuantumKemTag::MlKem512) => {
                generic_keygen::<{ MlKem512::KEY_LENGTH }, MlKem512>(rng)
            }
            KemTag::PostQuantum(PostQuantumKemTag::MlKem768) => {
                generic_keygen::<{ MlKem768::KEY_LENGTH }, MlKem768>(rng)
            }
            KemTag::Hybridized(PreQuantumKemTag::P256, PostQuantumKemTag::MlKem512) => {
                generic_keygen::<
                    { P256Kem::KEY_LENGTH },
                    KemCombiner<{ P256Kem::KEY_LENGTH }, P256Kem, MlKem512>,
                >(rng)
            }
            KemTag::Hybridized(PreQuantumKemTag::P256, PostQuantumKemTag::MlKem768) => {
                generic_keygen::<
                    { P256Kem::KEY_LENGTH },
                    KemCombiner<{ P256Kem::KEY_LENGTH }, P256Kem, MlKem768>,
                >(rng)
            }
            KemTag::Hybridized(PreQuantumKemTag::R25519, PostQuantumKemTag::MlKem512) => {
                generic_keygen::<
                    { R25519Kem::KEY_LENGTH },
                    KemCombiner<{ R25519Kem::KEY_LENGTH }, R25519Kem, MlKem512>,
                >(rng)
            }
            KemTag::Hybridized(PreQuantumKemTag::R25519, PostQuantumKemTag::MlKem768) => {
                generic_keygen::<
                    { R25519Kem::KEY_LENGTH },
                    KemCombiner<{ R25519Kem::KEY_LENGTH }, R25519Kem, MlKem768>,
                >(rng)
            }
            KemTag::Abe => {
                let access_structure = access_structure.ok_or_else(|| {
                    Error::OperationNotPermitted(
                        "cannot execute a Covercrypt key generation without an access structure"
                            .to_owned(),
                    )
                })?;
                let cc = Covercrypt::default();
                let (mut msk, _) = cc.setup()?;
                msk.access_structure = access_structure;
                let mpk = cc.update_msk(&mut msk)?;
                Ok((msk.serialize()?, mpk.serialize()?))
            }
        }?;

        Ok(((tag, dk_bytes).serialize()?, (tag, ek_bytes).serialize()?))
    }

    pub fn enc(
        ek_bytes: &[u8],
        access_policy: Option<&AccessPolicy>,
    ) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), Error> {
        let (tag, ek_bytes) =
            <(KemTag, Zeroizing<Vec<u8>>)>::deserialize(ek_bytes).map_err(|e| {
                Error::ConversionFailed(format!(
                    "failed deserializing the tag and encapsulation key in configurable KEM: {e}"
                ))
            })?;

        let rng = &mut CsRng::from_entropy();
        match tag {
            KemTag::PreQuantum(PreQuantumKemTag::P256) => {
                generic_enc::<{ P256Kem::KEY_LENGTH }, P256Kem>(&ek_bytes, rng)
                    .and_then(|(key, enc)| Ok((key.serialize()?, (tag, enc).serialize()?)))
            }
            KemTag::PreQuantum(PreQuantumKemTag::R25519) => {
                generic_enc::<{ R25519Kem::KEY_LENGTH }, R25519Kem>(&ek_bytes, rng)
                    .and_then(|(key, enc)| Ok((key.serialize()?, (tag, enc).serialize()?)))
            }
            KemTag::PostQuantum(PostQuantumKemTag::MlKem512) => {
                generic_enc::<{ MlKem512::KEY_LENGTH }, MlKem512>(&ek_bytes, rng)
                    .and_then(|(key, enc)| Ok((key.serialize()?, (tag, enc).serialize()?)))
            }
            KemTag::PostQuantum(PostQuantumKemTag::MlKem768) => {
                generic_enc::<{ MlKem768::KEY_LENGTH }, MlKem768>(&ek_bytes, rng)
                    .and_then(|(key, enc)| Ok((key.serialize()?, (tag, enc).serialize()?)))
            }
            KemTag::Hybridized(PreQuantumKemTag::P256, PostQuantumKemTag::MlKem512) => {
                generic_enc::<
                    { P256Kem::KEY_LENGTH },
                    KemCombiner<{ P256Kem::KEY_LENGTH }, P256Kem, MlKem512>,
                >(&ek_bytes, rng)
                .and_then(|(key, enc)| Ok((key.serialize()?, (tag, enc).serialize()?)))
            }
            KemTag::Hybridized(PreQuantumKemTag::P256, PostQuantumKemTag::MlKem768) => {
                generic_enc::<
                    { P256Kem::KEY_LENGTH },
                    KemCombiner<{ P256Kem::KEY_LENGTH }, P256Kem, MlKem768>,
                >(&ek_bytes, rng)
                .and_then(|(key, enc)| Ok((key.serialize()?, (tag, enc).serialize()?)))
            }
            KemTag::Hybridized(PreQuantumKemTag::R25519, PostQuantumKemTag::MlKem512) => {
                generic_enc::<
                    { R25519Kem::KEY_LENGTH },
                    KemCombiner<{ R25519Kem::KEY_LENGTH }, R25519Kem, MlKem512>,
                >(&ek_bytes, rng)
                .and_then(|(key, enc)| Ok((key.serialize()?, (tag, enc).serialize()?)))
            }
            KemTag::Hybridized(PreQuantumKemTag::R25519, PostQuantumKemTag::MlKem768) => {
                generic_enc::<
                    { R25519Kem::KEY_LENGTH },
                    KemCombiner<{ R25519Kem::KEY_LENGTH }, R25519Kem, MlKem768>,
                >(&ek_bytes, rng)
                .and_then(|(key, enc)| Ok((key.serialize()?, (tag, enc).serialize()?)))
            }
            KemTag::Abe => {
                let ap = access_policy.ok_or_else(|| {
                    Error::OperationNotPermitted(
                        "cannot create a Covercrypt encapsulation without an access policy"
                            .to_owned(),
                    )
                })?;
                let mpk = MasterPublicKey::deserialize(&ek_bytes)?;
                let (key, enc) = Covercrypt::default().encaps(&mpk, ap)?;
                Ok((key.serialize()?, (tag, enc.serialize()?).serialize()?))
            }
        }
    }

    pub fn usk_gen(
        msk: Zeroizing<Vec<u8>>,
        access_policy: &AccessPolicy,
    ) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), Error> {
        let (tag, msk_bytes) = <(KemTag, Zeroizing<Vec<u8>>)>::deserialize(&msk).map_err(|e| {
            Error::ConversionFailed(format!(
                "failed deserializing CoverCrypt MSK in configurable KEM: {e}"
            ))
        })?;

        let mut msk = MasterSecretKey::deserialize(&msk_bytes)?;
        let usk = Covercrypt::default().generate_user_secret_key(&mut msk, access_policy)?;

        Ok((
            (tag, msk.serialize()?).serialize()?,
            (tag, usk.serialize()?).serialize()?,
        ))
    }

    pub fn dec(dk: &[u8], enc: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let (dk_tag, dk_bytes) = <(KemTag, Vec<u8>)>::deserialize(dk).map_err(|e| {
            Error::ConversionFailed(format!(
                "failed deserializing the tag and decapsulation key in configurable KEM: {e}"
            ))
        })?;

        let (enc_tag, enc_bytes) = <(KemTag, Vec<u8>)>::deserialize(enc).map_err(|e| {
            Error::ConversionFailed(format!(
                "failed deserializing the tag and encapsulation in configurable KEM: {e}"
            ))
        })?;

        if dk_tag != enc_tag {
            return Err(Error::OperationNotPermitted(format!(
                "heterogeneous decapsulation-key and encapsulation tags: {dk_tag:?} != {enc_tag:?}"
            )));
        }

        match dk_tag {
            KemTag::PreQuantum(PreQuantumKemTag::P256) => {
                generic_dec::<{ P256Kem::KEY_LENGTH }, P256Kem>(&dk_bytes, &enc_bytes)
                    .and_then(|key| key.serialize().map_err(Error::from))
            }
            KemTag::PreQuantum(PreQuantumKemTag::R25519) => {
                generic_dec::<{ R25519Kem::KEY_LENGTH }, R25519Kem>(&dk_bytes, &enc_bytes)
                    .and_then(|key| key.serialize().map_err(Error::from))
            }
            KemTag::PostQuantum(PostQuantumKemTag::MlKem512) => {
                generic_dec::<{ MlKem512::KEY_LENGTH }, MlKem512>(&dk_bytes, &enc_bytes)
                    .and_then(|key| key.serialize().map_err(Error::from))
            }
            KemTag::PostQuantum(PostQuantumKemTag::MlKem768) => {
                generic_dec::<{ MlKem768::KEY_LENGTH }, MlKem768>(&dk_bytes, &enc_bytes)
                    .and_then(|key| key.serialize().map_err(Error::from))
            }
            KemTag::Hybridized(PreQuantumKemTag::P256, PostQuantumKemTag::MlKem512) => {
                generic_dec::<
                    { P256Kem::KEY_LENGTH },
                    KemCombiner<{ P256Kem::KEY_LENGTH }, P256Kem, MlKem512>,
                >(&dk_bytes, &enc_bytes)
                .and_then(|key| key.serialize().map_err(Error::from))
            }
            KemTag::Hybridized(PreQuantumKemTag::P256, PostQuantumKemTag::MlKem768) => {
                generic_dec::<
                    { P256Kem::KEY_LENGTH },
                    KemCombiner<{ P256Kem::KEY_LENGTH }, P256Kem, MlKem768>,
                >(&dk_bytes, &enc_bytes)
                .and_then(|key| key.serialize().map_err(Error::from))
            }
            KemTag::Hybridized(PreQuantumKemTag::R25519, PostQuantumKemTag::MlKem512) => {
                generic_dec::<
                    { R25519Kem::KEY_LENGTH },
                    KemCombiner<{ R25519Kem::KEY_LENGTH }, R25519Kem, MlKem512>,
                >(&dk_bytes, &enc_bytes)
                .and_then(|key| key.serialize().map_err(Error::from))
            }
            KemTag::Hybridized(PreQuantumKemTag::R25519, PostQuantumKemTag::MlKem768) => {
                generic_dec::<
                    { R25519Kem::KEY_LENGTH },
                    KemCombiner<{ R25519Kem::KEY_LENGTH }, R25519Kem, MlKem768>,
                >(&dk_bytes, &enc_bytes)
                .and_then(|key| key.serialize().map_err(Error::from))
            }
            KemTag::Abe => {
                let usk = UserSecretKey::deserialize(&dk_bytes)?;
                let enc = XEnc::deserialize(&enc_bytes)?;
                let key = Covercrypt::default().decaps(&usk, &enc)?.ok_or_else(|| {
                    Error::OperationNotPermitted(
                        "cannot open Covercrypt encapsulation: incompatible access rights"
                            .to_owned(),
                    )
                })?;
                Ok(key.serialize()?)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::gen_structure;

    use super::*;
    use cosmian_crypto_core::bytes_ser_de::test_serialization;

    #[test]
    fn test_tag_serialization() {
        // Exhaustively test serializations.
        test_serialization(&KemTag::PreQuantum(PreQuantumKemTag::P256)).unwrap();
        test_serialization(&KemTag::PreQuantum(PreQuantumKemTag::R25519)).unwrap();
        test_serialization(&KemTag::PostQuantum(PostQuantumKemTag::MlKem512)).unwrap();
        test_serialization(&KemTag::Hybridized(
            PreQuantumKemTag::P256,
            PostQuantumKemTag::MlKem512,
        ))
        .unwrap();
        test_serialization(&KemTag::Hybridized(
            PreQuantumKemTag::R25519,
            PostQuantumKemTag::MlKem512,
        ))
        .unwrap();
        test_serialization(&KemTag::Abe).unwrap();
    }

    #[test]
    fn test_configurable_kem() {
        fn run_test(tag: KemTag) {
            let (dk, ek) = ConfigurableKEM::keygen(tag, None).unwrap();
            let (key, enc) = ConfigurableKEM::enc(&ek, None).unwrap();
            let key_ = ConfigurableKEM::dec(&dk, &enc).unwrap();
            assert_eq!(key, key_);
        }

        run_test(KemTag::PreQuantum(PreQuantumKemTag::P256));

        run_test(KemTag::PreQuantum(PreQuantumKemTag::R25519));

        run_test(KemTag::PostQuantum(PostQuantumKemTag::MlKem512));

        run_test(KemTag::PostQuantum(PostQuantumKemTag::MlKem768));

        run_test(KemTag::Hybridized(
            PreQuantumKemTag::P256,
            PostQuantumKemTag::MlKem512,
        ));

        run_test(KemTag::Hybridized(
            PreQuantumKemTag::P256,
            PostQuantumKemTag::MlKem768,
        ));

        run_test(KemTag::Hybridized(
            PreQuantumKemTag::R25519,
            PostQuantumKemTag::MlKem512,
        ));
        run_test(KemTag::Hybridized(
            PreQuantumKemTag::R25519,
            PostQuantumKemTag::MlKem768,
        ));

        println!("testing CoverCrypt ABE...");
        let mut access_structure = AccessStructure::new();
        gen_structure(&mut access_structure, true).unwrap();
        let usk_access_policy = AccessPolicy::parse("DPT::MKG").unwrap();
        let enc_access_policy = AccessPolicy::parse("*").unwrap();

        let (msk, mpk) = ConfigurableKEM::keygen(KemTag::Abe, Some(access_structure)).unwrap();
        let (_msk, usk) = ConfigurableKEM::usk_gen(msk, &usk_access_policy).unwrap();
        let (key, enc) = ConfigurableKEM::enc(&mpk, Some(&enc_access_policy)).unwrap();
        let key_ = ConfigurableKEM::dec(&usk, &enc).unwrap();
        assert_eq!(key, key_);
    }
}
