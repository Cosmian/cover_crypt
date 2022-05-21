use crate::{
    cover_crypt_core,
    error::Error,
    policies::{AccessPolicy, Attribute, Policy},
};
use cosmian_crypto_base::{entropy::CsRng, hybrid_crypto::Kem};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::{convert::TryFrom, fmt::Display, marker::PhantomData, ops::DerefMut, sync::Mutex};

const KDF_INFO: &[u8] = b"Need to extend generated secret key.";

/// Partition associated to a KEM keypair. It corresponds to a combination
/// of attributes.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Hash)]
#[serde(try_from = "String", into = "String")]
pub struct Partition(Vec<u8>);

impl Display for Partition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl From<Partition> for String {
    fn from(a: Partition) -> Self {
        format!("{a}")
    }
}

impl TryFrom<String> for Partition {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let res = hex::decode(&value).map_err(|_e| Error::ConversionFailed)?;
        Ok(Partition(res))
    }
}

/// Compute the key hash of a given attribute combination. This key hash is
/// used to select a KEM key.
///
/// - `combination` : attribute combination
pub(crate) fn get_key_hash(combination: &[u32]) -> Vec<u8> {
    let mut combination = combination.to_owned();
    // the sort operation allows to get the same hash for :
    // `Department::HR || Department::FIN`
    // and
    // `Department::FIN || Department::HR`
    combination.sort_unstable();
    let mut bytes = Vec::with_capacity(combination.len() * 4);
    for value in combination {
        bytes.extend(value.to_be_bytes())
    }
    Sha3_256::digest(bytes).to_vec()
}

/// Ciphertext of the CoverCrypt algorithm. This is a `HashMap` of the KEM
/// encapsulations for some authorisations.
pub type CipherText = cover_crypt_core::Encapsulation<Partition>;

/// Private key of the CoverCrypt algorithm. This is a `HashMap` of the KEM
/// private keys for some authorisations.
pub type PrivateKey<KEM> = cover_crypt_core::PrivateKey<Partition, KEM>;

/// Public key of the CoverCrypt algorithm. This is a `HashMap` of the KEM
/// public keys for some authorisations.
pub type PublicKey<KEM> = cover_crypt_core::PublicKey<Partition, KEM>;

/// CoverCrypt public and private key pair.
#[derive(Clone, PartialEq)]
pub struct CCKeyPair<KEM: Kem> {
    pub(crate) pk: PublicKey<KEM>,
    pub(crate) sk: PrivateKey<KEM>,
}

impl<KEM: Kem> CCKeyPair<KEM> {
    pub fn public_key(&self) -> &PublicKey<KEM> {
        &self.pk
    }

    pub fn private_key(&self) -> &PrivateKey<KEM> {
        &self.sk
    }
}

/// The engine is the main entry point for the core functionalities.
///
/// It supplies a simple API that lets generate keys, encrypt and decrypt
/// messages.
///
/// In addition, two methods are supplied to generate random symmetric keys and
/// their corresponding cipher texts which are suitable for use in a hybrid
/// encryption scheme.
pub struct CoverCrypt<KEM> {
    pub(crate) rng: Mutex<CsRng>,
    phantom_kem: PhantomData<KEM>,
}

impl<KEM: Kem> CoverCrypt<KEM> {
    /// Instantiate a new CoverCrypt object.
    pub fn new() -> Self {
        Self {
            rng: Mutex::new(CsRng::new()),
            phantom_kem: PhantomData,
        }
    }

    /// Generate the master authority keys for supplied Policy
    ///
    ///  - `policy` : Policy to use to generate the keys
    pub fn generate_master_keys(
        &self,
        policy: &Policy,
    ) -> Result<(PrivateKey<KEM>, PublicKey<KEM>), Error> {
        // walk the hypercube to recover all the combinations and hash them
        let axes: Vec<&String> = policy.store().keys().collect();
        let keys = walk_hypercube(0, axes.as_slice(), policy)?
            .iter()
            .map(|combination| Partition(get_key_hash(combination)))
            .collect();
        Ok(cover_crypt_core::setup::<_, CsRng, KEM>(
            &mut self.rng.lock().expect("a mutex lock failed"),
            &keys,
        ))
    }

    /// Generate a user private key.
    ///
    /// - `msk`             : master secret key
    /// - `access_policy`   : user access policy
    /// - `policy`          : global policy
    pub fn generate_user_private_key(
        &self,
        msk: &PrivateKey<KEM>,
        access_policy: &AccessPolicy,
        policy: &Policy,
    ) -> Result<PrivateKey<KEM>, Error> {
        // get the key hash associated with the given access policy
        let keys = access_policy
            .to_attribute_combinations(policy)?
            .iter()
            .map(|comb| Partition(get_key_hash(comb)))
            .collect();
        // generate the corresponding user key
        cover_crypt_core::join::<_, KEM>(msk, &keys)
    }

    /// Generate a user public key.
    ///
    /// - `mpk`             : master public key
    /// - `access_policy`   : user access policy
    /// - `policy`          : global policy
    pub fn generate_user_public_key(
        &self,
        mpk: &PublicKey<KEM>,
        access_policy: &AccessPolicy,
        policy: &Policy,
    ) -> Result<PublicKey<KEM>, Error> {
        access_policy
            .to_attribute_combinations(policy)?
            .iter()
            .map(|comb| {
                let partition = Partition(get_key_hash(comb));
                // partition should be contained in the master key in
                // order to generate a valid user key
                let kem_public_key = mpk
                    .get(&partition)
                    .ok_or_else(|| Error::UnknownPartition(format!("{:?}", partition)))?;
                Ok((partition.to_owned(), kem_public_key.to_owned()))
            })
            // `PublicKey` is an alias to a `HashMap` which is collected here
            .collect()
    }

    /// Generate a random symmetric key of `symmetric_key_len` to be used in an
    /// hybrid encryption scheme and generate its CoverCrypt encrypted version with the
    /// supplied policy `attributes`.
    ///
    /// - `policy`          : global policy
    /// - `pk`              : public key
    /// - `access_policy`   : access policy to use for key encryption
    /// - `sym_key_len`     : length of the symmetric key to generate
    pub fn generate_symmetric_key(
        &self,
        policy: &Policy,
        pk: &PublicKey<KEM>,
        access_policy: &AccessPolicy,
        sym_key_len: usize,
    ) -> Result<(Vec<u8>, CipherText), Error> {
        // get the authorisations associated to the given access policy
        let authorisations = access_policy
            .to_attribute_combinations(policy)?
            .iter()
            .map(|comb| Partition(get_key_hash(comb)))
            .collect();
        let (mut K, E) = cover_crypt_core::encaps::<_, _, KEM>(
            &mut self.rng.lock().expect("Mutex lock failed!").deref_mut(),
            pk,
            &authorisations,
        )?;
        // expend keying data if needed
        if sym_key_len > K.len() {
            K = cosmian_crypto_base::kdf::hkdf_256(&K, sym_key_len, KDF_INFO)
                .map_err(Error::CryptoError)?;
        } else {
            K = K[..sym_key_len].to_owned();
        }
        Ok((K, E))
    }

    /// Decrypt a symmetric key generated with `generate_symmetric_key()`
    ///
    /// - `sk_u`        : user secret key
    /// - `c`           : encrypted symmetric key
    /// - `sym_key_len` : length of the symmetric key to generate
    pub fn decrypt_symmetric_key(
        &self,
        sk_u: &PrivateKey<KEM>,
        c: &CipherText,
        sym_key_len: usize,
    ) -> Result<Vec<u8>, Error> {
        let key =
            cover_crypt_core::decaps::<_, KEM>(sk_u, c)?.ok_or(Error::InsufficientAccessPolicy)?;
        if sym_key_len > key.len() {
            cosmian_crypto_base::kdf::hkdf_256(&key, sym_key_len, KDF_INFO)
                .map_err(Error::CryptoError)
        } else {
            Ok(key[..sym_key_len].to_owned())
        }
    }
}

impl<KEM: Kem> Default for CoverCrypt<KEM> {
    fn default() -> Self {
        Self::new()
    }
}

/// For all attributes in the given axis, return the combination of its values
/// with the values of all other remaining axes. The combination is made by
/// concatenating the Big Endian bytes of the attributes values.
///
/// - `current_axis`    : index of the axis being processed in the list of axes
/// - `axes`            : list of axes
/// - `policy`          : global policy
pub(crate) fn walk_hypercube(
    current_axis: usize,
    axes: &[&String],
    policy: &Policy,
) -> Result<Vec<Vec<u32>>, Error> {
    // get the current axis or return if there is no more axis
    let axis = match axes.get(current_axis) {
        None => return Ok(vec![]),
        Some(axis) => *axis,
    };
    // extract all attribute values from this axis
    let (attribute_names, _) = policy
        .store()
        .get(axis)
        .ok_or_else(|| Error::UnknownPartition(format!("{:?}", axis)))?;
    // there will be at least one value per attribute name
    let mut res = Vec::with_capacity(attribute_names.len());
    for name in attribute_names.iter() {
        res.extend(policy.attribute_values(&Attribute::new(axis, name))?);
    }
    // combine these values with all attribute values from the next axis
    let mut combinations: Vec<Vec<u32>> = vec![];
    for value in res {
        let other_values = walk_hypercube(current_axis + 1, axes, policy)?;
        if other_values.is_empty() {
            combinations.push(vec![value]);
        } else {
            for ov in other_values {
                let mut combined = Vec::with_capacity(1 + ov.len());
                combined.push(value);
                combined.extend_from_slice(&ov);
                combinations.push(combined);
            }
        }
    }
    Ok(combinations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policies::{Attribute, PolicyAxis};
    use cosmian_crypto_base::asymmetric::ristretto::X25519Crypto;
    use eyre::Result;

    #[test]
    fn test_hypercube() -> Result<(), Error> {
        let sec_level = PolicyAxis::new(
            "Security Level",
            &["Protected", "Confidential", "Top Secret"],
            true,
        );
        let department = PolicyAxis::new("Department", &["R&D", "HR", "MKG", "FIN"], false);
        let mut policy = Policy::new(100);
        policy.add_axis(&sec_level)?;
        policy.add_axis(&department)?;
        // rotate an attributes
        policy.rotate(&Attribute::new("Department", "FIN"))?;
        let axes: Vec<&String> = policy.store().keys().collect();
        let walk = walk_hypercube(0, &axes, &policy)?;
        assert!(
            walk == [
                // Protected && R&D
                [1, 4],
                // Protected && HR
                [1, 5],
                // Protected && MKG
                [1, 6],
                // Protected && FIN after rotation
                [1, 8],
                // Protected && FIN before rotation
                [1, 7],
                // Confidential && R&D
                [2, 4],
                // Confidential && HR
                [2, 5],
                // Confidential && MKG
                [2, 6],
                // Confidential && FIN after rotation
                [2, 8],
                // Confidential && FIN before rotation
                [2, 7],
                // Top Secret && R&D
                [3, 4],
                // Top Secret && HR
                [3, 5],
                // Top Secret && MKG
                [3, 6],
                // Top Secret && FIN after rotation
                [3, 8],
                // Top Secret && FIN before rotation
                [3, 7]
            ] || walk
                == [
                    [4, 1],
                    [4, 2],
                    [4, 3],
                    [5, 1],
                    [5, 2],
                    [5, 3],
                    [6, 1],
                    [6, 2],
                    [6, 3],
                    [8, 1],
                    [8, 2],
                    [8, 3],
                    [7, 1],
                    [7, 2],
                    [7, 3],
                ]
        );
        Ok(())
    }

    #[test]
    fn encrypt_decrypt_sym_key() -> Result<()> {
        const KEY_LENGTH: usize = 256;
        let sec_level = PolicyAxis::new(
            "Security Level",
            &["Protected", "Confidential", "Top Secret"],
            true,
        );
        let department = PolicyAxis::new("Department", &["R&D", "HR", "MKG", "FIN"], false);
        let mut policy = Policy::new(100);
        policy.add_axis(&sec_level)?;
        policy.add_axis(&department)?;
        policy.rotate(&Attribute::new("Department", "FIN"))?;
        let access_policy = (AccessPolicy::new("Department", "R&D")
            | AccessPolicy::new("Department", "FIN"))
            & AccessPolicy::new("Security Level", "Top Secret");
        let cc = CoverCrypt::<X25519Crypto>::default();
        let (msk, mpk) = cc.generate_master_keys(&policy)?;
        let sk_u = cc.generate_user_private_key(&msk, &access_policy, &policy)?;
        let (key, encrypted_key) =
            cc.generate_symmetric_key(&policy, &mpk, &access_policy, KEY_LENGTH)?;
        let recovered_key = cc.decrypt_symmetric_key(&sk_u, &encrypted_key, KEY_LENGTH)?;
        eyre::ensure!(key == recovered_key, "Wrong decryption of the key!");
        Ok(())
    }
}
