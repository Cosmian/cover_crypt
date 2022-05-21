use crate::{error::Error, utils};
use cosmian_crypto_base::{asymmetric::KeyPair, hybrid_crypto::Kem};
use rand_core::{CryptoRng, RngCore};
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
};

/// CovCrypt private keys are a set of KEM private keys.
pub type PrivateKey<A, KEM> = HashMap<A, <<KEM as Kem>::KeyPair as KeyPair>::PrivateKey>;

/// CovCrypt public keys are a set of KEM public keys.
pub type PublicKey<A, KEM> = HashMap<A, <<KEM as Kem>::KeyPair as KeyPair>::PublicKey>;

/// CovCrypt ciphertexts are a list of secret key / encapsulation couples
/// generated by the underlying KEM scheme.
pub type Encapsulation<A> = HashMap<A, (Vec<u8>, Vec<u8>)>;

/// CovCrypt secret key is a vector of bytes of the same length as secret key
/// of the underlying KEM.
pub type SecretKey = Vec<u8>;

/// Generate the master private key and master public key of the CoverCrypt scheme.
///
/// - `n`   : number of partition groups
///
/// Setup : `λ → (msk,mpk)`
///  - takes the security parameter (number of security bits we would like to
/// reach).
///
/// It first defines the partition of subsets Sᵢ that covers the set S
/// with respect to the target users’ rights.
///
/// And for each Sᵢ, it invokes (`KEM.KeyGen` which outputs `(pkᵢ,skᵢ)` and
/// defines `mpk = (pkᵢ)ᵢ` and `msk = (skᵢ)ᵢ` the master public key and master
/// secret key.
pub fn setup<A, R, KEM>(rng: &mut R, S: &HashSet<A>) -> (PrivateKey<A, KEM>, PublicKey<A, KEM>)
where
    A: Clone + Eq + Hash + Debug,
    R: CryptoRng + RngCore,
    KEM: Kem,
{
    let (mut msk, mut mpk) = (
        HashMap::with_capacity(S.len()),
        HashMap::with_capacity(S.len()),
    );
    for partition in S.iter() {
        let keypair = KEM::key_gen(rng);
        msk.insert(partition.to_owned(), keypair.private_key().to_owned());
        mpk.insert(partition.to_owned(), keypair.public_key().to_owned());
    }
    (msk, mpk)
}

/// Generate a user private key for a given list of user groups. It is composed
/// by the list of the KEM private keys associated with the user groups
/// containing the given user ID.
///
/// - `msk` : master secret key
/// - `U`   : user partitions
///
/// Join : `(msk, U) → skU`
///
/// For a user U, define skU as the set of secret keys ski for each i such that
/// U ∈ Si (meaning U has rights associated to set Si).
pub fn join<A, KEM>(msk: &PrivateKey<A, KEM>, U: &HashSet<A>) -> Result<PrivateKey<A, KEM>, Error>
where
    A: Clone + Eq + Hash + Debug,
    KEM: Kem,
{
    U.iter()
        .map(
            |partition| -> Result<(A, <KEM::KeyPair as KeyPair>::PrivateKey), Error> {
                let kem_private_ley = msk
                    .get(partition)
                    .ok_or_else(|| Error::UnknownPartition(format!("{:?}", partition)))?;
                Ok((partition.to_owned(), kem_private_ley.to_owned()))
            },
        )
        .collect::<Result<PrivateKey<A, KEM>, Error>>()
}

/// Generate the secret key and its encapsulation.
///
/// - `rng` : secure random number generator
/// - `mpk` : master public key
/// - `T`   : target groups
/// - `S`   : user groups
///
/// Encaps : `(mpk, T) → C = (K, Ci = (Ki ⊕ K, Ei)i∈A)`
///
/// Takes as input mpk and target set T. It first samples a random key K and
/// express T as set of covering subsets, i.e T = ∪i∈ASi.
/// Then for each i ∈ A, it invokes KEM.Encaps which Ci = (Ki, Ei)i∈A. It
/// finally returns (K, C = (Ki ⊕ K, Ei)i∈A).
pub fn encaps<A, R, KEM>(
    rng: &mut R,
    mpk: &PublicKey<A, KEM>,
    T: &HashSet<A>,
) -> Result<(SecretKey, Encapsulation<A>), Error>
where
    A: Clone + Eq + Hash + Debug,
    R: CryptoRng + RngCore,
    KEM: Kem,
{
    // secret key
    let K = utils::generate_random_bytes(rng, KEM::SECRET_KEY_LENGTH);

    // construct secret key encapsulation
    let mut E = HashMap::with_capacity(T.len());
    for partition in T.iter() {
        match mpk.get(partition) {
            Some(pk) => {
                let (K_i, E_i) = KEM::encaps(rng, pk).map_err(Error::CryptoError)?;
                E.insert(
                    partition.to_owned(),
                    (
                        K_i.iter().zip(K.iter()).map(|(e1, e2)| e1 ^ e2).collect(),
                        E_i,
                    ),
                );
                Ok(())
            }
            None => Err(Error::UnknownPartition(format!("{:?}", partition))),
        }?;
    }

    Ok((K, E))
}

/// Decapsulate the secret key if the given user ID is in the target set.
///
/// - `uid`     : user ID
/// - `sk_u`    : user private key
/// - `E`       : encapsulation
/// - `T`       : target set
/// - `S`       : list of all user groups
///
/// • Decaps: (skU, C) → K
///
/// Let T = ∪i∈BSi for some integers set B and A the indices of sets associated
/// to C.
/// If user U is in T, and there exists an index i ∈ A such that U is in
/// Si ⊆ T, it invokes KEM.Decaps(ski, Ei) which gives Ki. Then using the
/// corresponding Ci parsed as Ki', Ei, it obtains K = Ki' ⊕ Ki.
pub fn decaps<A, KEM>(
    sk_u: &PrivateKey<A, KEM>,
    E: &Encapsulation<A>,
) -> Result<Option<SecretKey>, Error>
where
    A: Clone + Eq + Hash + Debug,
    KEM: Kem,
{
    for (partition, (Ki_1, E_i)) in E.iter() {
        if let Some(sk) = sk_u.get(partition) {
            let Ki_2 = KEM::decaps(sk, E_i).map_err(Error::CryptoError)?;

            // XOR the two `K_i`
            let K = Ki_1
                .iter()
                .zip(Ki_2.iter())
                .map(|(e1, e2)| e1 ^ e2)
                .collect();
            return Ok(Some(K));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmian_crypto_base::asymmetric::ristretto::X25519Crypto;
    use cosmian_crypto_base::entropy::CsRng;
    use eyre::Result;

    #[test]
    fn test_cover_crypt() -> Result<()> {
        // partition list
        let S = HashSet::from(["admin", "dev"]);
        // user list
        let U = vec![HashSet::from(["dev"]), HashSet::from(["admin", "dev"])];
        // target set
        let T = HashSet::from(["admin"]);
        // secure random number generator
        let mut rng = CsRng::new();
        // setup scheme
        let (msk, mpk) = setup::<_, _, X25519Crypto>(&mut rng, &S);
        // generate user private keys
        let sk0 = join::<_, X25519Crypto>(&msk, &U[0])?;
        let sk1 = join::<_, X25519Crypto>(&msk, &U[1])?;
        // encapsulate for the target set
        let (K, E) = encaps::<_, _, X25519Crypto>(&mut rng, &mpk, &T)?;
        // decapsulate for users 1 and 3
        let res0 = decaps::<_, X25519Crypto>(&sk0, &E)?;
        let res1 = decaps::<_, X25519Crypto>(&sk1, &E)?;
        eyre::ensure!(res0.is_none(), "User 0 shouldn't be able to decapsulate!");
        eyre::ensure!(Some(K) == res1, "Wrong decapsulation for user 1!");
        Ok(())
    }
}
