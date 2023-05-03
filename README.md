# CoverCrypt

![Build status](https://github.com/Cosmian/cover_crypt/actions/workflows/ci.yml/badge.svg)
![latest version](https://img.shields.io/crates/v/cosmian_cover_crypt.svg)

Implementation of the [CoverCrypt](bib/CoverCrypt.pdf) algorithm which allows
creating ciphertexts for a set of attributes and issuing user keys with access
policies over these attributes.

<!-- toc -->

- [Getting started](#getting-started)
- [Building and testing](#building-and-testing)
- [Features](#features)
  * [Key generation](#key-generation)
  * [Policies and partitions](#policies-and-partitions)
  * [Serialization](#serialization)
  * [Symmetric key encapsulation](#symmetric-key-encapsulation)
  * [Secret key decapsulation](#secret-key-decapsulation)
- [Benchmarks](#benchmarks)
- [Documentation](#documentation)

<!-- tocstop -->

## Getting started

See [`examples/runme.rs`](./examples/runme.rs) for a code sample that
introduces the main CoverCrypt functionalities. It can be run using
`cargo run --example runme`.

## Building and testing

To build the core only, run:

```bash
cargo build --release
```

To build everything:

```bash
cargo build --release --all-features
```

The code contains numerous tests that you can run using:

```bash
cargo test --release --all-features
```

Benchmarks can be run using (one can pass any feature flag):

```bash
bash ./benches/generate.sh
```

## Features

In CoverCrypt, messages are encrypted using a symmetric scheme. The right
management is performed by a novel asymmetric scheme used to encapsulate a
symmetric key for a set of attributes. This encapsulation is stored in an
object called encrypted header, along with the symmetric ciphertext.

This design brings several advantages:

- the central authority has a unique key to protect (the master secret key);
- encapsulation can be performed without the need to store any sensitive
  information (public cryptography);
- encryption is as fast as symmetric schemes can be.

CoverCrypt encryption is post-quantum secure (with a post-quantum security
level of 128 bits):

- all encapsulations can be hybridized using INDCPA-KYBER, the INDCPA (a
  security level) version of the NIST standard for the post-quantum KEM,
  [Kyber](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8406610);
  the formal proof of the security can be found in the [CoverCrypt
  paper](#documentation).
- the actual data is encrypted using AES-GCM with a 256-bit key.

The CoverCrypt scheme also ensures that:

- user secret keys are unique;
- user secret keys are traceable (under some assumption, cf
  [CoverCrypt paper](#documentation)).

### Key generation

Asymmetric keys must be generated beforehand. This is the role of a central
authority, which is in charge of:

- generating and updating the master keys according to the right policy;
- generate and update user secret keys according to its rights.

The CoverCrypt API exposes 4 functions:

- `CoverCrypt::generate_master_keys`: generate master keys
- `CoverCrypt::update_master_keys`: update the master keys
- `CoverCrypt::generate_user_secret_key`: create a user secret key
- `CoverCrypt::refresh_user_secret_key`: update a user secret key

The key generations may be long if the policy contains many rights or if there
are many users. But this is usually run once at setup. Key update and refresh
stay fast if the changes are small.

### Policies and partitions

CoverCrypt is an attribute-based encryption algorithm. This means that an
encrypted header produced for the attributes `France` and `Top Secret` can only
be decrypted by the user holding a key corresponding to these attributes.

In order to transform this high-level view into encapsulations, the following
objects are defined:

- **policy**: defines all possible rights; a policy is built from a set of
  axes which are composed of sets of attributes.
- **encryption policy**: subset of the policy used to encrypt; an encryption
  policy is expressed as a boolean expression of attributes.
- **user policy**: subset of the policy for which a user key enables
  decryption; a user policy is expressed as a boolean expression of attributes.
- **partition**: combination of one attribute from each policy axis.

When generating the master keys, the global policy is converted into the set of
all possible partitions and a keypair is generated for each one of these
partitions. The master public key holds all the public key of all these
keypairs and the master secret key holds the secret key of all these keypairs.

When encrypting for a given encryption policy, this policy is converted into a
set of partitions. Then, one key encapsulation is generated per partition using
the corresponding public sub-key in the master public key.

Similarly, when generating a user secret key for a given user policy, this
policy is converted into the set of corresponding partitions and the user
receives the secret sub-key associated to each partitions.

**Example**: the following policy is composed of two axes. The `Security` axis
composed of three attributes and the `Country` axis composed of 4 attributes.

```txt
Polixy: {
 Security: { // <- first axis
  None,
  Medium,
  High
 },
 Country: { // <- second axis
  France,
  Germany,
  UK,
  Spain
 }
}
```

The encryption policy `Security::Medium && ( Country::France ||
Country::Spain)` would be converted into two partitions. The encryption policy
`Security::High` would be expanded into `Security::High && (Country::France ||
... || Country::Spain)` then converted into 4 partitions.

### Serialization

The size of the serialized keys and encapsulation is given by the following formulas:

- master secret key:
$$3 \cdot L_{sk} + \texttt{LEB128sizeof}(n_{p}) + \sum\limits_{p~\in~partitions} \left( \texttt{LEB128sizeof}(\texttt{sizeof}(p)) + \texttt{sizeof}(p) + 1 + L_{sk} + \delta_{p,~h} \cdot L_{sk}^{pq}\right)$$

- public key:

$$3 \cdot L_{pk} + \texttt{LEB128sizeof}(n_{p}) + \sum\limits_{p~\in~partitions} \left( \texttt{LEB128sizeof}(\texttt{sizeof}(p)) + \texttt{sizeof}(p) + 1 + L_{pk} + \delta_{p,~h} \cdot L_{pk}^{pq}\right)$$

- user secret key:

$$2 \cdot L_{sk} + \texttt{LEB128sizeof}(n_{p}) + \sum\limits_{p~\in~partitions} \left( 1 + L_{sk} + \delta_{p,~h} \cdot L_{sk}^{pq}\right)$$

- encapsulation:

$$2 \cdot L_{pk} + T + \texttt{LEB128sizeof}(n_{p}) + \sum\limits_{p~\in~partitions} \left(1 + \delta_{p,~c} \cdot L_{pk} + \delta_{p,~h} \cdot L_c^{pq}\right)$$

- encrypted header (encapsulation and symmetrically encrypted metadata):

$$\texttt{sizeof}(encapsulation) + \texttt{LEB128sizeof} \left(C_{overhead} + \texttt{sizeof}(metadata)\right) + C_{overhead} + \texttt{sizeof}(metadata)$$

where:

- $n_p$ is the number of partitions related to the encryption policy
- $\delta_{p,~c} = 1$ if $p$ is a classic partition, 0 otherwise
- $\delta_{p,~h} = 1 - \delta_{p,~c}$ (i.e. 1 if $p$ is a hybridized partition,
  0 otherwise)
- $\texttt{sizeof}: n \rightarrow$ size of $n$ in bytes
- $\texttt{LEB128sizeof}: n \rightarrow \left\lceil \frac{8 \cdot \texttt{sizeof}(n)}{7}\right\rceil$

**NOTE**: For our implementation `CoverCryptX25519Aes256`:

- Curve25519 public key length: $L_{pk} = 32~\textnormal{bytes}$
- Curve25519 secret key length: $L_{sk} = 32~\textnormal{bytes}$
- INDCPA-Kyber public key length: $L_{pk}^{pq} = 1184$
- INDCPA-Kyber secret key length: $L_{sk}^{pq} = 1152$
- INDCPA-Kyber ciphertext length: $L_c^{pq} = 1088$
- EAKEM tag length: $T = 16~\textnormal{bytes}$
- Symmetric encryption overhead: $C_{overhead} = 28~\textnormal{bytes}$ (16 bytes for the MAC tag and 12 bytes for the nonce)

### Symmetric key encapsulation

This is the core of the CoverCrypt scheme. It allows creating a symmetric key
and its encapsulation for a given set of rights.

To ease the management of the encapsulations, an object `EncryptedHeader`is
provided in the API. An encrypted header holds an encapsulation and a symmetric
ciphertext of an optional additional data. This additional data can be useful
to store metadata.

Classic implementation sizes:

| Nb. of partitions | Encapsulation size (in bytes) | User decryption key size (in bytes) |
|-------------------|-------------------------------|-------------------------------------|
| 1                 | 130                           | 98                                  |
| 2                 | 163                           | 131                                 |
| 3                 | 196                           | 164                                 |
| 4                 | 229                           | 197                                 |
| 5                 | 262                           | 230                                 |

Post-quantum implementation sizes:

| Nb. of partitions | Encapsulation size (in bytes) | User decryption key size (in bytes) |
|-------------------|-------------------------------|-------------------------------------|
| 1                 | 1186                          | 1250                                |
| 2                 | 2275                          | 2435                                |
| 3                 | 3364                          | 3620                                |
| 4                 | 4453                          | 4805                                |
| 5                 | 5542                          | 5990                                |

**Note**: encapsulations grow bigger with the size of the target set of rights
and so does the encapsulation time.

### Secret key decapsulation

A user can retrieve the symmetric key needed to decrypt a CoverCrypt ciphertext
by decrypting the associated `EncryptedHeader`. This is only possible if the
user secret keys contains the appropriate rights.

## Benchmarks

The benchmarks presented in this section are run on a Intel(R) Xeon(R) Platinum 8171M CPU @ 2.60GHz.

- [CoverCrypt classic implementation](./benches/BENCHMARKS_classic.md)
- [CoverCrypt post-quantum implementation](./benches/BENCHMARKS_hybridized.md)

## Documentation

A formal description and proof of the CoverCrypt scheme is given in [this paper](./bib/CoverCrypt.pdf).
It also contains an interesting discussion about the implementation.

The developer documentation can be found on [doc.rs](https://docs.rs/cosmian_cover_crypt/latest/cosmian_cover_crypt/index.html)
