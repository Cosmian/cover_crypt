# CoverCrypt &emsp; [![Build Status]][actions] [![Latest Version]][crates.io]

[build status]: https://img.shields.io/github/workflow/status/Cosmian/cosmian_cover_crypt/CI%20checks/main
[actions]: https://github.com/Cosmian/cosmian_cover_crypt/actions?query=branch%3Amain
[latest version]: https://img.shields.io/crates/v/cosmian_cover_crypt.svg
[crates.io]: https://crates.io/crates/cosmian_cover_crypt

Implementation of the [CoverCrypt](bib/CoverCrypt.pdf) algorithm which allows
creating ciphertexts for a set of attributes and issuing user keys with access
policies over these attributes.

<!-- toc -->

  * [Getting started](#getting-started)
- [Building and testing](#building-and-testing)
    + [Building the library for a different glibc](#building-the-library-for-a-different-glibc)
    + [Building for Pyo3](#building-for-pyo3)
  * [Features and Benchmarks](#features-and-benchmarks)
    + [Key generation](#key-generation)
    + [Secret key encapsulation](#secret-key-encapsulation)
    + [Secret key decapsulation](#secret-key-decapsulation)
  * [Documentation](#documentation)

<!-- tocstop -->

## Getting started

The following code sample introduces the CoverCrypt functionalities. It can be
run from `examples/runme.rs` using `cargo run --example runme`.

```rust
use abe_policy::{AccessPolicy, Attribute, Policy, PolicyAxis};
use cosmian_cover_crypt::{
    interfaces::statics::{CoverCryptX25519Aes256, EncryptedHeader},
    CoverCrypt,
};

// The first attribute axis will be a security level.
// This axis is hierarchical, i.e. users matching
// `Security Level::Confidential` can also decrypt
// messages encrypted for `Security Level::Protected`.
let sec_level = PolicyAxis::new(
    "Security Level",
    &["Protected", "Confidential", "Top Secret"],
    true,
);

// Another attribute axis will be department names.
// This axis is *not* hierarchical.
let department = PolicyAxis::new("Department", &["R&D", "HR", "MKG", "FIN"], false);

// Generate a new `Policy` object with a 100 revocations allowed.
let mut policy = Policy::new(100);

// Add the two generated axes to the policy
policy.add_axis(&sec_level).unwrap();
policy.add_axis(&department).unwrap();

// Setup CoverCrypt and generate master keys
let cover_crypt = CoverCryptX25519Aes256::default();
let (mut msk, mut mpk) = cover_crypt.generate_master_keys(&policy).unwrap();

// The user has a security clearance `Security Level::Top Secret`,
// and belongs to the finance department (`Department::FIN`).
let access_policy =
    AccessPolicy::from_boolean_expression("Security Level::Top Secret && Department::FIN")
        .unwrap();
let mut usk = cover_crypt
    .generate_user_secret_key(&msk, &access_policy, &policy)
    .unwrap();

// Encrypt
let (_, encrypted_header) = EncryptedHeader::generate(
    &cover_crypt,
    &policy,
    &mpk,
    &access_policy.attributes(),
    None,
    None,
)
.unwrap();

// The user is able to decrypt the encrypted header.
assert!(encrypted_header.decrypt(&cover_crypt, &usk, None).is_ok());

//
// Rotate the `Security Level::Top Secret` attribute
policy
    .rotate(&Attribute::from(("Security Level", "Top Secret")))
    .unwrap();

// Master keys need to be updated to take into account the policy rotation
cover_crypt
    .update_master_keys(&policy, &mut msk, &mut mpk)
    .unwrap();

// Encrypt with rotated attribute
let (_, new_encrypted_header) = EncryptedHeader::generate(
    &cover_crypt,
    &policy,
    &mpk,
    &[Attribute::from(("Security Level", "Top Secret"))],
    None,
    None,
)
.unwrap();

// user cannot decrypt the newly encrypted header
assert!(new_encrypted_header
    .decrypt(&cover_crypt, &usk, None)
    .is_err());

// refresh user secret key, do not grant old encryption access
cover_crypt
    .refresh_user_secret_key(&mut usk, &access_policy, &msk, &policy, false)
    .unwrap();

// The user with refreshed key is able to decrypt the newly encrypted header.
assert!(new_encrypted_header
    .decrypt(&cover_crypt, &usk, None)
    .is_ok());

// But it cannot decrypt old ciphertexts
assert!(encrypted_header.decrypt(&cover_crypt, &usk, None).is_err());
```

## Building and testing

To build the core only, run:

```bash
cargo build --release
```

To build the FFI interface:

```bash
cargo build --release --features interfaces
```

To build everything (including the FFI):

```bash
cargo build --release --all-features
```

The latter will build a shared library. On Linux, one can verify that the FFI
symbols are present using:

```bash
objdump -T  target/release/libcosmian_cover_crypt.so
```

The code contains numerous tests that you can run using:

```bash
cargo test --release --all-features
```

Benchmarks can be run using (one can pass any feature flag):

```bash
cargo bench
```

### Building the library for a different glibc

Go to the [build](build/glibc-2.17/) directory for an example on how to build for GLIBC 2.17

### Build and tests for Pyo3

```bash
./src/interfaces/pyo3/tests/test.sh
```

## Features and Benchmarks

In CoverCrypt, messages are encrypted using a symmetric scheme. The right
management is performed by a novel asymmetric scheme which is used to
encapsulate a symmetric key. This encapsulation is stored in an object called
encrypted header, along with the symmetric ciphertext.

This design brings several advantages:

- the central authority has a unique key to protect (the master secret key);
- encapsulation can be performed without the need to store any sensitive
  information (public cryptography);
- encryption is as fast as symmetric schemes can be.

The benchmarks presented in this section are run on a Intel(R) Core(TM)
i7-10750H CPU @ 3.20GHz.

### Key generation

Asymmetric keys must be generated beforehand. This is the role of a central
authority, which is in charge of:

- generating and updating the master keys according to the right policy;
- generate and update user secret keys.

The CoverCrypt APIs exposes everything that is needed:

- `CoverCrypt::setup` : generate master keys
- `CoverCrypt::join` : create a user secret key for the given rights
- `CoverCrypt::update` : update the master keys for the given policy
- `CoverCrypt::refresh` : refresh a user secret key from the master secret key

The key generations may be long if the policy contains many rights or if there
are many users. But this is usually run once at setup. Key updates and refresh
stay fast if the change in the policy is small.

### Serialization

The size of the serialized keys and encapsulation is given by the following formulas:
- master secret key:
```
3 * PRIVATE_KEY_LENGTH + LEB128_sizeof(partitions.len()) \
	+ sum(LEB128_sizeof(sizeof(partition)) + sizeof(partition) + PRIVATE_KEY_LENGTH)
```
- public key:
```
2 * PUBLIC_KEY_LENGTH + LEB128_sizeof(partitions.len()) \
	+ sum(LEB128_sizeof(sizeof(partition)) + sizeof(partition) + PUBLIC_KEY_LENGTH)
```
- user secret key:
```
2 * PRIVATE_KEY_LENGTH + LEB128_sizeof(partitions.len()) \
	+ sum(LEB128_sizeof(sizeof(partition)) + sizeof(partition) + PRIVATE_KEY_LENGTH)
```
- encapsulation:
```
2 * PUBLIC_KEY_LENGTH + LEB128_sizeof(partitions.len()) + sum(TAG_LENGTH + PRIVATE_KEY_LENGTH)
```
- encrypted header (see below):
```
sizeof(encapsulation) + DEM_ENCRYPTION_OVERHEAD + sizeof(plaintext)
```

NOTE: For our implementation `CoverCryptX25519Aes256`:
- `PUBLIC_KEY_LENGTH` is 32 bytes
- `PRIVATE_KEY_LENGTH` is 32 bytes
- `TAG_LENGTH` is 32 bytes
- `DEM_ENCRYPTION_OVERHEAD` is 28 bytes (12 bytes for the MAC tag and 16 bytes for the nonce)
- `LEB128_sizeof(partitions.len())` is equal to 1 byte if the number of partitions is less than `2^7`

The size of

Below id given the size of an encapsulation given a number of partitions.

+-------------------+-------------------------------+
| Nb. of partitions | encapsulation size (in bytes) |
+-------------------+-------------------------------+
|         1         |              129              |
+-------------------+-------------------------------+
|         2         |              193              |
+-------------------+-------------------------------+
|         3         |              257              |
+-------------------+-------------------------------+
|         4         |              321              |
+-------------------+-------------------------------+
|         5         |              385              |
+-------------------+-------------------------------+



### Secret key encapsulation

This is the core of the CoverCrypt scheme. It allows creating a symmetric key
and its encapsulation for a given set of rights.

To ease the management of the encapsulations, an object `EncryptedHeader`is
provided in the API. An encrypted header holds an encapsulation and a symmetric
ciphertext of an optional additional data. This additional data can be useful
to store metadata.

**Note**: encapsulations grow bigger with the size of the target set of rights
and so does the encapsulation time. The following benchmark gives the size of
the encrypted header and the encryption time given the number of rights in the
target set (one right = one partition).

```
Bench header encryption size: 1 partition: 126 bytes, 3 partitions: 190 bytes

Header encryption/1 partition
                        time:   [187.07 µs 187.10 µs 187.14 µs]

Header encryption/3 partitions
                        time:   [319.33 µs 319.41 µs 319.51 µs]
```

### Secret key decapsulation

A user can retrieve the symmetric key needed to decrypt a CoverCrypt ciphertext
by decrypting the associated `EncryptedHeader`. This is only possible if the
user secret keys contains the appropriate rights.

```
Header decryption/1 partition access
                        time:   [252.55 µs 252.66 µs 252.79 µs]

Header decryption/3 partition access
                        time:   [318.59 µs 318.66 µs 318.74 µs]
```

## Documentation

A formal description and proof of the CoverCrypt scheme is given in
[this paper](./bib/CoverCrypt.pdf).
It also contains an interesting discussion about the implementation.

The developer documentation can be found on
[doc.rs](https://docs.rs/cosmian_cover_crypt/6.0.8/cosmian_cover_crypt/index.html)
