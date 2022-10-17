# CoverCrypt &emsp; [![Build Status]][actions] [![Latest Version]][crates.io]

[Build Status]: https://img.shields.io/github/workflow/status/Cosmian/cosmian_cover_crypt/CI%20checks/main
[actions]: https://github.com/Cosmian/cosmian_cover_crypt/actions?query=branch%3Amain
[Latest Version]: https://img.shields.io/crates/v/cosmian_cover_crypt.svg
[crates.io]: https://crates.io/crates/cosmian_cover_crypt


Implementation of the [CoverCrypt](bib/CoverCrypt.pdf) algorithm which allows
creating ciphertexts for a set of attributes and issuing user keys with access
policies over these attributes.

## Getting started

``` rust
use abe_policy::{AccessPolicy, Attribute, Policy, PolicyAxis};
use cosmian_crypto_core::symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto;
use cosmian_cover_crypt::{CoverCrypt, interfaces::statics::*};

//
// Declare a new policy

// The first axis represents security levels. This axis is hierarchical, i.e.
// user matching a given level have access to all the lower levels. For
// example, a users matching `Security Level::Confidential` can also decrypt
// ciphertexts created for `Security Level::Protected`.
let sec_level = PolicyAxis::new(
    // axis name
    "Security Level",
    // axis attributes (lower attributes are declared first)
    &["Protected", "Confidential", "Top Secret"],
    // mark this axis as being hierarchical
    true,
);

// The second axis represents departments. This axis is *not* hierarchical.
let department = PolicyAxis::new("Department", &["R&D", "HR", "MKG", "FIN"], false);

// Generate a new `Policy` for these axis. 100 revocations are allowed.
let mut policy = Policy::new(100);
policy.add_axis(&sec_level).unwrap();
policy.add_axis(&department).unwrap();

// Instantiate CoverCrypt.
let cover_crypt = CoverCrypt::default();

// Generate master keys.
let (mut master_private_key, mut master_public_key) =
    cover_crypt.generate_master_keys(&policy).unwrap();

// Create a user secret key for a user in the finance department with a top
// secret security clearance.
let mut user_key = cover_crypt.generate_user_private_key(
    &master_private_key,
    &AccessPolicy::from_boolean_expression("Security Level::Top Secret && Department::FIN")
        .unwrap(),
    &policy
).unwrap();

// Encrypt a header for top level security clearance.
let encrypted_header = encrypt_hybrid_header::<Aes256GcmCrypto>(
    &policy,
    &master_public_key,
    &[Attribute::from(("Security Level", "Top Secret"))],
    None,
).unwrap();

// The user secret key is able to decrypt the encrypted header.
assert!(decrypt_hybrid_header::<Aes256GcmCrypto>(
    &user_key,
    &encrypted_header.header_bytes,
)
.is_ok());
```

# Building and testing

To build the core only, run:
``` bash
cargo build --release
```

To build the FFI interface:
``` bash
cargo build --release --features interfaces
```

To build everything (including the FFI):
``` bash
cargo build --release --all-features
```

The latter will build a shared library. On Linux, one can verify that the FFI
symbols are present using:
``` bash
objdump -T  target/release/libcosmian_cover_crypt.so
```

The code contains numerous tests that you can run using:
``` bash
cargo test --release --all-features
```

Benchmarks can be run using (one can pass any feature flag):
``` bash
cargo bench
```

### Building the library for a different glibc

Go to the [build](build/glibc-2.17/) directory for an example on how to build for GLIBC 2.17

### Building for Pyo3

```bash
maturin develop --cargo-extra-args="--release --features python
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
- `CoverCrypt::setup`   : generate master keys
- `CoverCrypt::join`    : create a user secret key for the given rights
- `CoverCrypt::update`  : update the master keys for the given policy
- `CoverCrypt::refresh` : refresh a user secret key from the master secret key

The key generations may be long if the policy contains many rights or if there
are many users. But this is usually run once at setup. Key updates and refresh
stay fast if the change in the policy is small.

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
Header encryption size: 1 partition: 129 bytes, 3 partitions: 193 bytes

Header encryption/1 partition
                        time:   [204.73 µs 204.79 µs 204.85 µs]

Header encryption/3 partitions
                        time:   [340.59 µs 340.69 µs 340.79 µs]
```

### Secret key decapsulation

A user can retrieve the symmetric key needed to decrypt a CoverCrypt ciphertext
by decrypting the associated `EncryptedHeader`. This is only possible if the
user secret keys contains the appropriate rights.

```
Header decryption/1 partition access
                        time:   [271.55 µs 271.62 µs 271.70 µs]

Header decryption/3 partition access
                        time:   [338.29 µs 338.32 µs 338.35 µs]
```

## Documentation

A formal description and proof of the CoverCrypt scheme is given in
[this paper](./bib/CoverCrypt.pdf).
It also contains an interesting discussion about the implementation.

The developer documentation can be found on
[doc.rs](https://docs.rs/cosmian_cover_crypt/6.0.8/cosmian_cover_crypt/index.html)
