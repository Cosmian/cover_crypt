# CoverCrypt

![Build status](https://github.com/Cosmian/cover_crypt/actions/workflows/ci.yml/badge.svg)
![Build status](https://github.com/Cosmian/cover_crypt/actions/workflows/build.yml/badge.svg)
![latest version](https://img.shields.io/crates/v/cosmian_cover_crypt.svg)

Implementation of the [CoverCrypt](bib/CoverCrypt.pdf) algorithm which allows
creating ciphertexts for a set of attributes and issuing user keys with access
policies over these attributes.

<!-- toc -->

- [Getting started](#getting-started)
- [Building and testing](#building-and-testing)
  - [Building the library for a different glibc](#building-the-library-for-a-different-glibc)
- [Features and Benchmarks](#features-and-benchmarks)
  - [Key generation](#key-generation)
  - [Serialization](#serialization)
  - [Secret key encapsulation](#secret-key-encapsulation)
  - [Secret key decapsulation](#secret-key-decapsulation)
- [Documentation](#documentation)
- [Releases](#releases)

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

To build the FFI interface:

```bash
cargo build --release --features ffi
```

To build the WASM interface:

```bash
cargo build --release --features wasm_bindgen
```

To build the Python interface, run:

```bash
maturin build --release --features python
```

**Note**: when a new function or class is added to the PyO3 interface, its
signature needs to be added to
[`__init__.pyi`](./python/cosmian_cover_crypt/__init__.pyi).

To run tests on the Python interface, run:

```bash
./python/scripts/test.sh
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

```c
3 * PRIVATE_KEY_LENGTH + LEB128_sizeof(partitions.len()) \
    + sum(LEB128_sizeof(sizeof(partition)) + sizeof(partition)
  + PRIVATE_KEY_LENGTH + 1 [+ INDCPA_KYBER_PRIVATE_KEY_LENGTH])
```

- public key:

```c
2 * PUBLIC_KEY_LENGTH + LEB128_sizeof(partitions.len()) \
    + sum(LEB128_sizeof(sizeof(partition)) + sizeof(partition)
    + PUBLIC_KEY_LENGTH + 1 [+ INDCPA_KYBER_PUBLIC_KEY_LENGTH])
```

- user secret key:

```c
2 * PRIVATE_KEY_LENGTH + LEB128_sizeof(partitions.len()) \
    + partition.len() * (PRIVATE_KEY_LENGTH + 1 [+ INDCPA_KYBER_PRIVATE_KEY_LENGTH])
```

- encapsulation:

```c
2 * PUBLIC_KEY_LENGTH + TAG_LENGTH + LEB128_sizeof(partitions.len())
 + partition.len() * [INDCPA_KYBER_CIPHERTEXT_LENGTH | PUBLIC_KEY_LENGTH]
```

- encrypted header (see below):

```c
sizeof(encapsulation) + DEM_ENCRYPTION_OVERHEAD + sizeof(plaintext)
```

**NOTE**: For our implementation `CoverCryptX25519Aes256`:

- `PUBLIC_KEY_LENGTH` is 32 bytes
- `PRIVATE_KEY_LENGTH` is 32 bytes
- `TAG_LENGTH` is 32 bytes
- `DEM_ENCRYPTION_OVERHEAD` is 28 bytes (12 bytes for the MAC tag and 16 bytes for the nonce)
- `LEB128_sizeof(n)` is equal to 1 byte if `n` is less than `2^7`

<!--Below id given the size of an encapsulation given a number of partitions.-->

<!--| Nb. of partitions | encapsulation size (in bytes) |-->
<!--| ----------------- | ----------------------------- |-->
<!--| 1                 | 129                           |-->
<!--| 2                 | 193                           |-->
<!--| 3                 | 257                           |-->
<!--| 4                 | 321                           |-->
<!--| 5                 | 385                           |-->

### Secret key encapsulation

This is the core of the CoverCrypt scheme. It allows creating a symmetric key
and its encapsulation for a given set of rights.

To ease the management of the encapsulations, an object `EncryptedHeader`is
provided in the API. An encrypted header holds an encapsulation and a symmetric
ciphertext of an optional additional data. This additional data can be useful
to store metadata.

| Nb. of partitions | Encapsulation time |
| ----------------- | ------------------ |
| 1                 | 260                |
| 2                 | 390                |
| 3                 | 518                |
| 4                 | 663                |
| 5                 | 791                |

**Note**: encapsulations grow bigger with the size of the target set of rights
and so does the encapsulation time. The following benchmark gives the size of
the encrypted header and the encryption time given the number of rights in the
target set (one right = one partition).

### Secret key decapsulation

A user can retrieve the symmetric key needed to decrypt a CoverCrypt ciphertext
by decrypting the associated `EncryptedHeader`. This is only possible if the
user secret keys contains the appropriate rights.

The following table gives the decryption time given the size (in number of
partitions) of the user secret key (vertically) and the encapsulation
(horizontally).

| Nb. of partitions (`usk` vs `encapsulation`, 1 match) | 1   | 2   | 3   | 4   | 5   |
| ----------------------------------------------------- | --- | --- | --- | --- | --- |
| 1                                                     | 215 | 276 | 330 | 344 | 399 |
| 2                                                     | 314 | 385 | 476 | 534 | 634 |
| 3                                                     | 388 | 528 | 666 | 815 | 847 |

## Documentation

A formal description and proof of the CoverCrypt scheme is given in
[this paper](./bib/CoverCrypt.pdf).
It also contains an interesting discussion about the implementation.

The developer documentation can be found on
[doc.rs](https://docs.rs/cosmian_cover_crypt/6.0.8/cosmian_cover_crypt/index.html)

## Releases

All releases can be found in the public URL [package.cosmian.com](https://package.cosmian.com).
