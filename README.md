# CoverCrypt &emsp; [![Build Status]][actions] [![Latest Version]][crates.io]

Implementation of the [CoverCrypt](bib/CoverCrypt.pdf) public key algorithm which partitions ciphertexts using attributes and allows issuing user keys with access policies over these attributes.

[Build Status]: https://img.shields.io/github/workflow/status/Cosmian/cover_crypt/CI%20checks/main
[actions]: https://github.com/Cosmian/cover_crypt/actions?query=branch%3Amain
[Latest Version]: https://img.shields.io/crates/v/cover_crypt.svg
[crates.io]: https://crates.io/crates/cover_crypt




- [A fast alternative to KP-ABE](#a-fast-alternative-to-kp-abe)
- [Building and testing](#building-and-testing)
  - [Building the library for a different glibc](#building-the-library-for-a-different-glibc)
  - [Building for Pyo3](#building-for-pyo3)
  - [Benchmarks](#benchmarks)
  - [Flamegraph](#flamegraph)

# A fast alternative to KP-ABE

CoverCrypt has been designed as a fast alternative to Key Policy Attribute Based Encryption schemes such as GPSW06 (>50x faster).

It is typically used in a hybrid encryption scheme as a KEM to encapsulate the symmetric key of a DEM (AES 256 GCM in the provided hybrid implementation)

```
CoverCrypt encryption over 1 partition: 
                        time:   [156.28 µs 156.73 µs 157.21 µs]
Found 538 outliers among 5000 measurements (10.76%)
  207 (4.14%) high mild
  331 (6.62%) high severe

CoverCrypt encryption over 3 partitions                                                                             
                        time:   [255.07 µs 255.70 µs 256.36 µs]
Found 364 outliers among 5000 measurements (7.28%)
  135 (2.70%) high mild
  229 (4.58%) high severe

CoverCrypt decryption with a 1 partition access user key
                        time:   [208.39 µs 209.17 µs 209.98 µs]
Found 601 outliers among 5000 measurements (12.02%)
  41 (0.82%) low mild
  139 (2.78%) high mild
  421 (8.42%) high severe

CoverCrypt decryption with a 3 partition access user key
                        time:   [260.87 µs 261.85 µs 262.85 µs]
Found 669 outliers among 5000 measurements (13.38%)
  13 (0.26%) low mild
  160 (3.20%) high mild
  496 (9.92%) high severe
```
Single threaded measurement over thousands of samples on an Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz

Run `cargo bench` to get the details (see below)

# Building and testing

The crate is separated in 3 main modules:

- `cover_crypt_core`: contains the cryptographic code for CoverCrypt. 
- `api.rs`: exposes the public API with policy management
- `interfaces`: contains interfaces useful for Cosmian matching those in [crypto_base](https://github.com/Cosmian/crypto_base) as well as a Foreign Function Interface (FFI) useful to integrate with other languages. In particular, the code in this module demonstrates the use of hybrid cryptography involving ABE and AES and exposes it as a FFI.

To build the core only, run

```bash
cargo build --release
```

To build the Cosmian interfaces without FFI, pass the `interfaces` feature flag, i.e.
```bash
cargo build --release --features interfaces
```

To build everything, including the FFI, pass the `ffi` feature flag, or use `--all-features` i.e.
```bash
cargo build --release --all-features
```

The latter will build a shared library and one can verify that the FFI symbols are present using (linux)
```bash
objdump -T  target/release/libcover_crypt.so
```

The code contains numerous tests that you can run using

```bash
cargo test --release --all-features
```

## Building the library for a different glibc

Go to the [build](build/glibc-2.17/) directory for an example on hw to build for GLIBC 2.17

## Building for Pyo3

```bash
maturin develop --cargo-extra-args="--release --features python
```

## Benchmarks

Benchmarking is using [Criterion](https://github.com/bheisler/criterion.rs) library.

Run all benchmarks:

```bash
cargo bench --features ffi
```

note: unfortunately, we cannot automatically tell Criterion to run benchmarks with `ffi` feature activated, we need to specify it.

Run only non-FFI benchmarks:

```console
cargo bench
```

## Flamegraph

To generate a [Flamegraph](https://github.com/flamegraph-rs/flamegraph) on Criterion's benchmark:

```console
cargo flamegraph --bench benches --features ffi -- --bench
```
