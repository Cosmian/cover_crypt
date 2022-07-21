# CoverCrypt &emsp; [![Build Status]][actions] [![Latest Version]][crates.io]

Implementation of the [CoverCrypt](bib/CoverCrypt.pdf) algorithm.

[Build Status]: https://img.shields.io/github/workflow/status/Cosmian/cover_crypt/CI%20checks/main
[actions]: https://github.com/Cosmian/cover_crypt/actions?query=branch%3Amain
[Latest Version]: https://img.shields.io/crates/v/cover_crypt.svg
[crates.io]: https://crates.io/crates/cover_crypt

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
