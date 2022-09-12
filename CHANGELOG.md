# Changelog

All notable changes to this project will be documented in this file.

---

## [7.0.0] - 2022-10-17

### Added

- instantiated types in `statics.rs`
- `Serializable` trait

### Changed

- use `SHA3-512` to derive keys
- use constant generics instead of `GenericArray`
- make `EncryptedHeader` generic
- make `ClearTextHeader` generic

### Fixed

### Removed

- `Metadata`

---

---
## [6.0.8] - 2022-10-17

### Added

### Changed

- `README.md`

### Fixed

### Removed
---

---
## [6.0.7] - 2022-10-14

### Added

- expose boolean Access Policy parsing in WASM
### Fixed

### Removed

---

---

## [6.0.6] - 2022-10-14

### Added

### Changed

- CI: use KMS version from Gitlab variable
- Update license

### Fixed

### Removed

---

---

## [6.0.5] - 2022-10-07

### Added

### Changed

- Rename library `cover_crypt` to `cosmian_cover_crypt`

### Fixed

### Removed

---

---

## [6.0.4] - 2022-09-28

### Added

### Changed

- Strip symbols on release for native library (libcover_crypt.so)

### Fixed

### Removed

---

---

## [6.0.3] - 2022-09-12

### Added

### Changed

- Adapt CI for `cosmian_js_lib` tests:
- populate postgres and postgrest docker containers

### Fixed

### Removed

---

---

## [6.0.2] - 2022-09-11

### Added

### Changed

- Simplify CI tests on `cosmian_js_lib` and `cosmian_java_lib`

### Fixed

### Removed

---

---

## [6.0.1] - 2022-09-05

### Added

- Enable tests on `cosmian_js_lib` and `cosmian_java_lib`
- Auto NPM publish on tags

### Changed

### Fixed

- Fix error message on invalid size errors.

### Removed

---

---

## [6.0.0] - 2022-08-29

### Added

- `write_array::<Length>()`
- `read_array::<Length>()`

### Changed

- `read_array()` -> `read_vec()`
- `write_array()` -> `write_vec()`
- `bytes_ser_de` is now private

### Fixed

### Removed

---

---

## [5.0.0] - 2022-08-24

### Added

### Changed

- Use CryptoCore v2.0.0

### Fixed

### Removed

---

---

## [4.1.1] - 2022-08-01

### Added

### Changed

- Serialization saves some more bytes
- Remove `Partition`s from `Encapsulation`s: now CoverCrypt returns a vector of
  symmetric keys when `decaps`. These keys should be tried on real symmetric
  ciphertexts in order to determine which is the good one. This works because
  symmetric ciphertexts are authenticated.

### Fixed

- bug in public key rotation

### Removed

---

---

## [4.1.0] - 2022-07-27

### Added

- Documentation

### Changed

- Use CryptoCore v1.0
- rename two `statics.rs` APIs

### Fixed

- serialization `write_array()` now takes a slice as argument
- replace some `Vec::new()` by `Vec::with_capacity()`

### Removed

---

---

## [4.0.0] - 2022-07-19

### Added

### Changed

- Implements the new version of CoverCrypt (V2).

### Fixed

### Removed

---

---

## [3.4.0] - 2022-07-18

### Added

### Changed

-bumped crypto_base to 2.1.0

### Fixed

- Attributes rotation; wrong update of the master keys

### Removed

---

---

## [3.2.1] - 2022-07-18

### Added

### Changed

### Fixed

- Returns in FFI functions (before exiting) the required pre-allocated out buffer size when buffer is too small

### Removed

---

---

## [3.2.0] - 2022-07-06

### Added

### Changed

- Use `abe_policy` library.

### Fixed

### Removed

- Remove `policy.rs` from the library

---

---

## [3.1.0] - 2022-07-01

### Added

### Changed

- Bump the cosmian_crypto_base version

### Fixed

### Removed

---

---

## [3.0.1] - 2022-06-21

### Added

- [pyo3 + JS/bindgen + FFI] Add CoverCrypt attributes rotation mechanism

### Changed

### Fixed

- Fix access policy to partitions

### Removed

---

## [3.0.0] - 2022-06-14

### Added

- Add Gitlab CI .gitlab-ci.yml
- [pyo3] Add Rust bindings for Python thanks to Pyo3

### Changed

- API changed: `to_bytes` become `try_to_bytes` for `PrivateKey` and `PublicKey`

### Fixed

### Removed

---

## [2.0.1] - 2022-06-07

### Added

- [JS/bindgen + FFI] Add ABE keys generation
- [pyo3] Add ABE keys generation

### Changed

### Fixed

### Removed

---

## [2.0.0] - 2022-05-31

### Added

### Changed

- Complete revamp of encoding of encapsulations and keys for a much more compact size.
  CipherTexts are NOT compatible with those of the 1.x releases

### Fixed

### Removed

---

## [1.0.3] - 2022-05-27

### Added

- [JS/bindgen] Add `webassembly_encrypt_hybrid_block`

### Changed

### Fixed

### Removed

---

## [1.0.2] - 2022-05-25

### Added

### Changed

### Fixed

- Fix decryption header with invalid first bytes in encrypted header

### Removed

---

## [1.0.1] - 2022-05-24

### Added

### Changed

### Fixed

- fix zero length metadata bug + fix symmetric overhead size bug + bump crypto_base to 1.2.2

### Removed

---

## [1.0.0] - 2022-05-23

### Added

- Cosmian Attributes Based Encryption (ABE) implementation 1.0.0

### Changed

### Fixed

### Removed
