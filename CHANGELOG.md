# Changelog

All notable changes to this project will be documented in this file.

## [15.1.0] - 2026-02-13

### 🚀 Features

- Add a tagged, byte-serialized configurable KEM API supporting pre-quantum (P-256, R25519), post-quantum (ML-KEM 512/768) and hybridized combinations, plus Covercrypt (ABE) encapsulations (`KemTag::Abe`).
- Add post-quantum-only ABE encapsulations/keys alongside pre-quantum and hybridized modes (`XEnc` variants and right key mode tracking).

### Refactor

- Restructure the crate around `abe/` and `providers/` modules; move ABE API/core/policy/serialization under `src/abe/`.
- Switch elliptic-curve backends to `cosmian_openssl_provider` / `cosmian_rust_curve25519_provider` and align internal traits with `cosmian_crypto_core` (`KEM`, `NIKE`, AE/PKE interfaces).
- Implement CryptoCore byte-serialization (`Serializable`) for `Dict`, `RevisionMap`, and `RevisionVec`.

### Bug Fixes

- Fix formatting of `CryptoCoreError` display message.

### Ci

- Pin Rust toolchain to 1.89.0 and update GitHub Actions checkout to v4; add `rust-toolchain.toml`.

### Miscellaneous Tasks

- Commit `Cargo.lock`, adjust dependency versions (criterion 0.7, zeroize 1.8, ml-kem 0.2), and use the `crypto_core` git branch containing the deserialization allocation fix.
- Rename benchmarks from "Classic" to "Pre-quantum".

## [15.0.0] - 2025-03-13

### 🚀 Features

- *Add partial coordinates*: Partial coordinates allow ciphertexts created with
  an access policy "D1::A" not to be invalidated upon addition or deletion of
  another dimension/attribute.

- *Hardened cryptographic primitives*: Covercrypt is now CCA-secure, with an
  improved resistance against timing attacks thanks to shuffling.

- *Toward cryptographic agility*: elliptic curve (as of now only the Ristretto
  form of the X25519 and P256 are available) and MLKEM security levels can be
  selected using features. The modular architecture allows to easily add new
  implementations. However the modularity is not trait-based but feature-based,
  prohibiting the instantiation of several coexisting flavors of Covercrypt.

- *Lighter encapsulations*: we decided to optimize encapsulation sizes at the
  cost of user-secret-key size since encapsulations are generally more numerous
  than user secret keys. In particular, it is now possible to efficiently create
  broadcast encapsulations for any valid combination of attributes

- *Interface standardization*: Covercrypt now exposes both a KEM and a PKE
  interface, both providing 128 bits of both pre- and post-quantum CCA security.

- *Interface simplification*: the policy object is now an internal detail of the
  MSK and needs not be passed to the Covercrypt API (which improves security by
  preventing de-synchronization between the policy and the master keys).

#### Breaking changes

1. Serialization of all Covercrypt objects has been modified, which makes
   previous serialized objects *incompatible*.
2. The policy was renamed access structure to avoid confusion with an access
   policy.
3. Access policies are parsed using a different set of rules:
   - "\*" stands for *all* the rights when used to generate a USK and *any*
     right when used to generate an encapsulation;
   - "D::A" stands for any combination involving the "A" attribute from the
     dimension "D";

   Therefore an encapsulation generated under the "D1::A && D2::B" access policy
   can be opened by user secret keys generated for the "D1::A || ...", "D2::B ||
   ..." or "D1::A && D2::B || ..." (as was already the case), and an
   encapsulation generated under the "D1::A" access policy can be opened by a
   user secret keys generated for the "D1::A && ..." access policy.

### Bug Fixes

- [**breaking**] Rename `from_boolean_expression` into `parse`

## [14.0.0] - 2024-03-07

### Features

- Change `Axis` to `Dimension` with a clear distinction between `Ordered` and `Unordered`.
- Create a `Dictionary` data structure to store and update `Ordered Dimension` efficiently
- Change the data structure of `MasterSecretKey` and `UserSecretKey` to keep track of subkeys version.
- Policy does not count the attribute rotations anymore as they are stored in the subkeys.
- a `UserSecretKey` can now be refreshed without any external `Policy` information.
- Internalize `Policy` parsing method from the KMS to improve encapsulation.

## [13.0.0] - 2023-11-06

### Bug Fixes

- KMAC compute deterministic & Policy edit edge case (#117)

### Features

- Add KMAC to attest the authenticity of user keys (#114) and make policy editable (#115):
  * In Covercrypt, we have the following properties:

    the number of attribute values grows with the number of attribute modifications performed: rotations add a new value for an existing attribute while attribute creations add a new attribute with a new value;
    the number of partitions is equal to the number of combinations of attribute values that can be created by using one value associated to an attribute from each axis;
    the number of keys in each master key is equal to the number of partitions that can be created using their associated policy.

  * Hence, if a great number of attributes are created or a great number of rotations are performed, the size of both the policy and the master keys will grow drastically.

  * To prevent this, we need to allow dropping attribute values from the policy:

    removing an attribute from a policy axis could prevent the number of attributes from growing too big;
    retaining only a given number of values per attribute could allow purging the policy from old rotated attribute values.

  * Then a master key update should synchronize the master keys with the updated policy.

  * **Note**: this is not a problem for user secret keys since they generally hold a small subset of the policy rights; they also can be purged from old sub-keys at each refresh by setting the keep_old_rights parameter to false which prevents rotations from rendering them unmanageable.

## [12.0.3] - 2023-09-18

### Features

- Support `crypto_core` v9.2.0

## [12.0.2] - 2023-09-01

### Features

- Update crypto_core to 9.1.0

## [12.0.1] - 2023-07-19

### Changed

- patched kyber seed security issue

## [12.0.0] - 2023-07-11

### Changed

- use CryptoCore v9.0
- remove generics
- update namings to follow paper updates
- harden zeroization of private data

## [11.0.2] - 2023-05-31

### Documentation

- Update cryptographic paper and README.md

## [11.0.1] - 2023-05-03

### Documentation

- Fix formulas + describe how partitions work

### Miscellaneous Tasks

- Release 11.0.1 in order to upgrade crypto_core and use ECIES

### Ci

- Missing github caches cleanup

---

## [11.0.0] - 2023-03-01

### Bug Fixes

- Decrypt test example

### Documentation

- Update readme

### Refactor

- [**breaking**] Move all interfaces (FFI, Wasm, pyo3) to `cloudproof_rust` repository
- remove unneeded dependencies
- remove inline macros
- remove serde wherever possible

### Ci

- Add autopublish action

### Testing

- Re-expose non-regression mechanism

---

## [10.0.0] - 2023-02-02

### Documentation

- Update readme with benchmarks and sizes

### Features

- Merge AbePolicy
- Adapt FFI, WASM and pyo3 interfaces

### Ci

- Update KMS version
- Rebase externals repos

---

## [9.0.0] - 2023-01-20

### Changed

- hybridized version of CoverCrypt using Kyber
- all serializations
- directory structure
- most of `core::partition`

---

## [8.0.2] - 2022-12-06

### Added

- CI: verify inter-compatibility between Java, JS, Flutter and python

---

## [8.0.1] - 2022-12-06

### Fixed

- python publish
- speedup ci

---

## [8.0.0] - 2022-12-01

### Added

- non regression test vectors with different encryption policies
- PyO3 functions signature is exported via a python interface file

### Changed

- improve serialization
- new python interfaces based on objects rather than functions covering a broader range of functionalities

---

---

## [7.1.1] - 2022-11-22

### Added

- add FFI call to convert a policy expression to JSON

### Changed

- `webassembly_hybrid_decrypt` now returns a binary format containing the metadata and the decrypted value (leb128 length + metadata + decrypted value)

---

---

## [7.1.0] - 2022-11-15

### Added

- added encrypt / decrypt to FFI

---

---

## [7.0.2] - 2022-11-14

### Fixed

- `build.sh` only build for features FFI for GLIBC_2.17
- no encryption in header if additional data is empty

---

---

## [7.0.1] - 2022-10-27

### Changed

- change `wasm` target to `web`

---

---

## [7.0.0] - 2022-10-26

### Added

- instantiated types in `statics.rs`
- `Serializable` trait

### Changed

- use `Shake256` to derive keys
- use constant generics instead of `GenericArray`
- make `EncryptedHeader` generic
- make `ClearTextHeader` generic
- use EAKEM (cf [MR](https://github.com/Cosmian/cover_crypt/pull/39))
- `UserSecretKey::x` is now a `HashSet` (`Partition`s are removed)
- `CoverCrypt::encaps()` now takes an `AccessPolicy`
- replace `Hc128` by `ChaCha12Rng` as RNG

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
