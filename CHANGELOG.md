# Changelog

All notable changes to this project will be documented in this file.

---
## [3.0.1] - 2022-06-21
### Added
- [pyo3] Add CoverCrypt attributes rotation mechanism
### Changed
### Fixed
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
