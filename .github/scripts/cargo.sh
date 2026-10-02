#!/bin/bash

set -ex

cargo fmt --check || exit 1

cargo install --locked cargo-deny && cargo deny check || exit 1

cargo clippy --no-deps --all-targets -- -D warnings                                                       || exit 1
cargo clippy --no-deps --all-targets --no-default-features --features curve25519,mlkem-768 -- -D warnings || exit 1
cargo clippy --no-deps --all-targets --no-default-features --features p-256,mlkem-512      -- -D warnings || exit 1
cargo clippy --no-deps --all-targets --no-default-features --features p-256,mlkem-768      -- -D warnings || exit 1

cargo test --all-targets --features test-utils                                            || exit 1
cargo test --all-targets --no-default-features --all-features                             || exit 1
cargo test --all-targets --no-default-features --features test-utils,curve25519,mlkem-768 || exit 1
cargo test --all-targets --no-default-features --features test-utils,p-256,mlkem-512      || exit 1
cargo test --all-targets --no-default-features --features test-utils,p-256,mlkem-768      || exit 1
