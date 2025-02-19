#!/bin/bash

set -ex

cargo fmt --check

cargo clippy --no-deps --all-targets -- -D warnings

cargo clippy --no-deps --all-targets --no-default-features --features curve25519,mlkem-768 -- -D warnings
cargo clippy --no-deps --all-targets --no-default-features --features p-256,mlkem-512 -- -D warnings
cargo clippy --no-deps --all-targets --no-default-features --features p-256,mlkem-768 -- -D warnings

cargo test
cargo test --no-default-features --features curve25519,mlkem-768
cargo test --no-default-features --features p-256,mlkem-512
cargo test --no-default-features --features p-256,mlkem-768
