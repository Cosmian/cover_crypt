cargo fmt --check || exit 1

cargo clippy --no-deps --all-targets -- -D warnings \
    || cargo clippy --no-deps --all-targets --no-default-features --features curve25519,mlkem-768 -- -D warnings \
    || cargo clippy --no-deps --all-targets --no-default-features --features p-256,mlkem-512 -- -D warnings \
    || cargo clippy --no-deps --all-targets --no-default-features --features p-256,mlkem-768 -- -D warnings \
    || exit 1

cargo test \
    || cargo test --no-default-features --features curve25519,mlkem-768 \
    || cargo test --no-default-features --features p-256,mlkem-512 \
    || cargo test --no-default-features --features p-256,mlkem-768 \
    || exit 1
