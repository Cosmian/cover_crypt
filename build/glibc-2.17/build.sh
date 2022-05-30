#!/bin/bash

set -e

ROOT_DIR=$(builtin cd ../..;pwd)
echo "Building project in $ROOT_DIR for LIBC 2.17"
TARGET_DIR=$ROOT_DIR/target_2.17

sudo docker run -it --rm \
-v $ROOT_DIR:/root/project \
-v $TARGET_DIR:/root/project/target \
rust_2.17 \
/bin/bash -c "cd /root/project && cargo build --release --all-features"