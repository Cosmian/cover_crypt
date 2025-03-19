#!/bin/bash

set -e

# Usage: bash generate.sh

if [[ "$1" == "generate" ]] ; then
    cargo install cargo-criterion
    cargo install criterion-table

    cargo criterion --features "test-utils" --message-format=json | criterion-table >benches/BENCHMARKS.md
fi

sed -i "s/❌ //g" benches/BENCHMARKS*.md
sed -i "s/🚀 //g" benches/BENCHMARKS*.md
sed -i "s/✅ //g" benches/BENCHMARKS*.md
