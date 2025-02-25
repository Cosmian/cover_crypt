#!/bin/bash

set -e

# Usage: bash generate.sh

if [[ "$1" == "generate" ]] ; then
    cargo install cargo-criterion
    cargo install criterion-table

    cargo criterion --features full_bench --message-format=json | criterion-table >benches/BENCHMARKS_classic.md
    cargo criterion --features full_bench,hybridized_bench --message-format=json | criterion-table >benches/BENCHMARKS_hybridized.md
fi

sed -i "s/❌ //g" benches/BENCHMARKS*.md
sed -i "s/🚀 //g" benches/BENCHMARKS*.md
sed -i "s/✅ //g" benches/BENCHMARKS*.md
