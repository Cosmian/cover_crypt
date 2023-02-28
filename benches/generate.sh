#!/bin/sh

set -e

# Usage: bash generate.sh

cargo install cargo-criterion
cargo install criterion-table

cargo criterion --features full_bench --message-format=json | criterion-table >benches/BENCHMARKS_classic.md
cargo criterion --features full_bench,hybridized_bench --message-format=json | criterion-table >benches/BENCHMARKS_hybridized.md

sed -i "s/❌ //g" benches/BENCHMARKS*.md
# sed -i "s/✅ //g" benches/BENCHMARKS*.md
