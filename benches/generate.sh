# Usage: bash generate.sh

#!/bin/sh

set -e

cargo criterion --features full_bench --message-format=json | criterion-table >benches/BENCHMARKS_classic.md
cargo criterion --features full_bench,hybridized_bench --message-format=json | criterion-table >benches/BENCHMARKS_hybridized.md

sed -i "s/❌ //g" benches/BENCHMARKS*.md
# sed -i "s/✅ //g" benches/BENCHMARKS*.md
<
