#!/bin/sh
set -eux

rm -f target/wheels/*.whl
maturin build --release --features python
pip install --force-reinstall target/wheels/*.whl
# Test typing
mypy python/scripts/test_cover_crypt.py
# Unit tests
python3 python/scripts/test_cover_crypt.py
