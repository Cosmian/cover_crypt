#!/bin/sh
set -euEx

rm -f target/wheels/*.whl
maturin build --release --features python
pip install --force-reinstall target/wheels/*.whl
python3 python/test_cover_crypt.py
