#!/bin/sh

set -euEx

# Clean previous build
rm -f target/wheels/*.whl

# Build for manylinux (glibc 2.17)
# Alternatively you can build for your glibc only by setting `compatibility = "off"` in pyproject.toml and running
# maturin build --release --features python
docker run --rm -v $(pwd):/io ghcr.io/pyo3/maturin build --release --features python

pip install --force-reinstall target/wheels/*.whl
python3 src/interfaces/pyo3/tests/test_cover_crypt.py
