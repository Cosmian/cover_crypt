#!/bin/sh

set -euEx

init(){
  virtualenv env
  source env/bin/activate
  pip install maturin
}

# init

rm -f target/wheels/*.whl
maturin build --cargo-extra-args="--release --features python"
pip install --force-reinstall target/wheels/*.whl
python3 src/interfaces/pyo3/tests/demo.py
