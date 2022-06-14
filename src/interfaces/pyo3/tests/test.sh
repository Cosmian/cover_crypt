#!/bin/sh

set -euEx

init(){
  virtualenv env
  source env/bin/activate
  pip install maturin
}

# init

maturin develop --cargo-extra-args="--release --features python"

python src/interfaces/pyo3/tests/demo.py
