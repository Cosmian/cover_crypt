#!/bin/sh
set -exu

# These tests have to be executed if no breaking have been made.
# Otherwise we know in advance that these tests will fail.
source ci/detect_breaking_changes.sh

if [ "$DO_TEST" = "1" ]; then
  git clone https://github.com/Cosmian/cosmian_java_lib.git
  cp target/x86_64-unknown-linux-gnu/release/libcover_crypt.so cosmian_java_lib/src/test/resources/linux-x86-64/
  cd cosmian_java_lib
  mvn package
fi
