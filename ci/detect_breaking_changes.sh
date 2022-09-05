#!/bin/sh
set -eu

# Get version from Cargo.toml and CHANGELOG.md
cargo_version=$(grep -m1 "version = " Cargo.toml | cut -d "\"" -f2)
changelog_versions=$(grep -m2 "## \[" CHANGELOG.md | cut -d "[" -f2 | cut -d "]" -f1)

export DO_TEST=1

# Export DO_TEST=1 if no breaking changes, 0 otherwise
compare_versions() {
  VERSION_1=$1
  VERSION_2=$2
  [[ ! "$VERSION_1" =~ ^[0-9].[0-9].[0-9]$ ]] && echo "Semantic versioning invalid: $VERSION_1" && exit 1
  [[ ! "$VERSION_2" =~ ^[0-9].[0-9].[0-9]$ ]] && echo "Semantic versioning invalid: $VERSION_2" && exit 1

  MAJOR_1=${VERSION_1%.*.*}
  MAJOR_2=${VERSION_2%.*.*}
  MINOR_1=${VERSION_1#*.}
  MINOR_1=${MINOR_1%.*}
  MINOR_2=${VERSION_2#*.}
  MINOR_2=${MINOR_2%.*}

  # 0.X.Y
  if [ "$MAJOR_1" = "0" ] && [ "$MINOR_1" != "$MINOR_2" ]; then
    export DO_TEST=0
    return;
  fi

  # X.Y.Z where X != 0
  if [ "$MAJOR_1" != "$MAJOR_2" ]; then
    export DO_TEST=0
  fi
}

while IFS= read -r changelog_version; do
  if [ "$cargo_version" != "$changelog_version" ]; then
    compare_versions $cargo_version $changelog_version
  fi
done <<<"$changelog_versions"
