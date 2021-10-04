#!/usr/bin/env bash
#
# Embeds the ZK Token project in the Solana monorepo build
#

here="$(dirname "$0")"
cd "$here"/..

if [[ -f Cargo.toml.org ]]; then
  echo "Error: Already ran $0 (Cargo.toml.org exists)"
  exit 1
fi

export DIRTY_OK=1
mv Cargo.toml Cargo.toml.org
touch Cargo.toml
./scripts/patch.crates-io.sh ..

cat Cargo.toml >> ../Cargo.toml
cat >> Cargo.toml <<EOF
[workspace]
members = [
    "demo",
    "program",
]
exclude = [
    "proof-program",
    "sdk",
]
EOF

exit 0
