#!/usr/bin/env bash
#
# Prepares a Solana monorepo tree for use by the zk-token build
#

set -e

here="$(dirname "$0")"
cd "$here"

if [[ ! -d solana ]]; then
  git clone git@github.com:solana-labs/solana.git
fi

if [[ ! -f solana/.zk-token-patched ]]; then
  git -C solana am "$PWD"/scripts/0001-feat-double-PACKET_DATA_SIZE.patch
  touch solana/.zk-token-patched
fi

exit 0
