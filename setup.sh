#!/usr/bin/env bash
#
# Prepares a Solana monorepo tree for use by the zk-token build
#

set -e

here="$(dirname "$0")"
cd "$here"

if [[ ! -d solana ]]; then
  if [[ -n $CI ]]; then
    git config --global user.email "you@example.com"
    git config --global user.name "Your Name"
    git clone https://github.com/solana-labs/solana.git
  else
    git clone git@github.com:solana-labs/solana.git
  fi
fi

if [[ ! -f solana/.zk-token-patched ]]; then
  git -C solana am "$PWD"/scripts/0001-feat-double-PACKET_DATA_SIZE.patch
  touch solana/.zk-token-patched
fi

exit 0
