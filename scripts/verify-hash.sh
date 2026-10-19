#!/bin/bash
# Rebuild the bridge co-signer and the timelock exactly like the release
# (build-wasm.sh + copy-wasm.sh: same packages in one cargo call, gzip -n -9)
# and print the sha256 of each gzipped module. Writes nothing into the repo:
# compare the printed hashes with the module hash the Internet Computer
# certifies for the live canisters (etchy.fun/verify).
set -e
cd /work
cargo build --locked --release --target wasm32-unknown-unknown -p cosigner -p timelock -p mock-sol-rpc 2>&1 | tail -n 2
R=/target/wasm32-unknown-unknown/release
for n in cosigner timelock; do
  echo "$(gzip -n -9 -c "$R/$n.wasm" | sha256sum | cut -d' ' -f1)  $n.wasm.gz"
done
