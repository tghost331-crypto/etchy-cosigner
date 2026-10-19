#!/bin/bash
# Copy the release canisters out of the build volume into ic/dist (git-ignored)
# with their sha256 (what the timelock publishes).
R=/target/wasm32-unknown-unknown/release
mkdir -p /work/dist
gzip -n -9 -c $R/cosigner.wasm > /work/dist/cosigner.wasm.gz
gzip -n -9 -c $R/timelock.wasm > /work/dist/timelock.wasm.gz
cd /work/dist && sha256sum cosigner.wasm.gz timelock.wasm.gz | tee SHA256SUMS
