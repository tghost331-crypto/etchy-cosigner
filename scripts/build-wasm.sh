#!/bin/bash
# Build the canisters (wasm32, release) and print their sha256 (the
# timelock publishes this hash; anyone can rebuild and compare).
cd /work
cargo build --release --target wasm32-unknown-unknown -p cosigner -p timelock -p mock-sol-rpc 2>&1 \
  | grep -E '^(error|warning)|^ *--> |^ *= (note|help)|^[0-9]+ *\||Finished|could not compile' \
  | head -200
echo "pipe=${PIPESTATUS[0]}"
cargo tree -d -e normal --target wasm32-unknown-unknown -p cosigner 2>/dev/null | grep -E '^ic-cdk|^candid' | head -20
ls -la /target/wasm32-unknown-unknown/release/*.wasm 2>/dev/null
sha256sum /target/wasm32-unknown-unknown/release/*.wasm 2>/dev/null
