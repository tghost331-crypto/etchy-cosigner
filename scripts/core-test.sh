#!/bin/bash
# Pure co-signer rules: unit tests (native) + shared test vectors.
cd /work
cargo test -p cosigner-core -- --nocapture 2>&1 \
  | grep -E '^(error|warning)|VECTOR|TS planner|SKIP|test result|panicked|FAILED|^ *--> |^ *= note|^[0-9]+ *\|' \
  | head -120
echo "pipe=${PIPESTATUS[0]}"
