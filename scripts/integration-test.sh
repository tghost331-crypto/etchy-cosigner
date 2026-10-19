#!/bin/bash
# Full local check: build the canisters, then PocketIC (local Internet
# Computer with a threshold Schnorr test key) + Bitcoin Core regtest.
cd /work
R=/target/wasm32-unknown-unknown/release
cargo build --release --target wasm32-unknown-unknown -p cosigner -p timelock -p mock-sol-rpc 2>&1 \
  | grep -E '^(error|warning)|^ *--> |Finished|could not compile' | head -80
gzip -n -9 -c $R/cosigner.wasm > $R/cosigner.wasm.gz
ls -la $R/cosigner.wasm $R/cosigner.wasm.gz $R/timelock.wasm | awk '{print $5, $9}'
sha256sum $R/cosigner.wasm $R/cosigner.wasm.gz $R/timelock.wasm

B="bitcoin-cli -regtest -datadir=/tmp/btc -rpcuser=etchy -rpcpassword=etchy"
mkdir -p /tmp/btc
bitcoind -regtest -daemon -datadir=/tmp/btc -rpcuser=etchy -rpcpassword=etchy \
  -fallbackfee=0.0001 -txindex=1 -server=1 >/dev/null
for i in $(seq 1 40); do $B getblockchaininfo >/dev/null 2>&1 && break; sleep 0.5; done
$B createwallet t >/dev/null && echo "bitcoind regtest up: $($B -version | head -1)"

export BITCOIND_URL=http://127.0.0.1:18443/ BITCOIND_AUTH=etchy:etchy WASM_DIR=$R
cargo test -p integration -- --nocapture --test-threads 2 2>&1 \
  | grep -E '^(error|warning)|^ *--> |^ *= (note|help)|^[0-9]+ *\||^test |REGTEST|SKIP|panicked|left|right|FAILED|test result|failures:|Running' \
  | head -250
echo "pipe=${PIPESTATUS[0]}"
$B stop >/dev/null 2>&1
