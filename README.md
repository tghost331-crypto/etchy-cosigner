# Etchy co-signer

The two [Internet Computer](https://internetcomputer.org) canisters that guard
[Etchy](https://etchy.fun)'s Bitcoin Rune custody, and how to check that the
code running on mainnet is exactly this code.

| | Canister | Module hash (sha256 of the gzipped wasm) |
| --- | --- | --- |
| Co-signer | [`37iis-2iaaa-aaaah-awbpq-cai`](https://dashboard.internetcomputer.org/canister/37iis-2iaaa-aaaah-awbpq-cai) | `86a5c592ebe02768ad2ee0e2e225baa69a43ac4d8776a340b3b8049c31a29eb4` |
| Timelock (the co-signer's only controller) | [`l2tmf-mqaaa-aaaaj-qsmpa-cai`](https://dashboard.internetcomputer.org/canister/l2tmf-mqaaa-aaaaj-qsmpa-cai) | `83473ccf3290b1867437dbd944fb0877cc41636e20abde7e72c4b6ad69165170` |

The timelock has **no controller**: nobody, Etchy included, can change it.
Live state of both (certified by the Internet Computer) for every coin:
[etchy.fun/verify](https://etchy.fun/verify). Security contact:
security@etchy.fun ([policy](SECURITY.md)).

## What it protects

Every Etchy coin's Rune sits at its own Bitcoin Taproot address:

```
P2TR( internal key = NUMS (BIP341 H: no key path, ever),
      leaf A = <C> OP_CHECKSIGVERIFY <E> OP_CHECKSIG     both keys
      leaf B = <52560> OP_CSV OP_DROP <E> OP_CHECKSIG    Etchy alone, only after
                                                         ~12 months unmoved )
```

* **E** is Etchy's key (a Turnkey account; fixed in the co-signer's settings).
* **C** is a threshold Schnorr key of the Internet Computer (`key_1`), held
  split across a subnet's nodes. No person or machine has it. It is derived
  per address from a path naming the coin (`["etchy-custody", mint]`, or
  `["etchy-deposit", mint, owner]`), so an input can only be co-signed for a
  request of its own coin.
* **Leaf B** is the backup: if the Internet Computer ever stopped answering,
  Etchy could move Runes after 52,560 blocks without a move. It cannot be
  used to rush anything.

A full compromise of Etchy's server (or of Turnkey) is therefore not enough to
move custody Runes: C only signs what the rules below allow.

## What the co-signer signs, and nothing else

Rules in [`cosigner-core`](cosigner-core/src/lib.rs) (pure Rust, no IC code),
canister in [`cosigner`](cosigner/src/lib.rs), interface
[`cosigner.did`](cosigner/cosigner.did).

1. **Payout** (`sign_payout`) of one Solana bridge `WithdrawalRequest`, which
   the canister **reads itself** through the SOL RPC canister (finalized,
   2 of 3 providers returning the same bytes), together with the coin's
   `MintBridge`, both owned by the
   [bridge program](https://github.com/tghost331-crypto/etchy-bridge):
   * the request is `Pending`; its coin is enabled, not paused, Rune linked;
   * output 0 pays the user's Taproot key exactly as locked on Solana;
   * output 1 is the coin's own custody address, always (the Runestone's
     pointer targets it: every Rune the edict does not send stays in custody);
   * output 2 is the exact Runestone `{pointer 1; edict(rune, amount, 0)}`;
   * output 3 is optional BTC change to Etchy's fee treasury;
   * co-signed inputs are custody or deposit addresses of this coin; any other
     input is the fee treasury; the miner fee is capped; version 2, locktime 0;
   * at most one payout per request: a fee-bumped version must spend an
     outpoint every earlier version spends, so at most one can confirm.
2. **Consolidation** (`sign_consolidation`): one coin's custody and deposit
   outputs back into that coin's custody address, no OP_RETURN (every Rune to
   output 0). At most 48 per day.

Every threshold signature is verified by the canister before it is returned,
and again by Etchy before anything is broadcast.

**Admin** (Etchy's Internet Computer identity): `pause`, `unpause`,
`set_callers` (which Etchy servers may ask). The admin can never sign and
never change a rule.

## Who can change the code: the timelock

[`timelock`](timelock/src/lib.rs) ([`timelock.did`](timelock/timelock.did))
is the co-signer's **only controller**, and has no controller itself:

* An upgrade is first **proposed** by the admin: the new module's sha256 and
  the exact upgrade argument become public (`proposals` query).
* It can be **executed** by anyone, but only after **48 hours**
  (`delay_seconds` = 172,800, fixed at install). The admin can cancel; nobody
  can run it early.
* It can only **upgrade** (stop, install with the state kept, start): never
  reinstall, delete, or change controllers. It has no such method.
* The co-signer itself refuses an upgrade that changes E or the backup delay
  (that would strand custody).

So any change to the rules is visible for two days before it can take effect.
Anyone can add cycles to either canister.

## Rebuild it and compare

The wasm modules are reproducible. With Docker:

```sh
docker build -f Dockerfile.build -t etchy-ic-build .
docker run --rm -v "$PWD:/work" -v etchy-ic-target:/target \
  -e CARGO_TARGET_DIR=/target etchy-ic-build bash /work/scripts/verify-hash.sh
```

It prints:

```
86a5c592ebe02768ad2ee0e2e225baa69a43ac4d8776a340b3b8049c31a29eb4  cosigner.wasm.gz
83473ccf3290b1867437dbd944fb0877cc41636e20abde7e72c4b6ad69165170  timelock.wasm.gz
```

Mount the repository at `/work` and the build folder at `/target` as shown:
the paths are part of the wasm. Compare with what the Internet Computer
reports for the live canisters:

```sh
dfx canister info 37iis-2iaaa-aaaah-awbpq-cai --network ic   # Module hash, Controllers
dfx canister info l2tmf-mqaaa-aaaaj-qsmpa-cai --network ic
```

## Tests

```sh
docker run --rm -v "$PWD:/work" -v etchy-ic-target:/target -e CARGO_TARGET_DIR=/target \
  etchy-ic-build bash /work/scripts/core-test.sh         # rules + shared test vectors
docker run --rm -v "$PWD:/work" -v etchy-ic-target:/target -e CARGO_TARGET_DIR=/target \
  etchy-ic-build bash /work/scripts/integration-test.sh  # PocketIC + Bitcoin Core regtest
```

* `cosigner-core`: every rule and refusal, the address and Runestone test
  vectors, and a payout planned by Etchy's TypeScript planner
  ([`fixtures/ts-payout.json`](fixtures/ts-payout.json)) approved byte for byte.
* `integration` (PocketIC, a local Internet Computer with a threshold Schnorr
  test key, and a mock SOL RPC): a payout co-signed exactly once, retries, the
  fee-bump rule, every refusal, pause and admin, the daily cap, consolidation;
  the timelock's 48 hours, a chunked upgrade that keeps state, bad or
  cancelled upgrades never running.
* `regtest` (Bitcoin Core 28.1): a payout signed by the canister's threshold
  key and E is accepted and confirmed; one key alone or swapped is refused;
  the backup leaf is refused early and accepted after its delay.

## What it does not protect (honest limits)

* **The Solana attester key** (on Etchy's server) could release vault tokens
  on Solana for a fake deposit; those tokens could then be bridged out for
  real Runes of that coin. The bridge program's per-coin daily release cap
  limits this. Fix later: the co-signer verifies deposits itself (it needs a
  Rune indexer on the Internet Computer).
* **The canister cannot see Rune balances** (no Rune indexer on the Internet
  Computer): Etchy picks the inputs. A wrong pick can only underpay (the
  request is then refunded on Solana), never send Runes elsewhere.
* **Refund after a payout**: the attester could refund a request already paid
  on Bitcoin. Etchy's code never does; the canister's payout record
  (`payout` query) makes it visible.

## License

Apache-2.0.
