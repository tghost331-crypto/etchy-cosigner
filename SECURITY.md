# Security policy

## Reporting a vulnerability

Email **security@etchy.fun** with:

- a description of the issue and its impact,
- the steps or a proof of concept to reproduce it,
- the canister IDs, Bitcoin transactions or Solana signatures involved, if any.

Please do not open a public GitHub issue for a security problem, and do not
exploit an issue beyond what is needed to show it exists. We will confirm
receipt, keep you informed while we fix it, and credit you if you wish. Note
that any fix to the co-signer is itself public for 48 hours before it can run
(the timelock).

## Scope

- The co-signer canister `37iis-2iaaa-aaaah-awbpq-cai` and the timelock
  canister `l2tmf-mqaaa-aaaaj-qsmpa-cai` on the Internet Computer.
- The source code in this repository.

Issues that matter most: anything that gets the co-signer to sign a Bitcoin
transaction moving Runes anywhere but the requester's locked address or the
coin's own custody; a second payout for the same request; co-signing an input
for another coin's request; an upgrade that runs without the 48-hour delay or
that changes Etchy's key or the backup delay; or a way to stop the co-signer
for good.
