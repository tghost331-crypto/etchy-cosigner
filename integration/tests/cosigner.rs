//! The co-signer canister on a local Internet Computer (PocketIC) with a real
//! threshold Schnorr test key and a mock SOL RPC canister.
use bitcoin::secp256k1::Message;
use candid::encode_one;
use integration::*;
use std::time::Duration;

const REQ: Key = [0xA1; 32];
const REQ2: Key = [0xA3; 32];
const REQ3: Key = [0xA4; 32];
const REQ4: Key = [0xA5; 32];
const MB: Key = [0xA2; 32];
const MB_OTHER: Key = [0xB2; 32];

fn solana(env: &Env) {
    env.set_account(&REQ, &BRIDGE, request_bytes(&MINT, 1, 1_000_000, &xo(USER), 0));
    env.set_account(&MB, &BRIDGE, mint_bridge_bytes(&MINT, 840_000, 7, true, false));
}

/// custody(MINT) input 0 + fee treasury input 1 -> user, change, Runestone, fee change.
fn payout(c: &Key, custody_txid: u8, fee_txid: u8, fee_change: u64) -> (bitcoin::Transaction, Vec<bitcoin::TxOut>) {
    let spk = custody_of(c).script_pubkey;
    let t = tx(
        vec![txin([custody_txid; 32], 0), txin([fee_txid; 32], 1)],
        vec![
            out(546, dest()),
            out(546, spk.clone()),
            out(0, core::payout_runestone(840_000, 7, 1_000_000, 1)),
            out(fee_change, fee_script()),
        ],
    );
    (t, vec![out(546, spk), out(20_000, fee_script())])
}
fn args(t: &bitcoin::Transaction, prev: &[bitcoin::TxOut], request: &Key, mb: &Key) -> PayoutArgs {
    PayoutArgs {
        tx: bitcoin::consensus::serialize(t),
        prevouts: to_prevouts(prev),
        inputs: vec![CoSigned { index: 0, address: custody(&MINT) }],
        request: b58(request),
        mint_bridge: b58(mb),
    }
}

#[test]
fn payout_is_cosigned_exactly_once() {
    let env = Env::new();
    solana(&env);
    let c = env.cosigner_key(custody(&MINT));
    // Same key on a second derivation (cached) and from the public query.
    assert_eq!(env.cosigner_key(custody(&MINT)), c);
    let q: Result<Option<AddressInfo>, String> =
        env.query(env.cosigner, "address", encode_one(custody(&MINT)).unwrap());
    let q = q.unwrap().unwrap();
    assert_eq!(q.script_pubkey, hex::encode(custody_of(&c).script_pubkey.as_bytes()));
    assert!(q.encoded.starts_with("tb1p"), "{}", q.encoded);
    // Every address has its own key: other coin, deposit addresses.
    let c_other = env.cosigner_key(custody(&OTHER_MINT));
    let c_dep = env.cosigner_key(deposit(&MINT, &OWNER));
    assert!(c != c_other && c != c_dep && c_other != c_dep);

    let (t, prev) = payout(&c, 1, 2, 10_000);
    let a = args(&t, &prev, &REQ, &MB);
    let s = env.sign_payout(server(), &a).expect("signed");
    assert_eq!(s.txid, t.compute_txid().to_string());
    assert_eq!(s.fee_sats, 20_546 - 11_092);
    assert_eq!(s.signatures.len(), 1);
    assert_eq!(s.signatures[0].index, 0);
    // The threshold signature is a valid BIP340 signature by C over leaf A.
    let cust = custody_of(&c);
    let msg = leaf_sighash(&t, &prev, 0, cust.leaf_hash);
    assert!(core::verify(&secp(), &c, &msg, &s.signatures[0].signature));
    // Etchy adds E; together they satisfy leaf A (checked on regtest too).
    let sig_e = secp().sign_schnorr_no_aux_rand(&Message::from_digest(msg), &kp(E));
    let w = witness_2of2(sig_e.as_ref(), &s.signatures[0].signature, &cust);
    assert_eq!(w.len(), 4);

    // The canister read Solana itself: finalized, base64, 2-of-3 consensus.
    let seen = env.seen();
    assert!(seen.finalized && seen.base64, "{seen:?}");
    assert_eq!(seen.threshold, "Some(Threshold { total: Some(3), min: 2 })");
    let calls = seen.calls;

    // A retry of the same transaction: same signatures, no new reads.
    let again = env.sign_payout(server(), &a).unwrap();
    assert_eq!(again, s);
    assert_eq!(env.seen().calls, calls);

    // A fee bump that spends the same custody input: allowed (they conflict).
    let (t2, prev2) = payout(&c, 1, 3, 8_000);
    let s2 = env.sign_payout(server(), &args(&t2, &prev2, &REQ, &MB)).unwrap();
    assert_ne!(s2.txid, s.txid);
    // ... but a second payout for the same request from other coins: refused.
    let (t3, prev3) = payout(&c, 9, 8, 10_000);
    assert_eq!(env.sign_payout(server(), &args(&t3, &prev3, &REQ, &MB)).unwrap_err(), "REQUEST_ALREADY_SIGNED");
    // A version that shares only the fee input of v1 but not of v2: refused.
    let (t4, prev4) = payout(&c, 9, 2, 10_000);
    assert_eq!(env.sign_payout(server(), &args(&t4, &prev4, &REQ, &MB)).unwrap_err(), "REQUEST_ALREADY_SIGNED");
    let rec: Option<PayoutRecord> = env.query(env.cosigner, "payout", encode_one(b58(&REQ)).unwrap());
    let rec = rec.unwrap();
    assert_eq!(rec.versions.len(), 2);
    let first_input = t.input[0].previous_output.to_string();
    assert_eq!(rec.common, vec![first_input]);
    assert_eq!(rec.atoms, 1_000_000);

    let st = env.status();
    assert_eq!((st.payouts, st.signatures), (1, 2));
    assert_eq!(st.paid_today, vec![(b58(&MINT), 1_000_000)]);
}

/// Not an allowed caller: dropped by the ingress filter (or refused inside).
fn refused(r: Result<Signatures, String>) -> bool {
    matches!(r, Err(e) if e.starts_with("REJECTED") || e == "NOT_ALLOWED")
}

#[test]
fn payout_refuses_what_solana_did_not_ask_for() {
    let env = Env::new();
    solana(&env);
    let c = env.cosigner_key(custody(&MINT));
    let (t, prev) = payout(&c, 1, 2, 10_000);

    // Not an Etchy server: the ingress filter drops it.
    assert!(refused(env.sign_payout(stranger(), &args(&t, &prev, &REQ, &MB))));
    // An account the bridge program does not own.
    env.set_account(&REQ2, &[0xEE; 32], request_bytes(&MINT, 2, 1_000_000, &xo(USER), 0));
    assert_eq!(env.sign_payout(server(), &args(&t, &prev, &REQ2, &MB)).unwrap_err(), "REQUEST_NOT_FROM_BRIDGE");
    // A request that is no longer Pending (Sent / Refunded).
    env.set_account(&REQ2, &BRIDGE, request_bytes(&MINT, 2, 1_000_000, &xo(USER), 1));
    assert_eq!(env.sign_payout(server(), &args(&t, &prev, &REQ2, &MB)).unwrap_err(), "REQUEST_NOT_PENDING");
    // Another destination than the one locked on Solana.
    env.set_account(&REQ2, &BRIDGE, request_bytes(&MINT, 2, 1_000_000, &xo(0x67), 0));
    assert_eq!(env.sign_payout(server(), &args(&t, &prev, &REQ2, &MB)).unwrap_err(), "WRONG_DESTINATION");
    // More than locked.
    env.set_account(&REQ2, &BRIDGE, request_bytes(&MINT, 2, 999_999, &xo(USER), 0));
    assert_eq!(env.sign_payout(server(), &args(&t, &prev, &REQ2, &MB)).unwrap_err(), "WRONG_RUNESTONE");
    // Another coin's MintBridge, or another coin's custody input.
    env.set_account(&MB_OTHER, &BRIDGE, mint_bridge_bytes(&OTHER_MINT, 840_000, 7, true, false));
    assert_eq!(env.sign_payout(server(), &args(&t, &prev, &REQ, &MB_OTHER)).unwrap_err(), "MINT_MISMATCH");
    let c_other = env.cosigner_key(custody(&OTHER_MINT));
    let (to, po) = payout(&c_other, 1, 2, 10_000);
    let mut a = args(&to, &po, &REQ, &MB);
    a.inputs[0].address = custody(&OTHER_MINT);
    assert_eq!(env.sign_payout(server(), &a).unwrap_err(), "INPUT_OF_ANOTHER_COIN");
    // Claiming the other coin's input is this coin's: its script does not match.
    let mut a = args(&to, &po, &REQ, &MB);
    a.inputs[0].address = custody(&MINT);
    assert_eq!(env.sign_payout(server(), &a).unwrap_err(), "WRONG_CHANGE");
    // Paused bridge coin on Solana.
    env.set_account(&MB, &BRIDGE, mint_bridge_bytes(&MINT, 840_000, 7, true, true));
    assert_eq!(env.sign_payout(server(), &args(&t, &prev, &REQ, &MB)).unwrap_err(), "COIN_NOT_BRIDGEABLE");
    env.set_account(&MB, &BRIDGE, mint_bridge_bytes(&MINT, 840_000, 7, true, false));
    // RPC providers disagree / error: nothing is signed.
    env.mock_mode("inconsistent");
    assert_eq!(env.sign_payout(server(), &args(&t, &prev, &REQ, &MB)).unwrap_err(), "SOL_RPC_PROVIDERS_DISAGREE");
    env.mock_mode("error");
    assert!(env.sign_payout(server(), &args(&t, &prev, &REQ, &MB)).unwrap_err().starts_with("SOL_RPC_ERROR"));
    env.mock_mode("ok");
    // Nothing above was signed.
    assert_eq!(env.status().signatures, 0);
    assert!(env.sign_payout(server(), &args(&t, &prev, &REQ, &MB)).is_ok());
}

#[test]
fn pause_admin_and_daily_cap() {
    let env = Env::new();
    solana(&env);
    let c = env.cosigner_key(custody(&MINT));
    // Any Etchy server can pause; only the admin can unpause.
    let r: Result<(), String> = env.call(server(), "pause", encode_one("incident drill".to_string()).unwrap());
    r.unwrap();
    let (t, prev) = payout(&c, 1, 2, 10_000);
    assert_eq!(env.sign_payout(server(), &args(&t, &prev, &REQ, &MB)).unwrap_err(), "PAUSED");
    let r: Result<(), String> = env.call(server(), "unpause", encode_one(()).unwrap());
    assert_eq!(r.unwrap_err(), "NOT_ADMIN");
    let r: Result<(), String> = env.call(admin(), "unpause", encode_one(()).unwrap());
    r.unwrap();
    // The admin cannot sign (not a caller) unless it names itself a caller.
    assert_eq!(env.sign_payout(admin(), &args(&t, &prev, &REQ, &MB)).unwrap_err(), "NOT_ALLOWED");

    // Daily cap 2.5M atoms per coin: 1M + 1M pass, the third 1M waits a day.
    env.sign_payout(server(), &args(&t, &prev, &REQ, &MB)).unwrap();
    env.set_account(&REQ2, &BRIDGE, request_bytes(&MINT, 2, 1_000_000, &xo(USER), 0));
    env.set_account(&REQ3, &BRIDGE, request_bytes(&MINT, 3, 1_000_000, &xo(USER), 0));
    let (t2, p2) = payout(&c, 11, 12, 10_000);
    env.sign_payout(server(), &args(&t2, &p2, &REQ2, &MB)).unwrap();
    let (t3, p3) = payout(&c, 13, 14, 10_000);
    assert_eq!(env.sign_payout(server(), &args(&t3, &p3, &REQ3, &MB)).unwrap_err(), "DAILY_CAP");
    env.pic.advance_time(Duration::from_secs(86_400));
    env.pic.tick();
    env.sign_payout(server(), &args(&t3, &p3, &REQ3, &MB)).unwrap();

    // Callers can be changed by the admin only.
    let r: Result<(), String> = env.call(server(), "set_callers", encode_one(vec![server(), server2()]).unwrap());
    assert_eq!(r.unwrap_err(), "NOT_ADMIN");
    let r: Result<(), String> = env.call(admin(), "set_callers", encode_one(vec![server2()]).unwrap());
    r.unwrap();
    env.set_account(&REQ4, &BRIDGE, request_bytes(&MINT, 4, 1_000, &xo(USER), 0));
    assert!(refused(env.sign_payout(server(), &args(&t, &prev, &REQ4, &MB))));
    let ev: Vec<Event> = env.query(env.cosigner, "events", encode_one(0u64).unwrap());
    let kinds: Vec<&str> = ev.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds, vec!["INSTALLED", "PAUSED", "UNPAUSED", "PAYOUT", "PAYOUT", "PAYOUT", "CALLERS"]);
}

#[test]
fn consolidation_keeps_runes_in_their_coin_custody() {
    let env = Env::new();
    let c = env.cosigner_key(custody(&MINT));
    let d = env.cosigner_key(deposit(&MINT, &OWNER));
    let cust = custody_of(&c);
    let dep = custody_of(&d);
    let t = tx(
        vec![txin([21; 32], 0), txin([22; 32], 3), txin([23; 32], 1)],
        vec![out(1_092, cust.script_pubkey.clone()), out(15_000, fee_script())],
    );
    let prev = vec![out(546, cust.script_pubkey.clone()), out(546, dep.script_pubkey.clone()), out(20_000, fee_script())];
    let a = ConsolidationArgs {
        tx: bitcoin::consensus::serialize(&t),
        prevouts: to_prevouts(&prev),
        inputs: vec![
            CoSigned { index: 0, address: custody(&MINT) },
            CoSigned { index: 1, address: deposit(&MINT, &OWNER) },
        ],
        mint: b58(&MINT),
    };
    let s = env.sign_consolidation(server(), &a).unwrap();
    assert_eq!(s.signatures.len(), 2);
    assert!(core::verify(&secp(), &c, &leaf_sighash(&t, &prev, 0, cust.leaf_hash), &s.signatures[0].signature));
    assert!(core::verify(&secp(), &d, &leaf_sighash(&t, &prev, 1, dep.leaf_hash), &s.signatures[1].signature));
    // Into someone else's address: refused.
    let mut bad = t.clone();
    bad.output[0].script_pubkey = dest();
    let mut b = a.clone();
    b.tx = bitcoin::consensus::serialize(&bad);
    assert_eq!(env.sign_consolidation(server(), &b).unwrap_err(), "WRONG_CUSTODY_OUTPUT");
    // With a Runestone (could send Runes elsewhere): refused.
    let mut bad = t.clone();
    bad.output.push(out(0, core::payout_runestone(840_000, 7, 1, 1)));
    b.tx = bitcoin::consensus::serialize(&bad);
    assert_eq!(env.sign_consolidation(server(), &b).unwrap_err(), "CONSOLIDATION_OUTPUTS");
    // Into another coin's custody.
    let mut b = a.clone();
    b.mint = b58(&OTHER_MINT);
    assert_eq!(env.sign_consolidation(server(), &b).unwrap_err(), "INPUT_OF_ANOTHER_COIN");
}
