use super::*;
use bitcoin::secp256k1::{Keypair, All};
use bitcoin::{Amount, Network, OutPoint, Sequence, TxIn, Txid, Witness};

fn secp() -> Secp256k1<All> {
    Secp256k1::new()
}
fn kp(n: u8) -> Keypair {
    Keypair::from_seckey_slice(&secp(), &[n; 32]).unwrap()
}
fn xo(n: u8) -> Key {
    kp(n).x_only_public_key().0.serialize()
}
const MINT: Key = [7; 32];
const OTHER_MINT: Key = [8; 32];
const OWNER: Key = [4; 32];

fn fee_script() -> ScriptBuf {
    let s = secp();
    ScriptBuf::new_p2tr(&s, kp(0x55).x_only_public_key().0, None)
}
fn cfg() -> Config {
    Config {
        etchy_key: xo(0x22),
        backup_blocks: 52_560,
        fee_treasury_script: fee_script().to_bytes(),
        max_fee_sats: 50_000,
        max_postage_sats: 10_000,
        bridge_program: [9; 32],
        scales: vec![],
    }
}
fn custody_spk(key: &Key) -> ScriptBuf {
    custody(&secp(), key, &cfg()).unwrap().script_pubkey
}
fn request() -> Request {
    Request {
        mint: MINT,
        seq: 1,
        request_id: 5,
        user: [3; 32],
        amount: 1_000_000,
        witness_program: xo(0x66),
        status: PENDING,
        btc_txid: [0; 32],
    }
}
fn mint_bridge() -> MintBridge {
    MintBridge { mint: MINT, rune_block: 840_000, rune_tx: 7, enabled: true, paused: false }
}
fn input(n: u8, vout: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint { txid: Txid::from_byte_array([n; 32]), vout },
        script_sig: ScriptBuf::new(),
        sequence: Sequence(0xffff_fffd),
        witness: Witness::new(),
    }
}
fn out(sats: u64, script: ScriptBuf) -> TxOut {
    TxOut { value: Amount::from_sat(sats), script_pubkey: script }
}
fn dest() -> ScriptBuf {
    let mut d = vec![0x51, 0x20];
    d.extend_from_slice(&xo(0x66));
    ScriptBuf::from_bytes(d)
}
/// custody(C=0x11) + fee treasury -> user, change, Runestone, fee change.
fn payout_tx(units: u128) -> (Transaction, Vec<TxOut>) {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input(1, 0), input(2, 1)],
        output: vec![
            out(546, dest()),
            out(546, custody_spk(&xo(0x11))),
            out(0, payout_runestone(840_000, 7, units, 1)),
            out(10_000, fee_script()),
        ],
    };
    let prevouts = vec![out(546, custody_spk(&xo(0x11))), out(20_000, fee_script())];
    (tx, prevouts)
}
fn signed_custody() -> Vec<Signed> {
    vec![(0, Path::Custody { mint: MINT }, xo(0x11))]
}
fn check(tx: &Transaction, prevouts: &[TxOut], signed: &[Signed], r: &Request, mb: &MintBridge) -> Result<Approved, String> {
    check_with(&cfg(), tx, prevouts, signed, r, mb)
}
fn check_with(c: &Config, tx: &Transaction, prevouts: &[TxOut], signed: &[Signed], r: &Request, mb: &MintBridge) -> Result<Approved, String> {
    check_payout(
        &secp(),
        c,
        &Payout { tx, prevouts, signed, change_key: xo(0x11), request: r, mint_bridge: mb },
    )
}

#[test]
fn payout_is_approved_and_the_signature_verifies() {
    let (tx, prev) = payout_tx(1_000_000);
    let a = check(&tx, &prev, &signed_custody(), &request(), &mint_bridge()).unwrap();
    assert_eq!(a.units, 1_000_000);
    assert_eq!(a.fee_sats, 20_546 - 11_092);
    assert_eq!(a.sighashes.len(), 1);
    let (i, msg) = a.sighashes[0];
    assert_eq!(i, 0);
    // The sighash is BIP341 script-path of leaf A over all prevouts.
    let c = custody(&secp(), &xo(0x11), &cfg()).unwrap();
    let mut cache = SighashCache::new(&tx);
    let expect = cache
        .taproot_script_spend_signature_hash(0, &Prevouts::All(&prev), c.leaf_hash, TapSighashType::Default)
        .unwrap();
    assert_eq!(msg, expect.to_byte_array());
    let sig = secp().sign_schnorr_no_aux_rand(&Message::from_digest(msg), &kp(0x11));
    assert!(verify(&secp(), &xo(0x11), &msg, sig.as_ref()));
    assert!(!verify(&secp(), &xo(0x12), &msg, sig.as_ref()));
}

#[test]
fn payout_refuses_anything_but_the_exact_request() {
    let (tx, prev) = payout_tx(1_000_000);
    let s = signed_custody();
    let err = |tx: &Transaction, prev: &[TxOut], s: &[Signed], r: &Request, mb: &MintBridge| {
        check(tx, prev, s, r, mb).unwrap_err()
    };
    // Solana side.
    let mut r = request();
    r.status = 1;
    assert_eq!(err(&tx, &prev, &s, &r, &mint_bridge()), "REQUEST_NOT_PENDING");
    let mut mb = mint_bridge();
    mb.mint = OTHER_MINT;
    assert_eq!(err(&tx, &prev, &s, &request(), &mb), "MINT_MISMATCH");
    let mut mb = mint_bridge();
    mb.paused = true;
    assert_eq!(err(&tx, &prev, &s, &request(), &mb), "COIN_NOT_BRIDGEABLE");
    let mut mb = mint_bridge();
    mb.rune_block = 0;
    assert_eq!(err(&tx, &prev, &s, &request(), &mb), "RUNE_NOT_LINKED");
    // A bigger amount than locked, or the same amount of another Rune.
    let (t, p) = payout_tx(1_000_001);
    assert_eq!(err(&t, &p, &s, &request(), &mint_bridge()), "WRONG_RUNESTONE");
    let mut t = tx.clone();
    t.output[2] = out(0, payout_runestone(840_000, 8, 1_000_000, 1));
    assert_eq!(err(&t, &prev, &s, &request(), &mint_bridge()), "WRONG_RUNESTONE");
    // Pointer anywhere but custody (the rest of the Runes would leave custody).
    let mut t = tx.clone();
    t.output[2] = out(0, payout_runestone(840_000, 7, 1_000_000, 0));
    assert_eq!(err(&t, &prev, &s, &request(), &mint_bridge()), "WRONG_RUNESTONE");
    // Someone else's destination; too much postage.
    let mut t = tx.clone();
    t.output[0] = out(546, fee_script());
    assert_eq!(err(&t, &prev, &s, &request(), &mint_bridge()), "WRONG_DESTINATION");
    let mut t = tx.clone();
    t.output[0].value = Amount::from_sat(10_001);
    assert_eq!(err(&t, &prev, &s, &request(), &mint_bridge()), "WRONG_DESTINATION");
    // Change anywhere but this coin's custody.
    let mut t = tx.clone();
    t.output[1] = out(546, fee_script());
    assert_eq!(err(&t, &prev, &s, &request(), &mint_bridge()), "WRONG_CHANGE");
    let mut t = tx.clone();
    t.output[1] = out(546, custody_spk(&xo(0x13)));
    assert_eq!(err(&t, &prev, &s, &request(), &mint_bridge()), "WRONG_CHANGE");
    // No change output at all (unallocated Runes would go to the user).
    let mut t = tx.clone();
    t.output.remove(1);
    assert_eq!(err(&t, &prev, &s, &request(), &mint_bridge()), "WRONG_CHANGE");
    // An extra output; BTC change anywhere but the fee treasury.
    let mut t = tx.clone();
    t.output.push(out(1_000, dest()));
    assert_eq!(err(&t, &prev, &s, &request(), &mint_bridge()), "PAYOUT_OUTPUTS");
    let mut t = tx.clone();
    t.output[3] = out(10_000, dest());
    assert_eq!(err(&t, &prev, &s, &request(), &mint_bridge()), "WRONG_FEE_CHANGE");
    // Inputs: another coin's path, a key that does not derive the input, a
    // foreign input left unsigned, the same input twice, none at all.
    let other = vec![(0, Path::Custody { mint: OTHER_MINT }, xo(0x11))];
    assert_eq!(err(&tx, &prev, &other, &request(), &mint_bridge()), "INPUT_OF_ANOTHER_COIN");
    let wrong_key = vec![(0, Path::Custody { mint: MINT }, xo(0x12))];
    assert_eq!(err(&tx, &prev, &wrong_key, &request(), &mint_bridge()), "INPUT_NOT_CUSTODY");
    let mut p = prev.clone();
    p[1] = out(20_000, custody_spk(&xo(0x14)));
    assert_eq!(err(&tx, &p, &s, &request(), &mint_bridge()), "FOREIGN_INPUT");
    let twice = vec![s[0].clone(), s[0].clone()];
    assert_eq!(err(&tx, &prev, &twice, &request(), &mint_bridge()), "BAD_INPUT_INDEX");
    assert_eq!(err(&tx, &prev, &[], &request(), &mint_bridge()), "NO_CUSTODY_INPUT");
    // Fee cap, version, lock time, prevouts.
    let mut low = cfg();
    low.max_fee_sats = 5_000;
    assert_eq!(
        check_with(&low, &tx, &prev, &s, &request(), &mint_bridge()).unwrap_err(),
        "FEE_TOO_HIGH"
    );
    let mut t = tx.clone();
    t.version = Version::ONE;
    assert_eq!(err(&t, &prev, &s, &request(), &mint_bridge()), "TX_VERSION_OR_LOCKTIME");
    assert_eq!(err(&tx, &prev[..1], &s, &request(), &mint_bridge()), "TX_INPUTS");
}

#[test]
fn deposits_of_the_same_coin_can_be_paid_out() {
    let (mut tx, mut prev) = payout_tx(1_000_000);
    tx.input.push(input(3, 0));
    prev.push(out(546, custody_spk(&xo(0x33))));
    let mut s = signed_custody();
    s.push((2, Path::Deposit { mint: MINT, owner: OWNER }, xo(0x33)));
    let a = check(&tx, &prev, &s, &request(), &mint_bridge()).unwrap();
    assert_eq!(a.sighashes.iter().map(|x| x.0).collect::<Vec<_>>(), vec![0, 2]);
    // ... but never a deposit address of another coin.
    s[1].1 = Path::Deposit { mint: OTHER_MINT, owner: OWNER };
    assert_eq!(check(&tx, &prev, &s, &request(), &mint_bridge()).unwrap_err(), "INPUT_OF_ANOTHER_COIN");
}

#[test]
fn imported_runes_use_their_scale_exactly() {
    let mut c = cfg();
    c.scales = vec![(MINT, 2)];
    let (tx, prev) = payout_tx(10_000);
    let a = check_with(&c, &tx, &prev, &signed_custody(), &request(), &mint_bridge()).unwrap();
    assert_eq!(a.units, 10_000);
    let mut r = request();
    r.amount = 1_000_050;
    assert_eq!(
        check_with(&c, &tx, &prev, &signed_custody(), &r, &mint_bridge()).unwrap_err(),
        "NOT_WHOLE_RUNE_UNITS"
    );
    assert_eq!(rune_units(5, -3).unwrap(), 5_000);
}

#[test]
fn consolidations_stay_in_the_coin_custody() {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input(1, 0), input(3, 0), input(2, 1)],
        output: vec![out(1_092, custody_spk(&xo(0x11))), out(15_000, fee_script())],
    };
    let prev = vec![
        out(546, custody_spk(&xo(0x11))),
        out(546, custody_spk(&xo(0x33))),
        out(20_000, fee_script()),
    ];
    let s = vec![
        (0, Path::Custody { mint: MINT }, xo(0x11)),
        (1, Path::Deposit { mint: MINT, owner: OWNER }, xo(0x33)),
    ];
    let c = |tx: &Transaction, s: &[Signed], key: Key| {
        check_consolidation(&secp(), &cfg(), &Consolidation { tx, prevouts: &prev, signed: s, mint: MINT, custody_key: key })
    };
    let a = c(&tx, &s, xo(0x11)).unwrap();
    assert_eq!(a.sighashes.len(), 2);
    assert_eq!(a.fee_sats, 21_092 - 16_092);
    // Into anything but custody(mint): refused.
    assert_eq!(c(&tx, &s, xo(0x33)).unwrap_err(), "WRONG_CUSTODY_OUTPUT");
    let mut t = tx.clone();
    t.output[1] = out(15_000, dest());
    assert_eq!(c(&t, &s, xo(0x11)).unwrap_err(), "WRONG_FEE_CHANGE");
    let mut t = tx.clone();
    t.output.push(out(0, payout_runestone(840_000, 7, 1, 1)));
    assert_eq!(c(&t, &s, xo(0x11)).unwrap_err(), "CONSOLIDATION_OUTPUTS");
    let other = vec![s[0].clone(), (1, Path::Deposit { mint: OTHER_MINT, owner: OWNER }, xo(0x33))];
    assert_eq!(c(&tx, &other, xo(0x11)).unwrap_err(), "INPUT_OF_ANOTHER_COIN");
}

#[test]
fn solana_accounts_decode() {
    let mut d = discriminator("WithdrawalRequest").to_vec();
    d.extend_from_slice(&MINT);
    d.extend_from_slice(&3u64.to_le_bytes());
    d.extend_from_slice(&9u64.to_le_bytes());
    d.extend_from_slice(&[1; 32]);
    d.extend_from_slice(&[2; 32]);
    d.extend_from_slice(&1_000_000u64.to_le_bytes());
    d.extend_from_slice(&xo(0x66));
    d.push(0);
    d.extend_from_slice(&[0; 32]);
    d.extend_from_slice(&1_700_000_000i64.to_le_bytes());
    d.push(254);
    let r = parse_request(&d).unwrap();
    assert_eq!((r.mint, r.seq, r.request_id, r.amount, r.status), (MINT, 3, 9, 1_000_000, 0));
    assert_eq!(r.witness_program, xo(0x66));
    assert!(parse_request(&d[..201]).is_err());
    let mut m = discriminator("MintBridge").to_vec();
    m.extend_from_slice(&MINT);
    m.extend_from_slice(&[5; 32]);
    m.extend_from_slice(&840_000u64.to_le_bytes());
    m.extend_from_slice(&7u32.to_le_bytes());
    m.extend_from_slice(&[1, 0]);
    m.extend_from_slice(&[0; 66]);
    let b = parse_mint_bridge(&m).unwrap();
    assert_eq!(b, mint_bridge());
    m[0] ^= 1;
    assert!(parse_mint_bridge(&m).is_err());
}

#[test]
fn config_is_checked() {
    let mut c = cfg();
    c.backup_blocks = 144;
    assert_eq!(c.validate().unwrap_err(), "BACKUP_TOO_SHORT");
    let mut c = cfg();
    c.fee_treasury_script = vec![0x00, 0x14];
    assert_eq!(c.validate().unwrap_err(), "FEE_TREASURY_NOT_P2TR");
    let mut c = cfg();
    c.etchy_key = NUMS;
    assert_eq!(c.validate().unwrap_err(), "INVALID_ETCHY_KEY");
}

/// Cross-language: a payout planned by Etchy's TypeScript planner
/// (apps/api/src/bridge-cosigned.ts, fixture written by
/// tests/m62-cosigned-payout.test.ts) is approved by the canister's rules.
#[test]
fn ts_planner_fixture_is_approved() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/ts-payout.json");
    let Ok(text) = std::fs::read_to_string(path) else {
        println!("SKIP: no TS fixture at {path}");
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let h = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
    let k32 = |k: &str| -> Key { h(k).try_into().unwrap() };
    let tx: Transaction = bitcoin::consensus::deserialize(&h("tx")).unwrap();
    let prevouts: Vec<TxOut> = v["prevouts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            out(
                p["value"].as_u64().unwrap(),
                ScriptBuf::from_bytes(hex::decode(p["script"].as_str().unwrap()).unwrap()),
            )
        })
        .collect();
    let mint = k32("mint");
    let c = k32("cosigner_key");
    let mut config = cfg();
    config.etchy_key = k32("etchy_key");
    config.fee_treasury_script = h("fee_treasury_script");
    let signed: Vec<Signed> = v["cosigned"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| (i.as_u64().unwrap() as usize, Path::Custody { mint }, c))
        .collect();
    let r = Request {
        mint,
        seq: 1,
        request_id: 1,
        user: [3; 32],
        amount: v["amount"].as_u64().unwrap(),
        witness_program: k32("witness_program"),
        status: PENDING,
        btc_txid: [0; 32],
    };
    let mb = MintBridge { mint, rune_block: 840_000, rune_tx: 7, enabled: true, paused: false };
    let a = check_payout(
        &secp(),
        &config,
        &Payout { tx: &tx, prevouts: &prevouts, signed: &signed, change_key: c, request: &r, mint_bridge: &mb },
    )
    .expect("the TS plan is approved by the co-signer rules");
    assert_eq!(a.txid, v["txid"].as_str().unwrap());
    assert_eq!(a.fee_sats, v["fee_sats"].as_u64().unwrap());
    println!("TS planner fixture approved: {}", a.txid);
}

/// Shared vectors: apps/api (TypeScript) must derive the same bytes.
#[test]
fn vectors() {
    let c = custody(&secp(), &xo(0x11), &cfg()).unwrap();
    let addr = bitcoin::Address::from_script(&c.script_pubkey, Network::Bitcoin).unwrap();
    println!("VECTOR cosigner={}", hex::encode(xo(0x11)));
    println!("VECTOR etchy={}", hex::encode(xo(0x22)));
    println!("VECTOR multisig={}", hex::encode(c.multisig.as_bytes()));
    println!("VECTOR backup={}", hex::encode(c.backup.as_bytes()));
    println!("VECTOR control={}", hex::encode(&c.control_block));
    println!("VECTOR output={}", hex::encode(c.output_key));
    println!("VECTOR address={addr}");
    println!(
        "VECTOR runestone={}",
        hex::encode(payout_runestone(840_000, 7, 1_000_000, 1).as_bytes())
    );
    println!("VECTOR disc_request={}", hex::encode(discriminator("WithdrawalRequest")));
    println!("VECTOR disc_mint={}", hex::encode(discriminator("MintBridge")));
    // The backup leaf pushes 52560 minimally (3 bytes, little endian, sign bit clear).
    assert_eq!(&c.backup.as_bytes()[..4], &[0x03, 0x50, 0xcd, 0x00]);
    assert_eq!(c.multisig.len(), 68);
    assert_eq!(c.control_block.len(), 65);
}
