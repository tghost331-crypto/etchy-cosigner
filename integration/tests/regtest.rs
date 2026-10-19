//! Bitcoin Core (regtest) checks the real scripts: a payout co-signed by the
//! canister's threshold key + Etchy's key is valid and confirms; one key
//! alone is not; the backup leaf works only after its delay.
//! Skipped unless BITCOIND_URL is set (scripts/integration-test.sh sets it).
use bitcoin::secp256k1::Message;
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::key::TapTweak;
use bitcoin::{Network, ScriptBuf, Sequence, Witness, XOnlyPublicKey};
use integration::*;
use serde_json::{json, Value};

struct Rpc {
    url: String,
    auth: String,
}
impl Rpc {
    fn from_env() -> Option<Rpc> {
        let url = std::env::var("BITCOIND_URL").ok()?;
        let user = std::env::var("BITCOIND_AUTH").unwrap_or_else(|_| "etchy:etchy".into());
        use base64::Engine;
        let auth = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(user));
        Some(Rpc { url, auth })
    }
    fn try_call(&self, method: &str, params: Value) -> Result<Value, Value> {
        let body = json!({ "jsonrpc": "1.0", "id": "t", "method": method, "params": params });
        let r = match ureq::post(&self.url).set("Authorization", &self.auth).send_json(body) {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => panic!("bitcoind {method}: {e}"),
        };
        let v: Value = r.into_json().expect("json");
        if v["error"].is_null() { Ok(v["result"].clone()) } else { Err(v["error"].clone()) }
    }
    fn call(&self, method: &str, params: Value) -> Value {
        self.try_call(method, params.clone()).unwrap_or_else(|e| panic!("{method} {params}: {e}"))
    }
    fn mine(&self, n: u32, to: &str) {
        self.call("generatetoaddress", json!([n, to]));
    }
    /// Fund `spk` with `sats`; returns the outpoint (confirmed).
    fn fund(&self, spk: &ScriptBuf, sats: u64, miner: &str) -> (bitcoin::OutPoint, bitcoin::TxOut) {
        let addr = bitcoin::Address::from_script(spk, Network::Regtest).unwrap().to_string();
        let btc = format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000);
        let txid: String = serde_json::from_value(self.call("sendtoaddress", json!([addr, btc.parse::<f64>().unwrap()]))).unwrap();
        self.mine(1, miner);
        let tx = self.call("getrawtransaction", json!([txid, true]));
        let want = hex::encode(spk.as_bytes());
        let vout = tx["vout"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["scriptPubKey"]["hex"] == want)
            .unwrap()["n"]
            .as_u64()
            .unwrap() as u32;
        (bitcoin::OutPoint { txid: txid.parse().unwrap(), vout }, out(sats, spk.clone()))
    }
    fn accept(&self, t: &bitcoin::Transaction) -> Result<(), String> {
        let hex = bitcoin::consensus::encode::serialize_hex(t);
        let r = self.call("testmempoolaccept", json!([[hex]]));
        if r[0]["allowed"] == json!(true) { Ok(()) } else { Err(r[0]["reject-reason"].to_string()) }
    }
}

fn fee_sign(t: &bitcoin::Transaction, prev: &[bitcoin::TxOut], i: usize) -> Witness {
    let s = secp();
    let tweaked = kp(FEE).tap_tweak(&s, None).to_keypair();
    let sig = s.sign_schnorr_no_aux_rand(&Message::from_digest(key_sighash(t, prev, i)), &tweaked);
    let mut w = Witness::new();
    w.push(sig.as_ref());
    w
}

#[test]
fn bitcoin_core_accepts_the_cosigned_payout() {
    let Some(rpc) = Rpc::from_env() else {
        eprintln!("SKIP: BITCOIND_URL not set");
        return;
    };
    let _ = rpc.try_call("createwallet", json!(["t"]));
    let miner: String = serde_json::from_value(rpc.call("getnewaddress", json!(["", "bech32m"]))).unwrap();
    rpc.mine(101, &miner);

    let env = Env::new();
    let req: Key = [0xA1; 32];
    let mb: Key = [0xA2; 32];
    env.set_account(&req, &BRIDGE, request_bytes(&MINT, 1, 1_000_000, &xo(USER), 0));
    env.set_account(&mb, &BRIDGE, mint_bridge_bytes(&MINT, 840_000, 7, true, false));
    let c = env.cosigner_key(custody(&MINT));
    let cust = custody_of(&c);

    // Etchy custody (2-of-2) and the fee treasury, funded on regtest.
    let (op_c, prev_c) = rpc.fund(&cust.script_pubkey, 10_000, &miner);
    let (op_f, prev_f) = rpc.fund(&fee_script(), 50_000, &miner);
    let mut t = tx(
        vec![txin([0; 32], 0), txin([0; 32], 0)],
        vec![
            out(546, dest()),
            out(546, cust.script_pubkey.clone()),
            out(0, core::payout_runestone(840_000, 7, 1_000_000, 1)),
            out(60_000 - 1_092 - 1_500, fee_script()),
        ],
    );
    t.input[0].previous_output = op_c;
    t.input[1].previous_output = op_f;
    let prev = vec![prev_c, prev_f];

    let s = env
        .sign_payout(
            server(),
            &PayoutArgs {
                tx: bitcoin::consensus::serialize(&t),
                prevouts: to_prevouts(&prev),
                inputs: vec![CoSigned { index: 0, address: custody(&MINT) }],
                request: b58(&req),
                mint_bridge: b58(&mb),
            },
        )
        .expect("co-signed");
    let sig_c = s.signatures[0].signature.clone();
    let msg = leaf_sighash(&t, &prev, 0, cust.leaf_hash);
    let sig_e = secp().sign_schnorr_no_aux_rand(&Message::from_digest(msg), &kp(E));

    // One key alone, or the keys swapped: Bitcoin refuses.
    let mut bad = t.clone();
    bad.input[1].witness = fee_sign(&bad, &prev, 1);
    bad.input[0].witness = witness_2of2(sig_e.as_ref(), sig_e.as_ref(), &cust);
    assert!(rpc.accept(&bad).is_err());
    bad.input[0].witness = witness_2of2(&sig_c, sig_e.as_ref(), &cust);
    assert!(rpc.accept(&bad).is_err());

    // Both keys: valid. Broadcast and confirm.
    t.input[0].witness = witness_2of2(sig_e.as_ref(), &sig_c, &cust);
    t.input[1].witness = fee_sign(&t, &prev, 1);
    rpc.accept(&t).expect("Bitcoin Core accepts the co-signed payout");
    let txid: String = serde_json::from_value(rpc.call("sendrawtransaction", json!([bitcoin::consensus::encode::serialize_hex(&t)]))).unwrap();
    assert_eq!(txid, s.txid);
    rpc.mine(1, &miner);
    let got = rpc.call("getrawtransaction", json!([txid, true]));
    assert!(got["confirmations"].as_u64().unwrap() >= 1);
    eprintln!("REGTEST payout {txid} confirmed (2-of-2 leaf, threshold key + Etchy key)");
}

#[test]
fn backup_leaf_only_after_its_delay() {
    let Some(rpc) = Rpc::from_env() else {
        eprintln!("SKIP: BITCOIND_URL not set");
        return;
    };
    let _ = rpc.try_call("createwallet", json!(["t"]));
    let miner: String = serde_json::from_value(rpc.call("getnewaddress", json!(["", "bech32m"]))).unwrap();
    rpc.mine(101, &miner);
    // Same construction, shortest allowed delay (1008 blocks), any co-signer key.
    let mut cfg = core_config();
    cfg.backup_blocks = 1_008;
    let s = secp();
    let c = core::custody(&s, &xo(0x11), &cfg).unwrap();
    let internal = XOnlyPublicKey::from_slice(&core::NUMS).unwrap();
    let info = TaprootBuilder::new()
        .add_leaf(1, c.multisig.clone())
        .unwrap()
        .add_leaf(1, c.backup.clone())
        .unwrap()
        .finalize(&s, internal)
        .unwrap();
    let control = info.control_block(&(c.backup.clone(), LeafVersion::TapScript)).unwrap();
    let (op, prev) = rpc.fund(&c.script_pubkey, 20_000, &miner);
    let mut t = tx(vec![txin([0; 32], 0)], vec![out(18_000, fee_script())]);
    t.input[0].previous_output = op;
    t.input[0].sequence = Sequence::from_height(1_008);
    let leaf = bitcoin::taproot::TapLeafHash::from_script(&c.backup, LeafVersion::TapScript);
    let msg = leaf_sighash(&t, &[prev.clone()], 0, leaf);
    let sig = s.sign_schnorr_no_aux_rand(&Message::from_digest(msg), &kp(E));
    let mut w = Witness::new();
    w.push(sig.as_ref());
    w.push(c.backup.as_bytes());
    w.push(control.serialize());
    t.input[0].witness = w;
    let early = rpc.accept(&t).unwrap_err();
    assert!(early.contains("non-BIP68-final"), "{early}");
    rpc.mine(1_008, &miner);
    rpc.accept(&t).expect("backup leaf after 1008 blocks");
    // And the 52560-block leaf (production) encodes the same way (vector test).
    assert_eq!(&core_config().backup_blocks, &52_560);
    eprintln!("REGTEST backup leaf: refused early, accepted after 1008 blocks");
}
