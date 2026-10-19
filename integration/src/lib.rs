//! TEST ONLY: PocketIC harness for the Etchy co-signer and timelock.
//! Interface types mirror cosigner.did / timelock.did (subsets are fine:
//! Candid ignores record fields a reader does not declare).
#![allow(dead_code)]

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Keypair, Secp256k1};
use bitcoin::sighash::{Prevouts as All_, SighashCache, TapSighashType};
use bitcoin::taproot::TapLeafHash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use candid::{decode_one, encode_args, encode_one, CandidType, Deserialize, Principal};
use pocket_ic::{PocketIc, PocketIcBuilder};
use serde::de::DeserializeOwned;

pub use cosigner_core as core;
pub use cosigner_core::Key;

// ------------------------------------------------------------- interface

#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cluster {
    Mainnet,
    Devnet,
}
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Scale {
    pub mint: String,
    pub exp: i8,
}
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub etchy_key: String,
    pub backup_blocks: u16,
    pub fee_treasury_script: String,
    pub max_fee_sats: u64,
    pub max_postage_sats: u64,
    pub bridge_program: String,
    pub scales: Vec<Scale>,
    pub daily_cap_atoms: Option<u64>,
}
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArgs {
    pub admin: Principal,
    pub callers: Vec<Principal>,
    pub key_name: String,
    pub cluster: Cluster,
    pub sol_rpc: Principal,
    pub settings: Settings,
}
#[derive(CandidType, Deserialize, Clone, Debug, Default)]
pub struct UpgradeArgs {
    pub admin: Option<Principal>,
    pub callers: Option<Vec<Principal>>,
    pub sol_rpc: Option<Principal>,
    pub settings: Option<Settings>,
}
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Address {
    Custody { mint: String },
    Deposit { mint: String, owner: String },
}
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Prevout {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct CoSigned {
    pub index: u32,
    pub address: Address,
}
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct PayoutArgs {
    pub tx: Vec<u8>,
    pub prevouts: Vec<Prevout>,
    pub inputs: Vec<CoSigned>,
    pub request: String,
    pub mint_bridge: String,
}
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct ConsolidationArgs {
    pub tx: Vec<u8>,
    pub prevouts: Vec<Prevout>,
    pub inputs: Vec<CoSigned>,
    pub mint: String,
}
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InputSignature {
    pub index: u32,
    pub signature: Vec<u8>,
}
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Signatures {
    pub txid: String,
    pub fee_sats: u64,
    pub signatures: Vec<InputSignature>,
}
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AddressInfo {
    pub address: Address,
    pub cosigner_key: String,
    pub script_pubkey: String,
    pub encoded: String,
}
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct PayoutRecord {
    pub mint: String,
    pub atoms: u64,
    pub versions: Vec<Signatures>,
    pub common: Vec<String>,
    pub first_at: u64,
}
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Event {
    pub id: u64,
    pub at: u64,
    pub kind: String,
    pub detail: String,
}
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Status {
    pub version: String,
    pub paused: bool,
    pub admin: Principal,
    pub callers: Vec<Principal>,
    pub key_name: String,
    pub settings: Settings,
    pub addresses_known: u64,
    pub payouts: u64,
    pub signatures: u64,
    pub consolidations_today: u32,
    pub paid_today: Vec<(String, u64)>,
}
#[derive(CandidType, Deserialize, Clone, Debug, Default)]
pub struct Seen {
    pub calls: u64,
    pub last_pubkey: String,
    pub finalized: bool,
    pub base64: bool,
    pub threshold: String,
    pub cycles: u64,
}
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct TimelockInit {
    pub admin: Principal,
    pub target: Principal,
    pub delay_seconds: u64,
}
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ProposalStatus {
    Pending,
    Executed,
    Cancelled,
}
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Proposal {
    pub id: u64,
    pub wasm_module_hash: Vec<u8>,
    pub arg_sha256: Vec<u8>,
    pub note: String,
    pub proposed_at: u64,
    pub executable_at: u64,
    pub status: ProposalStatus,
    pub chunks: Vec<Vec<u8>>,
    pub executed_at: Option<u64>,
    pub last_error: Option<String>,
}

// ------------------------------------------------------------ test world

pub fn secp() -> Secp256k1<All> {
    Secp256k1::new()
}
pub fn kp(n: u8) -> Keypair {
    Keypair::from_seckey_slice(&secp(), &[n; 32]).unwrap()
}
pub fn xo(n: u8) -> Key {
    kp(n).x_only_public_key().0.serialize()
}
pub fn b58(k: &Key) -> String {
    bs58::encode(k).into_string()
}
pub fn principal(n: u8) -> Principal {
    Principal::self_authenticating([n; 32])
}
pub const MINT: Key = [7; 32];
pub const OTHER_MINT: Key = [8; 32];
pub const OWNER: Key = [4; 32];
pub const BRIDGE: Key = [9; 32];
/// Etchy's leaf key E (secret [0x22; 32]) and the user's key.
pub const E: u8 = 0x22;
pub const USER: u8 = 0x66;
pub const FEE: u8 = 0x55;
pub fn admin() -> Principal {
    principal(1)
}
pub fn server() -> Principal {
    principal(2)
}
pub fn stranger() -> Principal {
    principal(3)
}
pub fn server2() -> Principal {
    principal(4)
}

pub fn fee_script() -> ScriptBuf {
    ScriptBuf::new_p2tr(&secp(), kp(FEE).x_only_public_key().0, None)
}
pub fn dest() -> ScriptBuf {
    let mut d = vec![0x51, 0x20];
    d.extend_from_slice(&xo(USER));
    ScriptBuf::from_bytes(d)
}
pub fn settings() -> Settings {
    Settings {
        etchy_key: hex::encode(xo(E)),
        backup_blocks: 52_560,
        fee_treasury_script: hex::encode(fee_script().as_bytes()),
        max_fee_sats: 50_000,
        max_postage_sats: 10_000,
        bridge_program: b58(&BRIDGE),
        scales: vec![],
        daily_cap_atoms: Some(2_500_000),
    }
}
pub fn core_config() -> core::Config {
    core::Config {
        etchy_key: xo(E),
        backup_blocks: 52_560,
        fee_treasury_script: fee_script().to_bytes(),
        max_fee_sats: 50_000,
        max_postage_sats: 10_000,
        bridge_program: BRIDGE,
        scales: vec![],
    }
}

/// Anchor `WithdrawalRequest` bytes (layout of the etchy-bridge program).
pub fn request_bytes(mint: &Key, seq: u64, amount: u64, witness_program: &Key, status: u8) -> Vec<u8> {
    let mut d = core::discriminator("WithdrawalRequest").to_vec();
    d.extend_from_slice(mint);
    d.extend_from_slice(&seq.to_le_bytes());
    d.extend_from_slice(&(seq + 100).to_le_bytes());
    d.extend_from_slice(&[1; 32]);
    d.extend_from_slice(&[2; 32]);
    d.extend_from_slice(&amount.to_le_bytes());
    d.extend_from_slice(witness_program);
    d.push(status);
    d.extend_from_slice(&[0; 32]);
    d.extend_from_slice(&1_700_000_000i64.to_le_bytes());
    d.push(254);
    d
}
/// Anchor `MintBridge` bytes.
pub fn mint_bridge_bytes(mint: &Key, rune_block: u64, rune_tx: u32, enabled: bool, paused: bool) -> Vec<u8> {
    let mut m = core::discriminator("MintBridge").to_vec();
    m.extend_from_slice(mint);
    m.extend_from_slice(&[5; 32]);
    m.extend_from_slice(&rune_block.to_le_bytes());
    m.extend_from_slice(&rune_tx.to_le_bytes());
    m.extend_from_slice(&[enabled as u8, paused as u8]);
    m.extend_from_slice(&[0; 66]);
    m
}

pub fn txin(txid: [u8; 32], vout: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint { txid: Txid::from_byte_array(txid), vout },
        script_sig: ScriptBuf::new(),
        sequence: Sequence(0xffff_fffd),
        witness: Witness::new(),
    }
}
pub fn out(sats: u64, script: ScriptBuf) -> TxOut {
    TxOut { value: Amount::from_sat(sats), script_pubkey: script }
}
pub fn tx(input: Vec<TxIn>, output: Vec<TxOut>) -> Transaction {
    Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input, output }
}
pub fn custody_of(cosigner_key: &Key) -> core::Custody {
    core::custody(&secp(), cosigner_key, &core_config()).unwrap()
}
pub fn to_prevouts(p: &[TxOut]) -> Vec<Prevout> {
    p.iter()
        .map(|o| Prevout { value: o.value.to_sat(), script_pubkey: o.script_pubkey.to_bytes() })
        .collect()
}
pub fn leaf_sighash(t: &Transaction, prevouts: &[TxOut], i: usize, leaf: TapLeafHash) -> [u8; 32] {
    SighashCache::new(t)
        .taproot_script_spend_signature_hash(i, &All_::All(prevouts), leaf, TapSighashType::Default)
        .unwrap()
        .to_byte_array()
}
pub fn key_sighash(t: &Transaction, prevouts: &[TxOut], i: usize) -> [u8; 32] {
    SighashCache::new(t)
        .taproot_key_spend_signature_hash(i, &All_::All(prevouts), TapSighashType::Default)
        .unwrap()
        .to_byte_array()
}
/// Leaf A witness: [sig_E, sig_C, leaf, control] (sig_C on top, checked first).
pub fn witness_2of2(sig_e: &[u8], sig_c: &[u8], c: &core::Custody) -> Witness {
    let mut w = Witness::new();
    w.push(sig_e);
    w.push(sig_c);
    w.push(c.multisig.as_bytes());
    w.push(&c.control_block);
    w
}

pub fn wasm(name: &str) -> Vec<u8> {
    let dir = std::env::var("WASM_DIR").unwrap_or_else(|_| "/target/wasm32-unknown-unknown/release".into());
    std::fs::read(format!("{dir}/{name}")).unwrap_or_else(|e| panic!("{dir}/{name}: {e}"))
}
pub fn key_name() -> String {
    std::env::var("KEY_NAME").unwrap_or_else(|_| "test_key_1".into())
}

pub struct Env {
    pub pic: PocketIc,
    pub cosigner: Principal,
    pub mock: Principal,
}

impl Env {
    /// PocketIC with a threshold-key subnet; mock SOL RPC + co-signer installed.
    pub fn new() -> Env {
        let pic = PocketIcBuilder::new()
            .with_application_subnet()
            .with_test_threshold_keys_subnet()
            .build();
        let mock = pic.create_canister();
        pic.add_cycles(mock, 10_000_000_000_000);
        pic.install_canister(mock, wasm("mock_sol_rpc.wasm"), encode_one(()).unwrap(), None);
        let cosigner = pic.create_canister();
        pic.add_cycles(cosigner, 100_000_000_000_000);
        let init = InitArgs {
            admin: admin(),
            callers: vec![server()],
            key_name: key_name(),
            cluster: Cluster::Devnet,
            sol_rpc: mock,
            settings: settings(),
        };
        pic.install_canister(cosigner, wasm("cosigner.wasm.gz"), encode_one(init).unwrap(), None);
        Env { pic, cosigner, mock }
    }

    pub fn raw_update(&self, canister: Principal, sender: Principal, method: &str, arg: Vec<u8>) -> Result<Vec<u8>, String> {
        self.pic.update_call(canister, sender, method, arg).map_err(|e| format!("REJECTED: {e:?}"))
    }
    pub fn update<T: CandidType + DeserializeOwned>(&self, canister: Principal, sender: Principal, method: &str, arg: Vec<u8>) -> Result<T, String> {
        let r = self.raw_update(canister, sender, method, arg)?;
        Ok(decode_one(&r).expect("decode"))
    }
    pub fn query<T: CandidType + DeserializeOwned>(&self, canister: Principal, method: &str, arg: Vec<u8>) -> T {
        let r = self.pic.query_call(canister, Principal::anonymous(), method, arg).expect("query");
        decode_one(&r).expect("decode")
    }
    /// A co-signer method returning `variant { Ok : T; Err : text }`.
    pub fn call<T: CandidType + DeserializeOwned>(&self, sender: Principal, method: &str, arg: Vec<u8>) -> Result<T, String> {
        self.update::<Result<T, String>>(self.cosigner, sender, method, arg)?
    }

    pub fn set_account(&self, pubkey: &Key, owner: &Key, data: Vec<u8>) {
        self.raw_update(self.mock, Principal::anonymous(), "set_account", encode_args((b58(pubkey), b58(owner), data)).unwrap())
            .unwrap();
    }
    pub fn mock_mode(&self, mode: &str) {
        self.raw_update(self.mock, Principal::anonymous(), "set_mode", encode_one(mode.to_string()).unwrap()).unwrap();
    }
    pub fn seen(&self) -> Seen {
        self.query(self.mock, "seen", encode_one(()).unwrap())
    }
    pub fn addresses(&self, list: Vec<Address>) -> Result<Vec<AddressInfo>, String> {
        self.call(server(), "addresses", encode_one(list).unwrap())
    }
    pub fn cosigner_key(&self, a: Address) -> Key {
        let info = self.addresses(vec![a]).expect("addresses").remove(0);
        hex::decode(info.cosigner_key).unwrap().try_into().unwrap()
    }
    pub fn sign_payout(&self, sender: Principal, a: &PayoutArgs) -> Result<Signatures, String> {
        self.call(sender, "sign_payout", encode_one(a).unwrap())
    }
    pub fn sign_consolidation(&self, sender: Principal, a: &ConsolidationArgs) -> Result<Signatures, String> {
        self.call(sender, "sign_consolidation", encode_one(a).unwrap())
    }
    pub fn status(&self) -> Status {
        self.query(self.cosigner, "status", encode_one(()).unwrap())
    }
}

pub fn custody(mint: &Key) -> Address {
    Address::Custody { mint: b58(mint) }
}
pub fn deposit(mint: &Key, owner: &Key) -> Address {
    Address::Deposit { mint: b58(mint), owner: b58(owner) }
}
