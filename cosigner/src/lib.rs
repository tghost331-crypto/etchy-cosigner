//! Etchy custody co-signer canister (M62).
//!
//! Holds one of the two keys of every Etchy Rune custody address: a threshold
//! Schnorr (BIP340) key of the Internet Computer, derived per address. No
//! single machine ever has it. The canister signs ONLY:
//!  * payouts that pay exactly one finalized, Pending Solana bridge request,
//!    read by this canister itself through the SOL RPC canister (2 of 3 RPC
//!    providers must return the same bytes), at most once per request
//!    (replacements must spend an input of every earlier version), under a
//!    per-coin daily cap;
//!  * consolidations that keep one coin's Runes in that coin's custody.
//! The rules are `cosigner_core` (pure, unit-tested). The admin can pause,
//! unpause and choose which Etchy servers may ask; nobody can change the
//! rules except through new code, and the only controller is the timelock
//! canister: every code change is public for 48 hours before it can run.

use bitcoin::consensus::deserialize;
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::{Amount, Network, ScriptBuf, Transaction, TxOut};
use candid::{CandidType, Deserialize, Nat, Principal};
use cosigner_core::{self as core, Key, Path};
use ic_cdk::call::Call;
use ic_cdk::{init, inspect_message, post_upgrade, pre_upgrade, query, update};
use ic_cdk_management_canister::{
    schnorr_public_key, sign_with_schnorr, SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgs,
    SignWithSchnorrArgs,
};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

mod sol;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DAY_NS: u64 = 86_400 * 1_000_000_000;
/// A call that died mid-way releases its request after this long.
const LOCK_NS: u64 = 15 * 60 * 1_000_000_000;
/// Cycles attached to one SOL RPC read (the unused part is refunded).
const SOL_RPC_CYCLES: u128 = 25_000_000_000;
const SOL_RPC_RESPONSE_BYTES: u64 = 2_048;
/// Versions (fee bumps) one request may be signed in, at most.
const MAX_VERSIONS: usize = 6;
const MAX_CONSOLIDATIONS_PER_DAY: u32 = 48;
const MAX_CALLERS: usize = 10;
const MAX_ADDRESSES_PER_CALL: usize = 50;
const MAX_EVENTS: usize = 500;

// ---------------------------------------------------------------- interface

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

/// The rules' parameters. Changing them needs new code (the 48h timelock).
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Etchy's x-only leaf key E (hex). Part of every address: never changes.
    pub etchy_key: String,
    /// Backup leaf delay in blocks. Part of every address: never changes.
    pub backup_blocks: u16,
    /// Etchy's fee treasury scriptPubKey (hex, P2TR).
    pub fee_treasury_script: String,
    pub max_fee_sats: u64,
    pub max_postage_sats: u64,
    /// The Solana bridge program (base58): owner of every account read.
    pub bridge_program: String,
    /// Imported Runes: Solana atoms -> Rune units scale.
    pub scales: Vec<Scale>,
    /// Per coin: Solana atoms paid out per UTC day, at most (None: no cap).
    pub daily_cap_atoms: Option<u64>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArgs {
    /// Can pause, unpause and set callers. Can never sign or change rules.
    pub admin: Principal,
    /// Etchy servers allowed to ask for signatures.
    pub callers: Vec<Principal>,
    /// Threshold key: "key_1" (production) or "test_key_1" (test).
    pub key_name: String,
    pub cluster: Cluster,
    pub sol_rpc: Principal,
    pub settings: Settings,
}

/// Passed by the timelock on an upgrade (all optional).
#[derive(CandidType, Deserialize, Clone, Debug, Default)]
pub struct UpgradeArgs {
    pub admin: Option<Principal>,
    pub callers: Option<Vec<Principal>>,
    pub sol_rpc: Option<Principal>,
    pub settings: Option<Settings>,
}

/// A co-signed address: a coin's custody, or a (coin, Solana wallet) deposit.
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
    /// The unsigned transaction (consensus bytes).
    pub tx: Vec<u8>,
    /// The output each input spends, in input order.
    pub prevouts: Vec<Prevout>,
    /// The inputs to co-sign (every other input must be the fee treasury).
    pub inputs: Vec<CoSigned>,
    /// The Solana WithdrawalRequest account (base58).
    pub request: String,
    /// The Solana MintBridge account of the request's coin (base58).
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
    /// BIP340, 64 bytes, SIGHASH_DEFAULT, over leaf A (script path).
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
    /// The co-signer's x-only key for this address (hex).
    pub cosigner_key: String,
    pub script_pubkey: String,
    /// bc1p... (Mainnet) / tb1p... (Devnet).
    pub encoded: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct PayoutRecord {
    pub mint: String,
    pub atoms: u64,
    /// Every version signed for this request (fee bumps share an input).
    pub versions: Vec<Signatures>,
    /// Outpoints spent by every version: at most one version can confirm.
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
    pub cluster: Cluster,
    pub sol_rpc: Principal,
    pub settings: Settings,
    pub addresses_known: u64,
    pub payouts: u64,
    pub signatures: u64,
    pub consolidations_today: u32,
    pub paid_today: Vec<(String, u64)>,
    pub cycles: Nat,
}

// -------------------------------------------------------------------- state

#[derive(CandidType, Deserialize, Clone, Debug)]
struct State {
    init: InitArgs,
    paused: bool,
    /// Address id -> co-signer x-only key (hex).
    keys: BTreeMap<String, String>,
    /// Solana request -> what was signed for it.
    payouts: BTreeMap<String, PayoutRecord>,
    /// Requests being processed right now -> since when.
    locks: BTreeMap<String, u64>,
    day: u64,
    paid_today: BTreeMap<String, u64>,
    consolidations_today: u32,
    signatures: u64,
    events: Vec<Event>,
    next_event: u64,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

fn with<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|s| f(s.borrow().as_ref().expect("initialized")))
}
fn with_mut<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|s| f(s.borrow_mut().as_mut().expect("initialized")))
}
fn now() -> u64 {
    ic_cdk::api::time()
}
fn roll_day(s: &mut State) {
    let d = now() / DAY_NS;
    if s.day != d {
        s.day = d;
        s.paid_today.clear();
        s.consolidations_today = 0;
    }
}
fn event(s: &mut State, kind: &str, detail: String) {
    s.next_event += 1;
    s.events.push(Event { id: s.next_event, at: now(), kind: kind.into(), detail });
    if s.events.len() > MAX_EVENTS {
        s.events.remove(0);
    }
}

// ------------------------------------------------------------------ helpers

fn key32(v: Vec<u8>, code: &str) -> Result<Key, String> {
    v.try_into().map_err(|_| code.to_string())
}
fn hex32(s: &str, code: &str) -> Result<Key, String> {
    key32(hex::decode(s).map_err(|_| code.to_string())?, code)
}
fn b58(s: &str, code: &str) -> Result<Key, String> {
    key32(bs58::decode(s).into_vec().map_err(|_| code.to_string())?, code)
}
fn b58e(k: &Key) -> String {
    bs58::encode(k).into_string()
}

fn config(st: &Settings) -> Result<core::Config, String> {
    let mut scales = Vec::new();
    for s in &st.scales {
        scales.push((b58(&s.mint, "INVALID_SCALE_MINT")?, s.exp));
    }
    let c = core::Config {
        etchy_key: hex32(&st.etchy_key, "INVALID_ETCHY_KEY")?,
        backup_blocks: st.backup_blocks,
        fee_treasury_script: hex::decode(&st.fee_treasury_script)
            .map_err(|_| "INVALID_FEE_TREASURY")?,
        max_fee_sats: st.max_fee_sats,
        max_postage_sats: st.max_postage_sats,
        bridge_program: b58(&st.bridge_program, "INVALID_BRIDGE_PROGRAM")?,
        scales,
    };
    c.validate()?;
    if st.daily_cap_atoms == Some(0) {
        return Err("INVALID_DAILY_CAP".into());
    }
    Ok(c)
}
fn current_config() -> Result<core::Config, String> {
    with(|s| config(&s.init.settings))
}

fn path_of(a: &Address) -> Result<Path, String> {
    Ok(match a {
        Address::Custody { mint } => Path::Custody { mint: b58(mint, "INVALID_MINT")? },
        Address::Deposit { mint, owner } => Path::Deposit {
            mint: b58(mint, "INVALID_MINT")?,
            owner: b58(owner, "INVALID_OWNER")?,
        },
    })
}
fn address_of(p: &Path) -> Address {
    match p {
        Path::Custody { mint } => Address::Custody { mint: b58e(mint) },
        Path::Deposit { mint, owner } => Address::Deposit { mint: b58e(mint), owner: b58e(owner) },
    }
}
fn path_id(p: &Path) -> String {
    match p {
        Path::Custody { mint } => format!("c:{}", b58e(mint)),
        Path::Deposit { mint, owner } => format!("d:{}:{}", b58e(mint), b58e(owner)),
    }
}

fn key_id() -> SchnorrKeyId {
    SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Bip340secp256k1,
        name: with(|s| s.init.key_name.clone()),
    }
}

/// The co-signer key of an address (derived once by the network, then cached).
async fn cosigner_key(p: &Path) -> Result<Key, String> {
    let id = path_id(p);
    if let Some(k) = with(|s| s.keys.get(&id).cloned()) {
        return hex32(&k, "KEY_CACHE");
    }
    let r = schnorr_public_key(&SchnorrPublicKeyArgs {
        canister_id: None,
        derivation_path: p.derivation(),
        key_id: key_id(),
    })
    .await
    .map_err(|e| format!("THRESHOLD_KEY: {e:?}"))?;
    // SEC1 compressed (33 bytes); BIP340 uses the x coordinate.
    if r.public_key.len() != 33 {
        return Err("THRESHOLD_KEY_FORMAT".into());
    }
    let k = key32(r.public_key[1..].to_vec(), "THRESHOLD_KEY_FORMAT")?;
    with_mut(|s| s.keys.insert(id, hex::encode(k)));
    Ok(k)
}

fn info_of<C: Verification>(
    secp: &Secp256k1<C>,
    cfg: &core::Config,
    p: &Path,
    key: &Key,
) -> Result<AddressInfo, String> {
    let c = core::custody(secp, key, cfg)?;
    let network = match with(|s| s.init.cluster) {
        Cluster::Mainnet => Network::Bitcoin,
        Cluster::Devnet => Network::Testnet,
    };
    let encoded = bitcoin::Address::from_script(&c.script_pubkey, network)
        .map_err(|_| "ADDRESS_ENCODING")?
        .to_string();
    Ok(AddressInfo {
        address: address_of(p),
        cosigner_key: hex::encode(key),
        script_pubkey: hex::encode(c.script_pubkey.as_bytes()),
        encoded,
    })
}

/// One Solana account, as the network sees it: finalized, and 2 of 3 RPC
/// providers must return the same bytes. Returns (owner program, data).
async fn read_account(pubkey: &str) -> Result<(Key, Vec<u8>), String> {
    use sol::*;
    let (sol_rpc, cluster) = with(|s| (s.init.sol_rpc, s.init.cluster));
    let sources = RpcSources::Default(match cluster {
        Cluster::Mainnet => SolanaCluster::Mainnet,
        Cluster::Devnet => SolanaCluster::Devnet,
    });
    let config = RpcConfig {
        responseSizeEstimate: Some(SOL_RPC_RESPONSE_BYTES),
        responseConsensus: Some(ConsensusStrategy::Threshold { total: Some(3), min: 2 }),
    };
    let params = GetAccountInfoParams {
        pubkey: pubkey.to_string(),
        commitment: Some(CommitmentLevel::finalized),
        encoding: Some(GetAccountInfoEncoding::base64),
        dataSlice: None,
        minContextSlot: None,
    };
    let res = Call::bounded_wait(sol_rpc, "getAccountInfo")
        .with_args(&(sources, Some(config), params))
        .with_cycles(SOL_RPC_CYCLES)
        .await
        .map_err(|e| format!("SOL_RPC_CALL: {e:?}"))?;
    let r: MultiGetAccountInfoResult =
        res.candid().map_err(|e| format!("SOL_RPC_DECODE: {e:?}"))?;
    let info = match r {
        MultiGetAccountInfoResult::Consistent(GetAccountInfoResult::Ok(Some(i))) => i,
        MultiGetAccountInfoResult::Consistent(GetAccountInfoResult::Ok(None)) => {
            return Err("SOLANA_ACCOUNT_NOT_FOUND".into())
        }
        MultiGetAccountInfoResult::Consistent(GetAccountInfoResult::Err(e)) => {
            return Err(format!("SOL_RPC_ERROR: {e:?}"))
        }
        MultiGetAccountInfoResult::Inconsistent(_) => {
            return Err("SOL_RPC_PROVIDERS_DISAGREE".into())
        }
    };
    let data = match info.data {
        AccountData::binary(b, AccountEncoding::base64) => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(b)
                .map_err(|_| "SOL_RPC_DATA")?
        }
        _ => return Err("SOL_RPC_ENCODING".into()),
    };
    Ok((b58(&info.owner, "SOL_RPC_OWNER")?, data))
}

fn prevouts(p: &[Prevout]) -> Vec<TxOut> {
    p.iter()
        .map(|o| TxOut {
            value: Amount::from_sat(o.value),
            script_pubkey: ScriptBuf::from_bytes(o.script_pubkey.clone()),
        })
        .collect()
}
fn cosigned(inputs: &[CoSigned]) -> Result<Vec<(usize, Path)>, String> {
    inputs.iter().map(|i| Ok((i.index as usize, path_of(&i.address)?))).collect()
}
fn parse_tx(bytes: &[u8]) -> Result<Transaction, String> {
    deserialize(bytes).map_err(|_| "INVALID_TX".to_string())
}

/// Threshold-sign every approved sighash, then check each signature.
async fn sign_all<C: Verification>(
    secp: &Secp256k1<C>,
    signed: &[core::Signed],
    sighashes: &[(usize, [u8; 32])],
) -> Result<Vec<InputSignature>, String> {
    let mut out = Vec::new();
    for (i, msg) in sighashes {
        let (_, path, key) = signed.iter().find(|(j, _, _)| j == i).ok_or("SIGHASH_INPUT")?;
        let r = sign_with_schnorr(&SignWithSchnorrArgs {
            message: msg.to_vec(),
            derivation_path: path.derivation(),
            key_id: key_id(),
            aux: None,
        })
        .await
        .map_err(|e| format!("THRESHOLD_SIGN: {e:?}"))?;
        if !core::verify(secp, key, msg, &r.signature) {
            return Err("THRESHOLD_SIGNATURE_INVALID".into());
        }
        out.push(InputSignature { index: *i as u32, signature: r.signature });
    }
    Ok(out)
}

/// One request at a time; a payout's daily-cap reservation is released if
/// the call does not finish.
struct Lock {
    request: String,
    reserved: Option<(u64, String, u64)>,
    done: bool,
}
impl Lock {
    fn take(request: &str) -> Result<Lock, String> {
        with_mut(|s| {
            let t = now();
            if let Some(at) = s.locks.get(request) {
                if t.saturating_sub(*at) < LOCK_NS {
                    return Err("REQUEST_IN_PROGRESS".to_string());
                }
            }
            s.locks.insert(request.to_string(), t);
            Ok(())
        })?;
        Ok(Lock { request: request.to_string(), reserved: None, done: false })
    }
    fn reserve(&mut self, s: &mut State, mint: &str, atoms: u64) {
        *s.paid_today.entry(mint.to_string()).or_default() += atoms;
        self.reserved = Some((s.day, mint.to_string(), atoms));
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        STATE.with(|st| {
            if let Ok(mut b) = st.try_borrow_mut() {
                if let Some(s) = b.as_mut() {
                    s.locks.remove(&self.request);
                    if let (false, Some((day, mint, atoms))) = (self.done, &self.reserved) {
                        if s.day == *day {
                            if let Some(u) = s.paid_today.get_mut(mint) {
                                *u = u.saturating_sub(*atoms);
                            }
                        }
                    }
                }
            }
        });
    }
}

fn caller() -> Principal {
    ic_cdk::api::msg_caller()
}
fn require_caller() -> Result<(), String> {
    let c = caller();
    with(|s| {
        if !s.init.callers.contains(&c) {
            return Err("NOT_ALLOWED".to_string());
        }
        if s.paused {
            return Err("PAUSED".to_string());
        }
        Ok(())
    })
}
fn require_admin() -> Result<(), String> {
    let c = caller();
    with(|s| if s.init.admin == c { Ok(()) } else { Err("NOT_ADMIN".to_string()) })
}

// ---------------------------------------------------------------- lifecycle

fn validate_init(a: &InitArgs) -> Result<(), String> {
    config(&a.settings)?;
    if a.key_name.is_empty() {
        return Err("INVALID_KEY_NAME".into());
    }
    if a.callers.len() > MAX_CALLERS || a.admin == Principal::anonymous() {
        return Err("INVALID_PRINCIPALS".into());
    }
    if a.callers.iter().any(|c| *c == Principal::anonymous()) {
        return Err("INVALID_PRINCIPALS".into());
    }
    Ok(())
}

#[init]
fn init(args: InitArgs) {
    if let Err(e) = validate_init(&args) {
        ic_cdk::trap(format!("INIT: {e}"));
    }
    let mut s = State {
        init: args,
        paused: false,
        keys: BTreeMap::new(),
        payouts: BTreeMap::new(),
        locks: BTreeMap::new(),
        day: now() / DAY_NS,
        paid_today: BTreeMap::new(),
        consolidations_today: 0,
        signatures: 0,
        events: Vec::new(),
        next_event: 0,
    };
    let detail = format!("version {VERSION}, key {}", s.init.key_name);
    event(&mut s, "INSTALLED", detail);
    STATE.with(|st| *st.borrow_mut() = Some(s));
}

#[pre_upgrade]
fn pre_upgrade() {
    let s = STATE.with(|st| st.borrow_mut().take()).expect("initialized");
    ic_cdk::storage::stable_save((s,)).expect("stable save");
}

#[post_upgrade]
fn post_upgrade(args: Option<UpgradeArgs>) {
    let (mut s,): (State,) = ic_cdk::storage::stable_restore().expect("stable restore");
    let a = args.unwrap_or_default();
    if let Some(admin) = a.admin {
        s.init.admin = admin;
    }
    if let Some(callers) = a.callers {
        s.init.callers = callers;
    }
    if let Some(sol_rpc) = a.sol_rpc {
        s.init.sol_rpc = sol_rpc;
    }
    if let Some(settings) = a.settings {
        // E and the backup delay are part of every address: changing them
        // would strand every Rune already in custody.
        if settings.etchy_key != s.init.settings.etchy_key
            || settings.backup_blocks != s.init.settings.backup_blocks
        {
            ic_cdk::trap("UPGRADE: etchy_key and backup_blocks never change");
        }
        s.init.settings = settings;
    }
    if let Err(e) = validate_init(&s.init) {
        ic_cdk::trap(format!("UPGRADE: {e}"));
    }
    s.locks.clear();
    event(&mut s, "UPGRADED", format!("version {VERSION}"));
    STATE.with(|st| *st.borrow_mut() = Some(s));
}

/// Ingress filter: only the admin and the callers may send update calls
/// (anyone else would only burn the canister's cycles).
#[inspect_message]
fn inspect() {
    let c = caller();
    if with(|s| s.init.admin == c || s.init.callers.contains(&c)) {
        ic_cdk::api::accept_message();
    }
}

// ------------------------------------------------------------------ signing

/// The co-signer keys and addresses (derived on first use).
#[update]
async fn addresses(list: Vec<Address>) -> Result<Vec<AddressInfo>, String> {
    require_caller()?;
    if list.len() > MAX_ADDRESSES_PER_CALL {
        return Err("TOO_MANY_ADDRESSES".into());
    }
    let cfg = current_config()?;
    let secp = Secp256k1::verification_only();
    let mut out = Vec::new();
    for a in &list {
        let p = path_of(a)?;
        let k = cosigner_key(&p).await?;
        out.push(info_of(&secp, &cfg, &p, &k)?);
    }
    Ok(out)
}

/// Sign a payout of exactly one Solana bridge request.
#[update]
async fn sign_payout(a: PayoutArgs) -> Result<Signatures, String> {
    require_caller()?;
    let cfg = current_config()?;
    let tx = parse_tx(&a.tx)?;
    let txid = tx.compute_txid().to_string();
    let prev = prevouts(&a.prevouts);
    let paths = cosigned(&a.inputs)?;
    b58(&a.request, "INVALID_REQUEST")?;
    b58(&a.mint_bridge, "INVALID_MINT_BRIDGE")?;
    // A retry of the same transaction gets the same signatures (nothing new).
    let again = with(|s| {
        s.payouts
            .get(&a.request)
            .and_then(|r| r.versions.iter().find(|v| v.txid == txid).cloned())
    });
    if let Some(v) = again {
        return Ok(v);
    }
    let mut lock = Lock::take(&a.request)?;

    // Solana, read by the canister itself.
    let (owner, data) = read_account(&a.request).await?;
    if owner != cfg.bridge_program {
        return Err("REQUEST_NOT_FROM_BRIDGE".into());
    }
    let request = core::parse_request(&data)?;
    let (owner, data) = read_account(&a.mint_bridge).await?;
    if owner != cfg.bridge_program {
        return Err("MINT_BRIDGE_NOT_FROM_BRIDGE".into());
    }
    let mint_bridge = core::parse_mint_bridge(&data)?;
    let mint = b58e(&request.mint);
    if paths.iter().any(|(_, p)| p.mint() != request.mint) {
        return Err("INPUT_OF_ANOTHER_COIN".into());
    }

    let mut signed = Vec::new();
    for (i, p) in &paths {
        signed.push((*i, p.clone(), cosigner_key(p).await?));
    }
    let change_key = cosigner_key(&Path::Custody { mint: request.mint }).await?;
    let secp = Secp256k1::verification_only();
    let approved = core::check_payout(
        &secp,
        &cfg,
        &core::Payout {
            tx: &tx,
            prevouts: &prev,
            signed: &signed,
            change_key,
            request: &request,
            mint_bridge: &mint_bridge,
        },
    )?;

    // At most one payout per request: a new version (fee bump) must spend
    // an outpoint that every earlier version spends.
    let spent: BTreeSet<String> = tx.input.iter().map(|i| i.previous_output.to_string()).collect();
    let first = with_mut(|s| -> Result<bool, String> {
        roll_day(s);
        match s.payouts.get(&a.request) {
            Some(r) => {
                if r.versions.len() >= MAX_VERSIONS {
                    return Err("TOO_MANY_VERSIONS".into());
                }
                if !r.common.iter().any(|o| spent.contains(o)) {
                    return Err("REQUEST_ALREADY_SIGNED".into());
                }
                Ok(false)
            }
            None => {
                let used = s.paid_today.get(&mint).copied().unwrap_or(0);
                if let Some(cap) = s.init.settings.daily_cap_atoms {
                    if used.saturating_add(request.amount) > cap {
                        return Err("DAILY_CAP".into());
                    }
                }
                lock.reserve(s, &mint, request.amount);
                Ok(true)
            }
        }
    })?;

    let signatures = sign_all(&secp, &signed, &approved.sighashes).await?;
    let out = Signatures { txid: approved.txid.clone(), fee_sats: approved.fee_sats, signatures };
    with_mut(|s| {
        let n = out.signatures.len() as u64;
        s.signatures += n;
        if first {
            s.payouts.insert(
                a.request.clone(),
                PayoutRecord {
                    mint: mint.clone(),
                    atoms: request.amount,
                    versions: vec![out.clone()],
                    common: spent.iter().cloned().collect(),
                    first_at: now(),
                },
            );
        } else if let Some(r) = s.payouts.get_mut(&a.request) {
            r.versions.push(out.clone());
            r.common.retain(|o| spent.contains(o));
        }
        event(
            s,
            "PAYOUT",
            format!(
                "request {} mint {} atoms {} txid {} fee {} inputs {}{}",
                a.request,
                mint,
                request.amount,
                out.txid,
                out.fee_sats,
                n,
                if first { "" } else { " (replacement)" }
            ),
        );
    });
    lock.done = true;
    Ok(out)
}

/// Sign a consolidation: one coin's custody/deposit outputs back into that
/// coin's custody (no Runestone: every Rune goes to output 0).
#[update]
async fn sign_consolidation(a: ConsolidationArgs) -> Result<Signatures, String> {
    require_caller()?;
    let cfg = current_config()?;
    let mint = b58(&a.mint, "INVALID_MINT")?;
    let tx = parse_tx(&a.tx)?;
    let prev = prevouts(&a.prevouts);
    let paths = cosigned(&a.inputs)?;
    if paths.iter().any(|(_, p)| p.mint() != mint) {
        return Err("INPUT_OF_ANOTHER_COIN".into());
    }
    with_mut(|s| {
        roll_day(s);
        if s.consolidations_today >= MAX_CONSOLIDATIONS_PER_DAY {
            Err("CONSOLIDATION_DAILY_LIMIT".to_string())
        } else {
            Ok(())
        }
    })?;
    let mut signed = Vec::new();
    for (i, p) in &paths {
        signed.push((*i, p.clone(), cosigner_key(p).await?));
    }
    let custody_key = cosigner_key(&Path::Custody { mint }).await?;
    let secp = Secp256k1::verification_only();
    let approved = core::check_consolidation(
        &secp,
        &cfg,
        &core::Consolidation { tx: &tx, prevouts: &prev, signed: &signed, mint, custody_key },
    )?;
    let signatures = sign_all(&secp, &signed, &approved.sighashes).await?;
    let out = Signatures { txid: approved.txid.clone(), fee_sats: approved.fee_sats, signatures };
    with_mut(|s| {
        roll_day(s);
        s.consolidations_today += 1;
        s.signatures += out.signatures.len() as u64;
        event(
            s,
            "CONSOLIDATION",
            format!("mint {} txid {} fee {} inputs {}", b58e(&mint), out.txid, out.fee_sats, out.signatures.len()),
        );
    });
    Ok(out)
}

// -------------------------------------------------------------------- admin

/// Stop all signing (the admin or any Etchy server: pausing is always safe).
#[update]
fn pause(reason: String) -> Result<(), String> {
    let c = caller();
    let ok = with(|s| s.init.admin == c || s.init.callers.contains(&c));
    if !ok {
        return Err("NOT_ALLOWED".into());
    }
    with_mut(|s| {
        s.paused = true;
        let r: String = reason.chars().take(200).collect();
        event(s, "PAUSED", format!("by {c}: {r}"));
    });
    Ok(())
}

#[update]
fn unpause() -> Result<(), String> {
    require_admin()?;
    with_mut(|s| {
        s.paused = false;
        event(s, "UNPAUSED", format!("by {}", caller()));
    });
    Ok(())
}

/// Which Etchy servers may ask for signatures (they can only get signatures
/// the rules allow; this is about who pays the cycles).
#[update]
fn set_callers(callers: Vec<Principal>) -> Result<(), String> {
    require_admin()?;
    if callers.len() > MAX_CALLERS || callers.iter().any(|c| *c == Principal::anonymous()) {
        return Err("INVALID_PRINCIPALS".into());
    }
    with_mut(|s| {
        let list: Vec<String> = callers.iter().map(|c| c.to_string()).collect();
        s.init.callers = callers;
        event(s, "CALLERS", list.join(","));
    });
    Ok(())
}

// ------------------------------------------------------------------ queries

#[query]
fn status() -> Status {
    with(|s| Status {
        version: VERSION.into(),
        paused: s.paused,
        admin: s.init.admin,
        callers: s.init.callers.clone(),
        key_name: s.init.key_name.clone(),
        cluster: s.init.cluster,
        sol_rpc: s.init.sol_rpc,
        settings: s.init.settings.clone(),
        addresses_known: s.keys.len() as u64,
        payouts: s.payouts.len() as u64,
        signatures: s.signatures,
        consolidations_today: if s.day == now() / DAY_NS { s.consolidations_today } else { 0 },
        paid_today: if s.day == now() / DAY_NS {
            s.paid_today.iter().map(|(k, v)| (k.clone(), *v)).collect()
        } else {
            vec![]
        },
        cycles: Nat::from(ic_cdk::api::canister_cycle_balance()),
    })
}

/// A known address (anyone can check Etchy's custody addresses).
#[query]
fn address(a: Address) -> Result<Option<AddressInfo>, String> {
    let p = path_of(&a)?;
    let Some(k) = with(|s| s.keys.get(&path_id(&p)).cloned()) else {
        return Ok(None);
    };
    let cfg = current_config()?;
    let secp = Secp256k1::verification_only();
    Ok(Some(info_of(&secp, &cfg, &p, &hex32(&k, "KEY_CACHE")?)?))
}

#[query]
fn payout(request: String) -> Option<PayoutRecord> {
    with(|s| s.payouts.get(&request).cloned())
}

/// Public log (newest last), up to 100 events after `after`.
#[query]
fn events(after: u64) -> Vec<Event> {
    with(|s| s.events.iter().filter(|e| e.id > after).take(100).cloned().collect())
}

ic_cdk::export_candid!();
