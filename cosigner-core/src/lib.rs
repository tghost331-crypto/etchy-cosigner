//! Etchy custody co-signer: the rules, as pure functions (no IC dependencies).
//!
//! Every Rune Etchy holds sits at a 2-of-2 Taproot address:
//!
//!   internal key : NUMS point (BIP341 "H"): no key-path spend, ever
//!   leaf A       : <C> OP_CHECKSIGVERIFY <E> OP_CHECKSIG      (co-signer + Etchy)
//!   leaf B       : <blocks> OP_CSV OP_DROP <E> OP_CHECKSIG     (Etchy alone, only
//!                  after the output has not moved for `blocks` blocks: the backup)
//!
//! `E` is Etchy's key (one Turnkey account's output key, fixed in the config).
//! `C` is the co-signer's threshold key, derived per address by the ICP
//! network from a path that names the coin's Solana mint (custody) or the
//! mint and the depositor (deposit addresses). So an input can only ever be
//! co-signed for a request of ITS OWN coin: a bridge entry pointing a new mint
//! at another coin's Rune can never reach that coin's Runes.
//!
//! The co-signer signs only two transaction shapes, re-derived here from the
//! exact bytes:
//!   * payout: exactly the Solana WithdrawalRequest (finalized, Pending):
//!     out0 = the user's Taproot key, out1 = custody(mint) change,
//!     out2 = OP_RETURN Runestone {pointer 1; edict(rune, units, 0)} byte-exact,
//!     out3 = optional fee change to Etchy's fee treasury.
//!     The pointer always targets custody, so every Rune not sent by the edict
//!     (whatever the inputs hold) stays in custody.
//!   * consolidation: custody/deposit outputs of ONE coin back into
//!     custody(mint) (no OP_RETURN: every Rune goes to out0), + fee change.
//! Other inputs may only be Etchy's fee treasury (it pays the miner).

use bitcoin::absolute::LockTime;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::opcodes::all::{
    OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CSV, OP_DROP, OP_PUSHNUM_13, OP_RETURN,
};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, Verification, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{ScriptBuf, Transaction, TxOut};
use std::collections::BTreeSet;

/// BIP341 NUMS point H (x-only): provably no private key.
pub const NUMS: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];
pub const DUST_SATS: u64 = 330;
pub const MAX_INPUTS: usize = 30;
/// Status byte of an Anchor `WithdrawalStatus::Pending`.
pub const PENDING: u8 = 0;

pub type Key = [u8; 32];

/// Where an address lives. The ICP derivation path is a pure function of it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Path {
    /// The coin's custody (premine, change, consolidations).
    Custody { mint: Key },
    /// Bridge to Solana: one deposit address per (coin, Solana wallet).
    Deposit { mint: Key, owner: Key },
}
impl Path {
    pub fn mint(&self) -> Key {
        match self {
            Path::Custody { mint } | Path::Deposit { mint, .. } => *mint,
        }
    }
    /// The threshold-key derivation path (never changes for an address).
    pub fn derivation(&self) -> Vec<Vec<u8>> {
        match self {
            Path::Custody { mint } => vec![b"etchy-custody".to_vec(), mint.to_vec()],
            Path::Deposit { mint, owner } => {
                vec![b"etchy-deposit".to_vec(), mint.to_vec(), owner.to_vec()]
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Etchy's x-only key in every leaf (a Turnkey account's output key).
    pub etchy_key: Key,
    /// Backup leaf: blocks an output must stay unmoved before Etchy alone can spend it.
    pub backup_blocks: u16,
    /// Etchy's fee treasury (pays miner fees; receives BTC change only).
    pub fee_treasury_script: Vec<u8>,
    pub max_fee_sats: u64,
    pub max_postage_sats: u64,
    /// The Solana bridge program (owner of every account read).
    pub bridge_program: Key,
    /// Imported Runes: (mint, exp) with atoms = units x 10^exp (exp < 0: units / 10^-exp).
    pub scales: Vec<(Key, i8)>,
}
impl Config {
    pub fn validate(&self) -> Result<(), String> {
        XOnlyPublicKey::from_slice(&self.etchy_key).map_err(|_| "INVALID_ETCHY_KEY")?;
        if self.etchy_key == NUMS {
            return Err("INVALID_ETCHY_KEY".into());
        }
        // At least ~1 week; Bitcoin's relative lock-time maximum is 65535 blocks.
        if self.backup_blocks < 1_008 {
            return Err("BACKUP_TOO_SHORT".into());
        }
        let s = &self.fee_treasury_script;
        if s.len() != 34 || s[0] != 0x51 || s[1] != 0x20 {
            return Err("FEE_TREASURY_NOT_P2TR".into());
        }
        if self.max_fee_sats == 0 || self.max_fee_sats > 1_000_000 {
            return Err("INVALID_MAX_FEE".into());
        }
        if self.max_postage_sats < DUST_SATS || self.max_postage_sats > 100_000 {
            return Err("INVALID_MAX_POSTAGE".into());
        }
        let mut seen = BTreeSet::new();
        for (mint, exp) in &self.scales {
            if !seen.insert(*mint) || *exp < -18 || *exp > 18 {
                return Err("INVALID_SCALE".into());
            }
        }
        Ok(())
    }
    pub fn scale(&self, mint: &Key) -> i8 {
        self.scales.iter().find(|(m, _)| m == mint).map(|(_, e)| *e).unwrap_or(0)
    }
}

fn xonly(k: &Key, code: &str) -> Result<XOnlyPublicKey, String> {
    XOnlyPublicKey::from_slice(k).map_err(|_| code.to_string())
}

pub fn multisig_leaf(cosigner: &XOnlyPublicKey, etchy: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(cosigner)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(etchy)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}
pub fn backup_leaf(etchy: &XOnlyPublicKey, blocks: u16) -> ScriptBuf {
    Builder::new()
        .push_int(i64::from(blocks))
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(etchy)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// One 2-of-2 custody address, fully derived.
#[derive(Clone, Debug)]
pub struct Custody {
    pub script_pubkey: ScriptBuf,
    pub output_key: Key,
    pub multisig: ScriptBuf,
    pub backup: ScriptBuf,
    /// Control block of leaf A (for the witness).
    pub control_block: Vec<u8>,
    pub leaf_hash: TapLeafHash,
}
pub fn custody<C: Verification>(
    secp: &Secp256k1<C>,
    cosigner: &Key,
    cfg: &Config,
) -> Result<Custody, String> {
    let c = xonly(cosigner, "INVALID_COSIGNER_KEY")?;
    let e = xonly(&cfg.etchy_key, "INVALID_ETCHY_KEY")?;
    if c == e {
        return Err("KEYS_NOT_DISTINCT".into());
    }
    let multisig = multisig_leaf(&c, &e);
    let backup = backup_leaf(&e, cfg.backup_blocks);
    let internal = XOnlyPublicKey::from_slice(&NUMS).expect("NUMS is a point");
    let info = TaprootBuilder::new()
        .add_leaf(1, multisig.clone())
        .and_then(|b| b.add_leaf(1, backup.clone()))
        .map_err(|_| "TAPROOT_BUILD")?
        .finalize(secp, internal)
        .map_err(|_| "TAPROOT_BUILD")?;
    let control_block = info
        .control_block(&(multisig.clone(), LeafVersion::TapScript))
        .ok_or("TAPROOT_BUILD")?
        .serialize();
    let output_key = info.output_key();
    Ok(Custody {
        script_pubkey: ScriptBuf::new_p2tr_tweaked(output_key),
        output_key: output_key.to_x_only_public_key().serialize(),
        leaf_hash: TapLeafHash::from_script(&multisig, LeafVersion::TapScript),
        multisig,
        backup,
        control_block,
    })
}

fn varint(mut n: u128, out: &mut Vec<u8>) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}
/// The ONLY Runestone a payout may carry (ord encipher, byte-exact):
/// Pointer(22)=pointer, Body(0), edict(block, tx, amount, output 0).
pub fn payout_runestone(block: u64, tx: u32, amount: u128, pointer: u32) -> ScriptBuf {
    let mut p = Vec::new();
    varint(22, &mut p);
    varint(u128::from(pointer), &mut p);
    varint(0, &mut p);
    varint(u128::from(block), &mut p);
    varint(u128::from(tx), &mut p);
    varint(amount, &mut p);
    varint(0, &mut p);
    Builder::new()
        .push_opcode(OP_RETURN)
        .push_opcode(OP_PUSHNUM_13)
        .push_slice(PushBytesBuf::try_from(p).expect("small payload"))
        .into_script()
}

// ---- Solana accounts (Anchor layout of solana/programs/etchy-bridge).
pub fn discriminator(name: &str) -> [u8; 8] {
    let h = sha256::Hash::hash(format!("account:{name}").as_bytes());
    let mut d = [0u8; 8];
    d.copy_from_slice(&h.as_byte_array()[..8]);
    d
}
fn key_at(data: &[u8], at: usize) -> Key {
    let mut k = [0u8; 32];
    k.copy_from_slice(&data[at..at + 32]);
    k
}
fn u64_at(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().expect("8 bytes"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub mint: Key,
    pub seq: u64,
    pub request_id: u64,
    pub user: Key,
    pub amount: u64,
    pub witness_program: Key,
    pub status: u8,
    pub btc_txid: Key,
}
/// `WithdrawalRequest`: disc, mint, seq, request_id, user, user_token, amount,
/// btc_witness_program, status, btc_txid, requested_at, bump.
pub fn parse_request(data: &[u8]) -> Result<Request, String> {
    if data.len() < 202 || data[..8] != discriminator("WithdrawalRequest") {
        return Err("NOT_A_WITHDRAWAL_REQUEST".into());
    }
    Ok(Request {
        mint: key_at(data, 8),
        seq: u64_at(data, 40),
        request_id: u64_at(data, 48),
        user: key_at(data, 56),
        amount: u64_at(data, 120),
        witness_program: key_at(data, 128),
        status: data[160],
        btc_txid: key_at(data, 161),
    })
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintBridge {
    pub mint: Key,
    pub rune_block: u64,
    pub rune_tx: u32,
    pub enabled: bool,
    pub paused: bool,
}
/// `MintBridge`: disc, mint, vault, rune_block, rune_tx, enabled, paused, ...
pub fn parse_mint_bridge(data: &[u8]) -> Result<MintBridge, String> {
    if data.len() < 86 || data[..8] != discriminator("MintBridge") {
        return Err("NOT_A_MINT_BRIDGE".into());
    }
    Ok(MintBridge {
        mint: key_at(data, 8),
        rune_block: u64_at(data, 72),
        rune_tx: u32::from_le_bytes(data[80..84].try_into().expect("4 bytes")),
        enabled: data[84] == 1,
        paused: data[85] == 1,
    })
}
/// Solana token atoms -> Rune units (exactly; a remainder is refused).
pub fn rune_units(atoms: u64, exp: i8) -> Result<u128, String> {
    let a = u128::from(atoms);
    if exp >= 0 {
        let d = 10u128.pow(exp as u32);
        if a % d != 0 {
            return Err("NOT_WHOLE_RUNE_UNITS".into());
        }
        Ok(a / d)
    } else {
        Ok(a * 10u128.pow((-exp) as u32))
    }
}

/// An input the co-signer signs: (input index, its address path, its co-signer key).
pub type Signed = (usize, Path, Key);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approved {
    pub txid: String,
    /// (input index, BIP341 script-path sighash of leaf A).
    pub sighashes: Vec<(usize, [u8; 32])>,
    pub fee_sats: u64,
    /// Rune units paid (payouts; 0 for consolidations).
    pub units: u128,
}

fn shape(tx: &Transaction, prevouts: &[TxOut]) -> Result<(), String> {
    if tx.version != Version::TWO || tx.lock_time != LockTime::ZERO {
        return Err("TX_VERSION_OR_LOCKTIME".into());
    }
    if tx.input.is_empty() || tx.input.len() > MAX_INPUTS || prevouts.len() != tx.input.len() {
        return Err("TX_INPUTS".into());
    }
    Ok(())
}
fn fee(tx: &Transaction, prevouts: &[TxOut], cfg: &Config) -> Result<u64, String> {
    let mut input: u64 = 0;
    for p in prevouts {
        input = input.checked_add(p.value.to_sat()).ok_or("AMOUNT_OVERFLOW")?;
    }
    let mut output: u64 = 0;
    for o in &tx.output {
        output = output.checked_add(o.value.to_sat()).ok_or("AMOUNT_OVERFLOW")?;
    }
    let fee = input.checked_sub(output).ok_or("OUTPUTS_ABOVE_INPUTS")?;
    if fee > cfg.max_fee_sats {
        return Err("FEE_TOO_HIGH".into());
    }
    Ok(fee)
}
/// Every co-signed input is a custody/deposit address of `mint`; every other
/// input is Etchy's fee treasury. Returns the sighash of each co-signed input.
fn inputs<C: Verification>(
    secp: &Secp256k1<C>,
    cfg: &Config,
    tx: &Transaction,
    prevouts: &[TxOut],
    signed: &[Signed],
    mint: &Key,
) -> Result<Vec<(usize, [u8; 32])>, String> {
    if signed.is_empty() {
        return Err("NO_CUSTODY_INPUT".into());
    }
    let mut seen = BTreeSet::new();
    let mut leaves = Vec::new();
    for (i, path, key) in signed {
        if *i >= tx.input.len() || !seen.insert(*i) {
            return Err("BAD_INPUT_INDEX".into());
        }
        if path.mint() != *mint {
            return Err("INPUT_OF_ANOTHER_COIN".into());
        }
        let c = custody(secp, key, cfg)?;
        if prevouts[*i].script_pubkey != c.script_pubkey {
            return Err("INPUT_NOT_CUSTODY".into());
        }
        leaves.push((*i, c.leaf_hash));
    }
    for (i, p) in prevouts.iter().enumerate() {
        if !seen.contains(&i) && p.script_pubkey.as_bytes() != cfg.fee_treasury_script.as_slice() {
            return Err("FOREIGN_INPUT".into());
        }
    }
    let all = Prevouts::All(prevouts);
    let mut cache = SighashCache::new(tx);
    let mut out = Vec::new();
    for (i, leaf) in leaves {
        let h = cache
            .taproot_script_spend_signature_hash(i, &all, leaf, TapSighashType::Default)
            .map_err(|_| "SIGHASH")?;
        out.push((i, h.to_byte_array()));
    }
    Ok(out)
}

pub struct Payout<'a> {
    pub tx: &'a Transaction,
    pub prevouts: &'a [TxOut],
    pub signed: &'a [Signed],
    /// Co-signer key of `Path::Custody { mint: request.mint }` (the change).
    pub change_key: Key,
    pub request: &'a Request,
    pub mint_bridge: &'a MintBridge,
}
pub fn check_payout<C: Verification>(
    secp: &Secp256k1<C>,
    cfg: &Config,
    p: &Payout,
) -> Result<Approved, String> {
    cfg.validate()?;
    let (tx, r, mb) = (p.tx, p.request, p.mint_bridge);
    if r.status != PENDING {
        return Err("REQUEST_NOT_PENDING".into());
    }
    if r.mint != mb.mint {
        return Err("MINT_MISMATCH".into());
    }
    if !mb.enabled || mb.paused {
        return Err("COIN_NOT_BRIDGEABLE".into());
    }
    if mb.rune_block == 0 {
        return Err("RUNE_NOT_LINKED".into());
    }
    if r.amount == 0 {
        return Err("ZERO_AMOUNT".into());
    }
    let units = rune_units(r.amount, cfg.scale(&r.mint))?;
    if units == 0 {
        return Err("ZERO_AMOUNT".into());
    }
    shape(tx, p.prevouts)?;
    if tx.output.len() != 3 && tx.output.len() != 4 {
        return Err("PAYOUT_OUTPUTS".into());
    }
    // out0: the user's Taproot key, exactly as locked on Solana.
    XOnlyPublicKey::from_slice(&r.witness_program).map_err(|_| "DESTINATION_NOT_SPENDABLE")?;
    let mut dest = vec![0x51, 0x20];
    dest.extend_from_slice(&r.witness_program);
    let postage = |v: u64| v >= DUST_SATS && v <= cfg.max_postage_sats;
    let o = &tx.output;
    if o[0].script_pubkey.as_bytes() != dest.as_slice() || !postage(o[0].value.to_sat()) {
        return Err("WRONG_DESTINATION".into());
    }
    // out1: the coin's own custody (every other Rune goes here, by pointer).
    let change = custody(secp, &p.change_key, cfg)?;
    if o[1].script_pubkey != change.script_pubkey || !postage(o[1].value.to_sat()) {
        return Err("WRONG_CHANGE".into());
    }
    // out2: the exact Runestone.
    if o[2].script_pubkey != payout_runestone(mb.rune_block, mb.rune_tx, units, 1)
        || o[2].value.to_sat() != 0
    {
        return Err("WRONG_RUNESTONE".into());
    }
    if o.len() == 4 && o[3].script_pubkey.as_bytes() != cfg.fee_treasury_script.as_slice() {
        return Err("WRONG_FEE_CHANGE".into());
    }
    let sighashes = inputs(secp, cfg, tx, p.prevouts, p.signed, &r.mint)?;
    Ok(Approved {
        txid: tx.compute_txid().to_string(),
        sighashes,
        fee_sats: fee(tx, p.prevouts, cfg)?,
        units,
    })
}

pub struct Consolidation<'a> {
    pub tx: &'a Transaction,
    pub prevouts: &'a [TxOut],
    pub signed: &'a [Signed],
    pub mint: Key,
    /// Co-signer key of `Path::Custody { mint }` (the destination).
    pub custody_key: Key,
}
pub fn check_consolidation<C: Verification>(
    secp: &Secp256k1<C>,
    cfg: &Config,
    p: &Consolidation,
) -> Result<Approved, String> {
    cfg.validate()?;
    let tx = p.tx;
    shape(tx, p.prevouts)?;
    if tx.output.is_empty() || tx.output.len() > 2 {
        return Err("CONSOLIDATION_OUTPUTS".into());
    }
    let target = custody(secp, &p.custody_key, cfg)?;
    if tx.output[0].script_pubkey != target.script_pubkey || tx.output[0].value.to_sat() < DUST_SATS {
        return Err("WRONG_CUSTODY_OUTPUT".into());
    }
    if tx.output.len() == 2
        && tx.output[1].script_pubkey.as_bytes() != cfg.fee_treasury_script.as_slice()
    {
        return Err("WRONG_FEE_CHANGE".into());
    }
    let sighashes = inputs(secp, cfg, tx, p.prevouts, p.signed, &p.mint)?;
    Ok(Approved {
        txid: tx.compute_txid().to_string(),
        sighashes,
        fee_sats: fee(tx, p.prevouts, cfg)?,
        units: 0,
    })
}

/// BIP340 check of a co-signer signature (the canister checks its own).
pub fn verify<C: Verification>(secp: &Secp256k1<C>, key: &Key, msg: &[u8; 32], sig: &[u8]) -> bool {
    let (Ok(k), Ok(s)) = (XOnlyPublicKey::from_slice(key), Signature::from_slice(sig)) else {
        return false;
    };
    secp.verify_schnorr(&s, &Message::from_digest(*msg), &k).is_ok()
}

#[cfg(test)]
mod tests;
