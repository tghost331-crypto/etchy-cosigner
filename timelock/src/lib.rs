//! Etchy timelock (M62): the ONLY controller of the co-signer canister.
//!
//! A code change for the co-signer is first PROPOSED (the wasm's sha256 and
//! the exact upgrade argument become public), and can only be EXECUTED once
//! `delay_seconds` (48 hours) have passed. Anyone can watch `proposals`, and
//! the admin can cancel. The co-signer can only ever be UPGRADED (its state,
//! including the record of every payout signed, is kept): never reinstalled,
//! deleted, or given another controller: this canister has no such method.
//! Once this canister has no controller of its own, these rules are final.

use candid::{CandidType, Deserialize, Principal};
use ic_cdk::{init, post_upgrade, pre_upgrade, query, update};
use ic_cdk_management_canister::{
    clear_chunk_store, install_chunked_code, start_canister, stop_canister, upload_chunk,
    CanisterIdRecord, CanisterInstallMode, ChunkHash, InstallChunkedCodeArgs, UploadChunkArgs,
};
use sha2::{Digest, Sha256};
use std::cell::RefCell;

const MIN_DELAY_SECONDS: u64 = 86_400;
const MAX_PENDING: usize = 5;
const MAX_CHUNKS: usize = 40;

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArgs {
    /// Proposes and cancels. Cannot skip the delay.
    pub admin: Principal,
    /// The co-signer canister.
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
    /// sha256 of the new wasm module (compare with a reproducible build).
    pub wasm_module_hash: Vec<u8>,
    /// The exact candid upgrade argument, and its sha256.
    pub arg: Vec<u8>,
    pub arg_sha256: Vec<u8>,
    pub note: String,
    pub proposed_at: u64,
    pub executable_at: u64,
    pub status: ProposalStatus,
    /// Uploaded chunks (their hashes); the install checks the whole wasm hash.
    pub chunks: Vec<Vec<u8>>,
    pub executed_at: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Info {
    pub admin: Principal,
    pub target: Principal,
    pub delay_seconds: u64,
    pub now: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct State {
    init: InitArgs,
    proposals: Vec<Proposal>,
    next_id: u64,
    /// One execution at a time.
    executing: bool,
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
fn require_admin() -> Result<(), String> {
    let c = ic_cdk::api::msg_caller();
    with(|s| if s.init.admin == c { Ok(()) } else { Err("NOT_ADMIN".to_string()) })
}
fn pending(s: &State, id: u64) -> Result<usize, String> {
    let i = s.proposals.iter().position(|p| p.id == id).ok_or("NO_SUCH_PROPOSAL")?;
    if s.proposals[i].status != ProposalStatus::Pending {
        return Err("NOT_PENDING".into());
    }
    Ok(i)
}

#[init]
fn init(args: InitArgs) {
    if args.delay_seconds < MIN_DELAY_SECONDS {
        ic_cdk::trap("INIT: delay below 24 hours");
    }
    if args.admin == Principal::anonymous() || args.target == Principal::anonymous() {
        ic_cdk::trap("INIT: invalid principals");
    }
    STATE.with(|s| {
        *s.borrow_mut() = Some(State { init: args, proposals: vec![], next_id: 1, executing: false })
    });
}

#[pre_upgrade]
fn pre_upgrade() {
    let s = STATE.with(|st| st.borrow_mut().take()).expect("initialized");
    ic_cdk::storage::stable_save((s,)).expect("stable save");
}

#[post_upgrade]
fn post_upgrade() {
    let (mut s,): (State,) = ic_cdk::storage::stable_restore().expect("stable restore");
    s.executing = false;
    STATE.with(|st| *st.borrow_mut() = Some(s));
}

/// Admin: publish an upgrade. It can run `delay_seconds` from now, not sooner.
#[update]
fn propose(wasm_module_hash: Vec<u8>, arg: Vec<u8>, note: String) -> Result<u64, String> {
    require_admin()?;
    if wasm_module_hash.len() != 32 {
        return Err("WASM_HASH_NOT_SHA256".into());
    }
    if note.len() > 2_000 || arg.len() > 100_000 {
        return Err("TOO_LARGE".into());
    }
    with_mut(|s| {
        if s.proposals.iter().filter(|p| p.status == ProposalStatus::Pending).count() >= MAX_PENDING {
            return Err("TOO_MANY_PENDING".to_string());
        }
        let id = s.next_id;
        s.next_id += 1;
        let t = now();
        s.proposals.push(Proposal {
            id,
            wasm_module_hash,
            arg_sha256: Sha256::digest(&arg).to_vec(),
            arg,
            note,
            proposed_at: t,
            executable_at: t + s.init.delay_seconds * 1_000_000_000,
            status: ProposalStatus::Pending,
            chunks: vec![],
            executed_at: None,
            last_error: None,
        });
        Ok(id)
    })
}

#[update]
fn cancel(id: u64) -> Result<(), String> {
    require_admin()?;
    with_mut(|s| {
        let i = pending(s, id)?;
        s.proposals[i].status = ProposalStatus::Cancelled;
        Ok(())
    })
}

/// Admin: upload the wasm in chunks (<= 1 MiB each) into the co-signer's
/// chunk store. The chunks cannot change what runs: the install checks the
/// sha256 of the whole module against the published hash.
#[update]
async fn upload(id: u64, chunk: Vec<u8>) -> Result<Vec<u8>, String> {
    require_admin()?;
    let target = with(|s| {
        let i = pending(s, id)?;
        if s.proposals[i].chunks.len() >= MAX_CHUNKS {
            return Err("TOO_MANY_CHUNKS".to_string());
        }
        Ok(s.init.target)
    })?;
    let r = upload_chunk(&UploadChunkArgs { canister_id: target, chunk })
        .await
        .map_err(|e| format!("UPLOAD: {e:?}"))?;
    with_mut(|s| {
        let i = pending(s, id)?;
        s.proposals[i].chunks.push(r.hash.clone());
        Ok(r.hash)
    })
}

/// Anyone, once the delay has passed: stop, upgrade, start the co-signer.
#[update]
async fn execute(id: u64) -> Result<(), String> {
    let (target, p) = with_mut(|s| {
        let i = pending(s, id)?;
        if now() < s.proposals[i].executable_at {
            return Err("TOO_EARLY".to_string());
        }
        if s.executing {
            return Err("EXECUTION_IN_PROGRESS".to_string());
        }
        s.executing = true;
        Ok((s.init.target, s.proposals[i].clone()))
    })?;
    let result = run(target, &p).await;
    with_mut(|s| {
        s.executing = false;
        if let Ok(i) = pending(s, id) {
            match &result {
                Ok(()) => {
                    s.proposals[i].status = ProposalStatus::Executed;
                    s.proposals[i].executed_at = Some(now());
                    s.proposals[i].last_error = None;
                }
                Err(e) => s.proposals[i].last_error = Some(e.clone()),
            }
        }
    });
    if result.is_ok() {
        // Best effort: the chunks are no longer needed.
        let _ = clear_chunk_store(&CanisterIdRecord { canister_id: target }).await;
    }
    result
}

async fn run(target: Principal, p: &Proposal) -> Result<(), String> {
    if p.chunks.is_empty() {
        return Err("NO_CHUNKS".into());
    }
    let rec = CanisterIdRecord { canister_id: target };
    stop_canister(&rec).await.map_err(|e| format!("STOP: {e:?}"))?;
    let installed = install_chunked_code(&InstallChunkedCodeArgs {
        mode: CanisterInstallMode::Upgrade(None),
        target_canister: target,
        store_canister: None,
        chunk_hashes_list: p.chunks.iter().map(|h| ChunkHash { hash: h.clone() }).collect(),
        wasm_module_hash: p.wasm_module_hash.clone(),
        arg: p.arg.clone(),
    })
    .await
    .map_err(|e| format!("INSTALL: {e:?}"));
    // Always start it again (also when the install failed: old code keeps running).
    let started = start_canister(&rec).await.map_err(|e| format!("START: {e:?}"));
    installed?;
    started
}

#[query]
fn proposals() -> Vec<Proposal> {
    with(|s| s.proposals.clone())
}

#[query]
fn info() -> Info {
    with(|s| Info {
        admin: s.init.admin,
        target: s.init.target,
        delay_seconds: s.init.delay_seconds,
        now: now(),
    })
}

ic_cdk::export_candid!();
