//! TEST ONLY: a stand-in for the SOL RPC canister with the same
//! `getAccountInfo` interface. Tests set the accounts it returns.
use candid::{CandidType, Deserialize};
use ic_cdk::{query, update};
use std::cell::RefCell;
use std::collections::BTreeMap;

#[path = "../../cosigner/src/sol.rs"]
mod sol;
use sol::*;

#[derive(CandidType, Deserialize, Clone, Debug, Default)]
pub struct Seen {
    pub calls: u64,
    pub last_pubkey: String,
    pub finalized: bool,
    pub base64: bool,
    pub threshold: String,
    pub cycles: u64,
}

thread_local! {
    static ACCOUNTS: RefCell<BTreeMap<String, (String, Vec<u8>)>> = RefCell::new(BTreeMap::new());
    static MODE: RefCell<String> = RefCell::new("ok".into());
    static SEEN: RefCell<Seen> = RefCell::new(Seen::default());
}

#[update]
fn set_account(pubkey: String, owner: String, data: Vec<u8>) {
    ACCOUNTS.with(|a| a.borrow_mut().insert(pubkey, (owner, data)));
}

#[update]
fn remove_account(pubkey: String) {
    ACCOUNTS.with(|a| a.borrow_mut().remove(&pubkey));
}

/// "ok" | "inconsistent" | "error"
#[update]
fn set_mode(mode: String) {
    MODE.with(|m| *m.borrow_mut() = mode);
}

#[query]
fn seen() -> Seen {
    SEEN.with(|s| s.borrow().clone())
}

#[update(name = "getAccountInfo")]
fn get_account_info(
    _sources: RpcSources,
    config: Option<RpcConfig>,
    params: GetAccountInfoParams,
) -> MultiGetAccountInfoResult {
    let cycles = ic_cdk::api::msg_cycles_accept(1_000_000_000);
    SEEN.with(|s| {
        let mut s = s.borrow_mut();
        s.calls += 1;
        s.last_pubkey = params.pubkey.clone();
        s.finalized = params.commitment == Some(CommitmentLevel::finalized);
        s.base64 = params.encoding == Some(GetAccountInfoEncoding::base64);
        s.threshold = format!("{:?}", config.and_then(|c| c.responseConsensus));
        s.cycles = cycles as u64;
    });
    let mode = MODE.with(|m| m.borrow().clone());
    if mode == "inconsistent" {
        return MultiGetAccountInfoResult::Inconsistent(vec![]);
    }
    if mode == "error" {
        return MultiGetAccountInfoResult::Consistent(GetAccountInfoResult::Err(
            RpcError::ValidationError("mock error".into()),
        ));
    }
    let found = ACCOUNTS.with(|a| a.borrow().get(&params.pubkey).cloned());
    MultiGetAccountInfoResult::Consistent(GetAccountInfoResult::Ok(found.map(|(owner, data)| {
        use base64::Engine;
        AccountInfo {
            lamports: 1_000_000,
            space: data.len() as u64,
            data: AccountData::binary(
                base64::engine::general_purpose::STANDARD.encode(&data),
                AccountEncoding::base64,
            ),
            owner,
            executable: false,
            rentEpoch: 0,
        }
    })))
}
