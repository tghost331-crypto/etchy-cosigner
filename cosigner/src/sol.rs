//! The subset of the SOL RPC canister interface (tghme-zyaaa-aaaar-qarca-cai)
//! the co-signer uses: `getAccountInfo` and its cycles cost. Field names follow
//! the canister's Candid exactly (sol_rpc_canister.did).
#![allow(non_snake_case, non_camel_case_types, dead_code)]

use candid::{CandidType, Deserialize, Nat, Reserved};

#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolanaCluster {
    Mainnet,
    Devnet,
    Testnet,
}

/// Only `Default` is used: the SOL RPC canister picks the providers.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum RpcSources {
    Default(SolanaCluster),
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ConsensusStrategy {
    Equality,
    Threshold { total: Option<u8>, min: u8 },
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct RpcConfig {
    pub responseSizeEstimate: Option<u64>,
    pub responseConsensus: Option<ConsensusStrategy>,
}

#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentLevel {
    processed,
    confirmed,
    finalized,
}

#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum GetAccountInfoEncoding {
    base58,
    base64,
    #[serde(rename = "base64+zstd")]
    base64_zstd,
    jsonParsed,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct DataSlice {
    pub length: u32,
    pub offset: u32,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct GetAccountInfoParams {
    pub pubkey: String,
    pub commitment: Option<CommitmentLevel>,
    pub encoding: Option<GetAccountInfoEncoding>,
    pub dataSlice: Option<DataSlice>,
    pub minContextSlot: Option<u64>,
}

#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountEncoding {
    binary,
    base58,
    base64,
    #[serde(rename = "base64+zstd")]
    base64_zstd,
    jsonParsed,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum AccountData {
    legacyBinary(String),
    json(Reserved),
    binary(String, AccountEncoding),
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct AccountInfo {
    pub lamports: u64,
    pub data: AccountData,
    pub owner: String,
    pub executable: bool,
    pub rentEpoch: u64,
    pub space: u64,
}

/// `RpcError`, keeping only the text cases (the rest is logged as a kind).
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum RpcError {
    JsonRpcError(Reserved),
    ProviderError(Reserved),
    ValidationError(String),
    HttpOutcallError(Reserved),
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum GetAccountInfoResult {
    Ok(Option<AccountInfo>),
    Err(RpcError),
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum MultiGetAccountInfoResult {
    Consistent(GetAccountInfoResult),
    Inconsistent(Vec<(Reserved, GetAccountInfoResult)>),
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum RequestCostResult {
    Ok(Nat),
    Err(RpcError),
}
