//! The timelock as the co-signer's only controller: every upgrade waits 48h
//! in public; nobody (not even the admin) can change the co-signer sooner.
use candid::{encode_args, encode_one, Principal};
use integration::*;
use sha2::{Digest, Sha256};
use std::time::Duration;

const DELAY: u64 = 48 * 3600;

fn timelock(env: &Env) -> Principal {
    let tl = env.pic.create_canister();
    env.pic.add_cycles(tl, 10_000_000_000_000);
    let init = TimelockInit { admin: admin(), target: env.cosigner, delay_seconds: DELAY };
    env.pic.install_canister(tl, wasm("timelock.wasm"), encode_one(init).unwrap(), None);
    // Hand the co-signer over: the timelock becomes its ONLY controller.
    env.pic.set_controllers(env.cosigner, None, vec![tl]).unwrap();
    tl
}
fn tl_call<T: candid::CandidType + serde::de::DeserializeOwned>(
    env: &Env,
    tl: Principal,
    sender: Principal,
    method: &str,
    arg: Vec<u8>,
) -> Result<T, String> {
    env.update::<Result<T, String>>(tl, sender, method, arg)?
}
fn propose(env: &Env, tl: Principal, wasm: &[u8], arg: &UpgradeArgs, note: &str) -> u64 {
    let hash = Sha256::digest(wasm).to_vec();
    let a = encode_one(Some(arg.clone())).unwrap();
    tl_call(env, tl, admin(), "propose", encode_args((hash, a, note.to_string())).unwrap()).unwrap()
}
fn upload_all(env: &Env, tl: Principal, id: u64, wasm: &[u8]) {
    // Two chunks at least (exercises the chunked install).
    let half = wasm.len() / 2 + 1;
    for chunk in wasm.chunks(half) {
        let h: Vec<u8> = tl_call(env, tl, admin(), "upload", encode_args((id, chunk.to_vec())).unwrap()).unwrap();
        assert_eq!(h, Sha256::digest(chunk).to_vec());
    }
}
fn proposals(env: &Env, tl: Principal) -> Vec<Proposal> {
    env.query(tl, "proposals", encode_one(()).unwrap())
}

#[test]
fn upgrades_wait_48_hours_in_public() {
    let env = Env::new();
    let c_before = env.cosigner_key(custody(&MINT));
    let tl = timelock(&env);
    let code = wasm("cosigner.wasm.gz");

    // Nobody but the timelock can touch the co-signer now.
    assert!(env.pic.upgrade_canister(env.cosigner, code.clone(), encode_one(None::<UpgradeArgs>).unwrap(), None).is_err());
    assert!(env.pic.upgrade_canister(env.cosigner, code.clone(), encode_one(None::<UpgradeArgs>).unwrap(), Some(admin())).is_err());
    assert!(env.pic.set_controllers(env.cosigner, Some(admin()), vec![admin()]).is_err());

    // Only the admin proposes.
    let hash = Sha256::digest(&code).to_vec();
    let r: Result<u64, String> = tl_call(&env, tl, stranger(), "propose", encode_args((hash.clone(), vec![0u8], "x".to_string())).unwrap());
    assert_eq!(r.unwrap_err(), "NOT_ADMIN");

    let arg = UpgradeArgs { callers: Some(vec![server(), server2()]), ..Default::default() };
    let id = propose(&env, tl, &code, &arg, "add a second Etchy server");
    upload_all(&env, tl, id, &code);
    let p = &proposals(&env, tl)[0];
    assert_eq!(p.status, ProposalStatus::Pending);
    assert_eq!(p.wasm_module_hash, hash);
    assert_eq!(p.executable_at - p.proposed_at, DELAY * 1_000_000_000);

    // Too early, for anyone (also the admin).
    let r: Result<(), String> = tl_call(&env, tl, admin(), "execute", encode_one(id).unwrap());
    assert_eq!(r.unwrap_err(), "TOO_EARLY");
    env.pic.advance_time(Duration::from_secs(DELAY - 60));
    env.pic.tick();
    let r: Result<(), String> = tl_call(&env, tl, stranger(), "execute", encode_one(id).unwrap());
    assert_eq!(r.unwrap_err(), "TOO_EARLY");

    // After 48h anyone can run it.
    env.pic.advance_time(Duration::from_secs(61));
    env.pic.tick();
    let r: Result<(), String> = tl_call(&env, tl, stranger(), "execute", encode_one(id).unwrap());
    r.unwrap();
    let st = env.status();
    assert_eq!(st.callers, vec![server(), server2()]);
    assert!(!st.paused);
    // State and keys survive the upgrade (same address for the same coin).
    assert_eq!(env.cosigner_key(custody(&MINT)), c_before);
    let ev: Vec<Event> = env.query(env.cosigner, "events", encode_one(0u64).unwrap());
    assert_eq!(ev.first().unwrap().kind, "INSTALLED");
    assert_eq!(ev.last().unwrap().kind, "UPGRADED");
    assert_eq!(proposals(&env, tl)[0].status, ProposalStatus::Executed);
    let r: Result<(), String> = tl_call(&env, tl, stranger(), "execute", encode_one(id).unwrap());
    assert_eq!(r.unwrap_err(), "NOT_PENDING");
}

#[test]
fn bad_or_cancelled_upgrades_never_run() {
    let env = Env::new();
    let tl = timelock(&env);
    let code = wasm("cosigner.wasm.gz");

    // Changing Etchy's key would strand custody: the co-signer refuses it.
    let mut s = settings();
    s.etchy_key = hex::encode(xo(0x23));
    let id = propose(&env, tl, &code, &UpgradeArgs { settings: Some(s), ..Default::default() }, "bad");
    upload_all(&env, tl, id, &code);
    env.pic.advance_time(Duration::from_secs(DELAY + 1));
    env.pic.tick();
    let r: Result<(), String> = tl_call(&env, tl, admin(), "execute", encode_one(id).unwrap());
    let e = r.unwrap_err();
    assert!(e.starts_with("INSTALL"), "{e}");
    // The old code still runs, with the old settings, and is started again.
    assert_eq!(env.status().settings, settings());
    assert!(env.addresses(vec![custody(&MINT)]).is_ok());
    assert!(proposals(&env, tl)[0].last_error.is_some());

    // A wasm other than the published hash cannot be installed.
    let id2 = propose(&env, tl, &code, &UpgradeArgs::default(), "other bytes");
    let other = wasm("timelock.wasm");
    upload_all(&env, tl, id2, &other);
    env.pic.advance_time(Duration::from_secs(DELAY + 1));
    env.pic.tick();
    let r: Result<(), String> = tl_call(&env, tl, admin(), "execute", encode_one(id2).unwrap());
    assert!(r.unwrap_err().starts_with("INSTALL"));

    // Cancelled: never runs.
    let id3 = propose(&env, tl, &code, &UpgradeArgs::default(), "cancel me");
    upload_all(&env, tl, id3, &code);
    let r: Result<(), String> = tl_call(&env, tl, stranger(), "cancel", encode_one(id3).unwrap());
    assert_eq!(r.unwrap_err(), "NOT_ADMIN");
    let r: Result<(), String> = tl_call(&env, tl, admin(), "cancel", encode_one(id3).unwrap());
    r.unwrap();
    env.pic.advance_time(Duration::from_secs(DELAY + 1));
    env.pic.tick();
    let r: Result<(), String> = tl_call(&env, tl, admin(), "execute", encode_one(id3).unwrap());
    assert_eq!(r.unwrap_err(), "NOT_PENDING");
    // A delay below 24h is refused at install.
    let bad = env.pic.create_canister();
    env.pic.add_cycles(bad, 1_000_000_000_000);
    let init = TimelockInit { admin: admin(), target: env.cosigner, delay_seconds: 3600 };
    let res = env.pic.install_canister_result(bad, wasm("timelock.wasm"), encode_one(init).unwrap(), None);
    assert!(res.is_err());
}

trait InstallResult {
    fn install_canister_result(&self, c: Principal, w: Vec<u8>, a: Vec<u8>, s: Option<Principal>) -> Result<(), String>;
}
impl InstallResult for pocket_ic::PocketIc {
    fn install_canister_result(&self, c: Principal, w: Vec<u8>, a: Vec<u8>, s: Option<Principal>) -> Result<(), String> {
        // install_canister panics on failure; reinstall-mode API returns a Result.
        self.reinstall_canister(c, w, a, s).map_err(|e| format!("{e:?}"))
    }
}
