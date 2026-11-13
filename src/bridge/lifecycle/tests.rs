use super::*;
use crate::fault::{self, Point};
use crate::network::store::NetworkLeaseStore;
use crate::scope::ScopeStore;
use crate::zfs::ZfsManager;

const NETWORK: &str = "rgnet";

struct Env {
    config: crate::manifest::BlackshipConfig,
    full_name: String,
}

fn env(extra: &str) -> Option<Env> {
    if !nix::unistd::geteuid().is_root() {
        return None;
    }
    let data_dir = std::env::var("BLACKSHIP_E2E_DATA_DIR").ok()?;
    let release = std::env::var("BLACKSHIP_E2E_RELEASE").ok()?;
    let (pool, dataset) = std::env::var("BLACKSHIP_E2E_ZFS")
        .ok()?
        .split_once('/')
        .map(|(p, d)| (p.to_string(), d.to_string()))?;
    let project = format!("rg{}", std::process::id());
    let manifest = format!(
        r#"
[config]
project = "{project}"
data_dir = "{data_dir}"
releases_dir = "{data_dir}/releases"
cache_dir = "{data_dir}/cache"
zfs_enabled = true
zpool = "{pool}"
dataset = "{dataset}"

[[networks]]
name = "{NETWORK}"
subnet = "10.88.0.0/24"
gateway = "10.88.0.1"

[[jails]]
name = "web"
release = "{release}"
init = false
{extra}
"#
    );
    Some(Env {
        config: toml::from_str(&manifest).ok()?,
        full_name: format!("{project}-web"),
    })
}

fn leased() -> &'static str {
    "[jails.network]\nnetworks = [\"rgnet\"]"
}

fn bridge(env: &Env) -> Bridge {
    Bridge::open(env.config.clone(), false).unwrap()
}

fn zfs(env: &Env) -> ZfsManager {
    let c = &env.config.config;
    ZfsManager::new(
        c.zpool.as_deref().unwrap(),
        &c.dataset,
        c.data_dir.join("jails"),
    )
}

fn leaks(env: &Env) -> Vec<String> {
    let mut found = Vec::new();
    if jail_getid(&env.full_name).is_ok() {
        found.push("jail".to_string());
    }
    if zfs(env).jail_dataset_exists(&env.full_name).unwrap() {
        found.push("dataset".to_string());
    }
    let leases = NetworkLeaseStore::from_config(Some(&env.config));
    if leases
        .list(NETWORK)
        .unwrap()
        .iter()
        .any(|lease| lease.owner == env.full_name)
    {
        found.push("lease".to_string());
    }
    let scopes = ScopeStore::from_config(Some(&env.config));
    if scopes
        .get(&env.full_name)
        .unwrap()
        .is_some_and(|scope| scope.holds_resources())
    {
        found.push("scope".to_string());
    }
    found
}

fn scrub(env: &Env) {
    if let Ok(jid) = jail_getid(&env.full_name) {
        let _ = jail_remove(jid);
    }
    let _ = zfs(env).destroy_jail_dataset(&env.full_name);
    let _ = NetworkLeaseStore::from_config(Some(&env.config)).release_owner(&env.full_name);
    let _ = ScopeStore::from_config(Some(&env.config)).delete(&env.full_name);
}

fn failed_start_leaks_nothing(extra: &str, point: Point) {
    let Some(env) = env(extra) else {
        return;
    };
    let mut bridge = bridge(&env);
    fault::arm(point);
    let outcome = bridge.up(Some("web"));
    fault::disarm();
    let found = leaks(&env);
    scrub(&env);
    assert!(outcome.is_err(), "{point:?} must fail the start");
    assert!(found.is_empty(), "{point:?} leaked {found:?}");
}

#[test]
#[ignore = "needs root, ZFS and a bootstrapped release"]
fn fault_after_zfs_releases_the_dataset() {
    failed_start_leaks_nothing("", Point::AfterZfs);
}

#[test]
#[ignore = "needs root, ZFS and a bootstrapped release"]
fn fault_after_lease_releases_lease_and_dataset() {
    failed_start_leaks_nothing(leased(), Point::AfterLease);
}

#[test]
#[ignore = "needs root, ZFS and a bootstrapped release"]
fn fault_after_jail_create_removes_the_jail() {
    failed_start_leaks_nothing(leased(), Point::AfterJailCreate);
}

#[test]
#[ignore = "needs root, ZFS and a bootstrapped release"]
fn fault_before_rctl_removes_the_jail() {
    failed_start_leaks_nothing("[jails.resources]\nmemory = \"64m\"", Point::BeforeRctl);
}
