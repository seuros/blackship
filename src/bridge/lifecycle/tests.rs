use super::*;
use crate::fault::{self, Point};
use crate::gc::{Reaper, classify};
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
    let _ = crate::audit::AuditLog::from_config(Some(&env.config)).delete(&env.full_name);
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

#[test]
#[ignore = "needs root, ZFS and a bootstrapped release"]
fn gc_reclaims_a_restarted_jail_after_the_supervisor_dies() {
    let Some(env) = env(leased()) else {
        return;
    };
    let mut first = bridge(&env);
    first.up(Some("web")).unwrap();
    first.down(Some("web")).unwrap();
    first.up(Some("web")).unwrap();
    drop(first);
    scrub_live_jail(&env);

    let reaper = Reaper::new(&env.config, false).unwrap();
    let survey = reaper.survey().unwrap();
    for orphan in classify(&survey)
        .iter()
        .filter(|orphan| orphan.jail == env.full_name)
    {
        reaper.reap(orphan, false, false).unwrap();
    }
    let found = leaks(&env);
    scrub(&env);
    assert!(found.is_empty(), "gc left {found:?}");
}

fn scrub_live_jail(env: &Env) {
    if let Ok(jid) = jail_getid(&env.full_name) {
        jail_remove(jid).unwrap();
    }
}

const BRIDGE: &str = "rgbr0";
const BYSTANDER: &str = "rgbyst0";

fn vnet_extra() -> String {
    format!("[jails.network]\nvnet = true\nnetworks = [\"{NETWORK}\"]\nbridge = \"{BRIDGE}\"")
}

fn interface_exists(name: &str) -> bool {
    crate::network::ioctl::interface_exists(name).unwrap()
}

fn destroy_if_present(name: &str) {
    if interface_exists(name) {
        crate::network::ioctl::destroy_interface(name).unwrap();
    }
}

#[test]
#[ignore = "needs root, ZFS and a bootstrapped release"]
fn gc_reclaims_the_bridge_a_failed_vnet_start_created() {
    let Some(env) = env(&vnet_extra()) else {
        return;
    };
    destroy_if_present(BRIDGE);
    destroy_if_present(BYSTANDER);
    crate::network::Bridge::create(BYSTANDER).unwrap();

    let mut bridge = bridge(&env);
    fault::arm(Point::AfterBridge);
    let outcome = bridge.up(Some("web"));
    fault::disarm();
    let leaked = interface_exists(BRIDGE);

    let reaper = Reaper::new(&env.config, false).unwrap();
    for orphan in classify(&reaper.survey().unwrap()) {
        if !orphan.requires_force {
            reaper.reap(&orphan, false, false).unwrap();
        }
    }
    let reclaimed = !interface_exists(BRIDGE);
    let bystander_kept = interface_exists(BYSTANDER);

    drop(reaper);
    scrub(&env);
    destroy_if_present(BRIDGE);
    destroy_if_present(BYSTANDER);
    assert!(outcome.is_err());
    assert!(
        leaked,
        "the failed start should strand the bridge it created"
    );
    assert!(reclaimed, "gc should reclaim the stranded bridge");
    assert!(bystander_kept, "gc must not touch an untagged bridge");
}

#[test]
#[ignore = "needs root, ZFS and a bootstrapped release"]
fn a_migration_fence_refuses_start_until_cleared() {
    let Some(env) = env("") else {
        return;
    };
    let zfs = zfs(&env);
    let mut first = bridge(&env);
    first.up(Some("web")).unwrap();
    first.down(Some("web")).unwrap();

    zfs.fence_jail_dataset(
        &env.full_name,
        "bastion/zroot/blackship/jails/web@1794000000",
    )
    .unwrap();
    let refused = bridge(&env).up(Some("web")).unwrap_err().to_string();
    let still_down = jail_getid(&env.full_name).is_err();
    zfs.clear_jail_migration_fence(&env.full_name).unwrap();
    let unfenced = zfs.jail_migration_fence(&env.full_name).is_none();
    let mut again = bridge(&env);
    let started = again.up(Some("web")).is_ok();
    let running = jail_getid(&env.full_name).is_ok();
    again.down(Some("web")).unwrap();

    scrub(&env);
    assert!(
        refused.contains("bastion/zroot/blackship/jails/web"),
        "{refused}"
    );
    assert!(refused.contains("blackship unfence"), "{refused}");
    assert!(still_down, "a fenced jail must not start");
    assert!(unfenced);
    assert!(started && running, "the jail starts once unfenced");
}
