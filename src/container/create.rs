//! Building a container: claim, provision, mount, network, jail, limits.

use super::registry::{self, Record};
use super::{Container, ContainerSpec, Network, teardown, validate_container_name};
use crate::error::{Error, Result};
use crate::host::Layout;
use crate::manifest::validate_name;
use crate::network;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

pub fn create(layout: &Arc<Layout>, spec: &ContainerSpec) -> Result<Container> {
    Error::require_root("creating a container")?;
    validate(spec)?;

    let name = spec.name();
    let release_path = layout.releases_dir().join(spec.release());
    if !release_path.join("bin").exists() {
        return Err(Error::ReleaseNotFound(spec.release().to_string()));
    }
    if crate::jail::jail_getid(name).is_ok() {
        return Err(Error::JailExists(name.to_string()));
    }

    let root = layout.container_root(name);
    crate::blueprint::context::reject_symlink_ancestors(layout.data_dir(), &root)?;

    let zfs = layout.zfs();
    let dataset = zfs
        .as_ref()
        .filter(|zfs| zfs.release_is_cloneable(spec.release()))
        .map(|zfs| zfs.container_dataset(name));

    registry::claim(
        layout,
        name,
        &Record {
            release: spec.release().to_string(),
            root: root.clone(),
            dataset: dataset.clone(),
            owner_pid: Some(std::process::id()),
            labels: spec.labels.clone(),
        },
    )?;

    // Leftovers predating the claim are not ours: refuse rather than clobber.
    let occupied = std::fs::read_dir(&root).is_ok_and(|mut entries| entries.next().is_some());
    let dataset_taken = match (&zfs, &dataset) {
        (Some(zfs), Some(ds)) => zfs.dataset_exists(ds)?,
        _ => false,
    };
    if occupied || dataset_taken {
        // Rollback; keep the original error.
        let _ = registry::remove(layout, name);
        return Err(Error::JailExists(name.to_string()));
    }

    match build(layout, spec, &release_path, &root, dataset.as_deref()) {
        Ok(jid) => Ok(Container {
            layout: Arc::clone(layout),
            name: name.to_string(),
            jid,
            root,
            dataset,
            destroy_on_drop: true,
        }),
        Err(e) => {
            // Rollback; keep the original error.
            let _ = teardown::destroy(layout, name);
            Err(e)
        }
    }
}

fn validate(spec: &ContainerSpec) -> Result<()> {
    validate_container_name(spec.name())?;
    validate_name("release", spec.release())?;
    if let Some(hostname) = &spec.hostname
        && (hostname.is_empty()
            || !hostname
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.'))
    {
        return Err(Error::InvalidArgument(format!(
            "hostname '{hostname}' must be letters, digits, '-' and '.'"
        )));
    }
    for mount in &spec.mounts {
        if !mount.host.is_absolute() || !mount.host.is_dir() {
            return Err(Error::InvalidArgument(format!(
                "mount source '{}' must be an existing absolute directory",
                mount.host.display()
            )));
        }
        let clean = mount
            .jail
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)));
        if !mount.jail.is_absolute() || !clean || mount.jail == Path::new("/") {
            return Err(Error::InvalidArgument(format!(
                "mount target '{}' must be an absolute path below / with no '..'",
                mount.jail.display()
            )));
        }
    }
    for param in &spec.params {
        if param.is_empty() || param.starts_with('-') {
            return Err(Error::InvalidArgument(format!(
                "jail parameter '{param}' is not a jail(8) parameter"
            )));
        }
    }
    Ok(())
}

/// Everything after the claim; returns the new jail id.
fn build(
    layout: &Layout,
    spec: &ContainerSpec,
    release_path: &Path,
    root: &Path,
    dataset: Option<&str>,
) -> Result<i32> {
    match (dataset, layout.zfs()) {
        (Some(dataset), Some(zfs)) => zfs.clone_release_into(spec.release(), dataset, root)?,
        _ => copy_release(layout, release_path, root)?,
    }

    if spec.network == Network::Inherit {
        // Sharing the host's addresses is only useful with its resolver.
        let resolv = Path::new("/etc/resolv.conf");
        if resolv.exists() {
            std::fs::copy(resolv, root.join("etc/resolv.conf"))?;
        }
    }

    for mount in &spec.mounts {
        mount_nullfs(root, &mount.host, &mount.jail, mount.writable)?;
    }

    let vnet = match &spec.network {
        Network::Vnet(network_name) => Some(setup_vnet(layout, spec.name(), network_name)?),
        _ => None,
    };

    start_jail(spec, root)?;
    let jid = crate::jail::jail_getid(spec.name())?;

    if let Some(vnet) = &vnet {
        vnet.attach_to_jail(jid)?;
    }

    let resources = spec.limits.resources();
    if resources.has_rctl_rules() {
        crate::rctl::apply_limits(spec.name(), resources)?;
    }
    if let Some(cpus) = &resources.cpuset {
        crate::rctl::apply_cpuset(jid, cpus)?;
    }
    Ok(jid)
}

/// Full copy of the release for non-ZFS hosts, after a free-space check.
fn copy_release(layout: &Layout, release_path: &Path, root: &Path) -> Result<()> {
    if let Some(needed) = dir_size(release_path) {
        let free = free_space(layout.data_dir()).unwrap_or(u64::MAX);
        if free < needed + needed / 10 {
            return Err(Error::JailCreationFailed(format!(
                "Not enough space to copy release: need ~{} MiB, {} MiB free on {}. \
                 Enable ZFS for copy-on-write clones.",
                needed / 1_048_576,
                free / 1_048_576,
                layout.data_dir().display()
            )));
        }
    }
    std::fs::create_dir_all(root)?;
    let mut source = release_path.as_os_str().to_owned();
    source.push("/.");
    let output = Command::new("/bin/cp")
        .arg("-a")
        .arg(&source)
        .arg(root)
        .output()?;
    if !output.status.success() {
        return Err(Error::JailCreationFailed(format!(
            "Failed to copy release: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Total bytes used by a directory tree (best effort).
fn dir_size(path: &Path) -> Option<u64> {
    let output = Command::new("/usr/bin/du")
        .args(["-sk"])
        .arg(path)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let kib: u64 = text.split_whitespace().next()?.parse().ok()?;
    Some(kib * 1024)
}

/// Free bytes on the filesystem holding `path`.
fn free_space(path: &Path) -> Option<u64> {
    let stat = nix::sys::statfs::statfs(path).ok()?;
    // f_bavail is signed on FreeBSD (negative when root eats the reserve).
    u64::try_from(stat.blocks_available())
        .ok()
        .map(|blocks| blocks * stat.block_size())
}

/// nullfs-mount `host` at `jail` inside `root`, creating the target.
fn mount_nullfs(root: &Path, host: &Path, jail: &Path, writable: bool) -> Result<()> {
    let target = root.join(jail.strip_prefix("/").unwrap_or(jail));
    crate::blueprint::context::reject_symlink_ancestors(root, &target)?;
    std::fs::create_dir_all(&target)?;
    let canonical_root = root.canonicalize()?;
    let canonical_target: PathBuf = target.canonicalize()?;
    if !canonical_target.starts_with(&canonical_root) {
        return Err(Error::InvalidArgument(format!(
            "mount target '{}' escapes the container root",
            jail.display()
        )));
    }
    let output = Command::new("/sbin/mount_nullfs")
        .args(["-o", if writable { "rw" } else { "ro" }])
        .arg(host)
        .arg(&canonical_target)
        .output()?;
    if !output.status.success() {
        return Err(Error::JailCreationFailed(format!(
            "mount_nullfs {} {}: {}",
            host.display(),
            canonical_target.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Lease an address on `network_name` and build the VNET interface pair.
fn setup_vnet(layout: &Layout, name: &str, network_name: &str) -> Result<network::VnetSetup> {
    let config = layout.state_config();
    let lease_store = network::NetworkLeaseStore::from_config(config);
    let (runtime_networks, mut allocator, _) = network::build_runtime_allocator(config)?;
    let runtime_network = runtime_networks
        .get(network_name)
        .cloned()
        .ok_or_else(|| Error::NetworkNotFound(network_name.to_string()))?;
    let bridge_name = runtime_network.bridge.clone().ok_or_else(|| {
        Error::Network(format!(
            "Network '{network_name}' exists but has no host bridge. Create it with 'blackship network create {network_name} ...'"
        ))
    })?;
    let ip = network::allocate_and_record(&mut allocator, &lease_store, network_name, name)?;

    let backend = match runtime_network.backend.as_str() {
        "netgraph" => network::vnet::NetworkBackend::Netgraph,
        _ => network::vnet::NetworkBackend::Epair,
    };
    let vnet_config = network::VnetConfig::new(
        bridge_name,
        format!("{}/{}", ip, runtime_network.subnet.prefix_len()),
        runtime_network.gateway,
    )
    .with_backend(backend);
    let setup = network::VnetSetup::create(name, vnet_config)?;
    let state_record = setup.state_record(name, Some(network_name));
    if let Err(e) = network::VnetStateStore::from_config(config).save(&state_record) {
        // Not recorded yet, so the teardown would not find it.
        let _ = setup.cleanup();
        return Err(e);
    }
    Ok(setup)
}

/// The jail(8) parameters for `spec` rooted at `root`.
fn jail_params(spec: &ContainerSpec, root: &Path) -> Vec<String> {
    let mut params = vec![
        format!("name={}", spec.name()),
        format!("path={}", root.display()),
        format!(
            "host.hostname={}",
            spec.hostname.as_deref().unwrap_or(&spec.name)
        ),
        // The handle, not a process, decides when the jail ends.
        "persist".to_string(),
        "mount.devfs".to_string(),
    ];
    match &spec.network {
        Network::None => {
            params.push("ip4=disable".to_string());
            params.push("ip6=disable".to_string());
        }
        Network::Inherit => {
            params.push("ip4=inherit".to_string());
            params.push("ip6=inherit".to_string());
        }
        Network::Vnet(_) => params.push("vnet".to_string()),
    }
    if spec.raw_sockets {
        params.push("allow.raw_sockets".to_string());
    }
    if spec.boot {
        params.push("exec.start=/bin/sh /etc/rc".to_string());
    }
    params.extend(spec.params.iter().cloned());
    params
}

fn start_jail(spec: &ContainerSpec, root: &Path) -> Result<()> {
    let output = Command::new("/usr/sbin/jail")
        .arg("-c")
        .args(jail_params(spec, root))
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::JailCreationFailed(format!(
            "jail -c {}: {}",
            spec.name(),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests;
