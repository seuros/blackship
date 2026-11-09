//! Ephemeral containers: jails cloned from a release, driven through a
//! handle, and torn down without leaving anything behind.
//!
//! ```no_run
//! use blackship::{ContainerSpec, Exec, Host, Network};
//! use std::time::Duration;
//!
//! # fn main() -> blackship::Result<()> {
//! let host = Host::new("/var/db/kim/blackship").with_zfs("zroot", "kim/blackship");
//! let ci = host.create(
//!     &ContainerSpec::new("kim-42", "16.0-CURRENT")
//!         .hostname("ci")
//!         .network(Network::Inherit),
//! )?;
//! let run = ci.exec(Exec::shell("uname -a").timeout(Duration::from_secs(30)))?;
//! assert!(run.exit.success());
//! ci.destroy()?;
//! # Ok(())
//! # }
//! ```

mod copy;
mod create;
mod exec;
mod registry;
mod teardown;

pub use exec::{Exec, ExecOutput, Exit, Stream};
pub use registry::{ContainerInfo, Selector};

#[cfg(feature = "cli")]
pub use copy::{JailSide as CopyJailSide, Side as CopySide, transfer as transfer_between};
use copy::{JailSide, transfer};
#[cfg(feature = "cli")]
pub use teardown::{network_cleanup, unmount_jail_filesystems};

use crate::error::{Error, Result};
use crate::host::{Host, Layout};
use crate::manifest::validate_name;
use crate::rctl::ResourceConfig;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// How a container reaches the network.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Network {
    /// No network at all (`ip4=disable`, `ip6=disable`).
    #[default]
    None,
    /// Share the host's addresses and its `/etc/resolv.conf`.
    Inherit,
    /// A private VNET stack on a named Blackship network, with a leased
    /// address and the host's `/etc/resolv.conf` minus the nameservers only
    /// the host can reach (loopback, link-local with a zone).
    Vnet(String),
}

impl Network {
    /// A VNET stack on the named network.
    pub fn vnet(network: impl Into<String>) -> Self {
        Self::Vnet(network.into())
    }
}

/// A host directory exposed inside the container through nullfs.
///
/// Read-write mounts are `nosuid` unless [`allow_setuid`](Self::allow_setuid)
/// says otherwise: whatever the container writes there must not become a
/// setuid program inside it. `nosuid` is a property of this mount only; the
/// same files reached through the host path are not covered, so a host
/// directory other users can reach still wants a nosuid filesystem.
///
/// ```
/// use blackship::Mount;
///
/// let work = Mount::read_write("/var/db/kim/jobs/42", "/work").noexec();
/// assert!(work.is_nosuid() && work.is_noexec());
/// assert!(!Mount::read_write("/srv/tools", "/tools").allow_setuid().is_nosuid());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    host: PathBuf,
    jail: PathBuf,
    writable: bool,
    nosuid: bool,
    noexec: bool,
}

impl Mount {
    /// Expose `host` at absolute path `jail` inside the container, read-only.
    pub fn read_only(host: impl Into<PathBuf>, jail: impl Into<PathBuf>) -> Self {
        Self {
            host: host.into(),
            jail: jail.into(),
            writable: false,
            nosuid: false,
            noexec: false,
        }
    }

    /// Expose `host` at `jail`, writable from inside the container and `nosuid`.
    pub fn read_write(host: impl Into<PathBuf>, jail: impl Into<PathBuf>) -> Self {
        Self {
            writable: true,
            nosuid: true,
            ..Self::read_only(host, jail)
        }
    }

    /// Ignore setuid and setgid bits on files reached through this mount.
    #[must_use]
    pub const fn nosuid(mut self) -> Self {
        self.nosuid = true;
        self
    }

    /// Honour setuid and setgid bits, opting a read-write mount out of its
    /// `nosuid` default.
    #[must_use]
    pub const fn allow_setuid(mut self) -> Self {
        self.nosuid = false;
        self
    }

    /// Refuse to execute anything through this mount.
    #[must_use]
    pub const fn noexec(mut self) -> Self {
        self.noexec = true;
        self
    }

    /// The host side of the mount.
    #[must_use]
    pub fn host_path(&self) -> &Path {
        &self.host
    }

    /// Where the mount appears inside the container.
    #[must_use]
    pub fn jail_path(&self) -> &Path {
        &self.jail
    }

    /// Whether the container may write through the mount.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.writable
    }

    /// Whether setuid and setgid bits are ignored.
    #[must_use]
    pub const fn is_nosuid(&self) -> bool {
        self.nosuid
    }

    /// Whether executing through the mount is refused.
    #[must_use]
    pub const fn is_noexec(&self) -> bool {
        self.noexec
    }

    /// The `mount_nullfs` options, one per `-o`: `mount_nullfs(8)` silently
    /// ignores a comma-joined list, read-only included.
    pub(crate) fn options(&self) -> Vec<&'static str> {
        let mut options = vec![if self.writable { "rw" } else { "ro" }];
        if self.nosuid {
            options.push("nosuid");
        }
        if self.noexec {
            options.push("noexec");
        }
        options
    }
}

/// Resource limits enforced by rctl(8) and cpuset(1).
///
/// Needs `kern.racct.enable=1`; without RACCT, creation fails with [`Error::Rctl`].
#[derive(Debug, Clone, Default)]
pub struct Limits {
    resources: ResourceConfig,
}

impl Limits {
    /// No limits yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resident memory cap, in rctl units: `"512m"`, `"4g"`.
    #[must_use]
    pub fn memory(mut self, amount: impl Into<String>) -> Self {
        self.resources.memory = Some(amount.into());
        self
    }

    /// Swap cap, in rctl units.
    #[must_use]
    pub fn swap(mut self, amount: impl Into<String>) -> Self {
        self.resources.swap = Some(amount.into());
        self
    }

    /// CPU cap in percent of one core: `200` is two cores' worth.
    #[must_use]
    pub fn cpu_percent(mut self, percent: u32) -> Self {
        self.resources.cpu = Some(percent.to_string());
        self
    }

    /// Process count cap.
    #[must_use]
    pub const fn max_processes(mut self, count: u32) -> Self {
        self.resources.maxproc = Some(count);
        self
    }

    /// Thread count cap.
    #[must_use]
    pub const fn max_threads(mut self, count: u32) -> Self {
        self.resources.maxthreads = Some(count);
        self
    }

    /// Open file descriptor cap.
    #[must_use]
    pub const fn open_files(mut self, count: u32) -> Self {
        self.resources.openfiles = Some(count);
        self
    }

    /// Pin the container to a CPU list: `"0-3"`, `"0,2"`.
    #[must_use]
    pub fn cpus(mut self, list: impl Into<String>) -> Self {
        self.resources.cpuset = Some(list.into());
        self
    }

    /// A raw rctl rule, `resource:action=amount`; the subject is added for you.
    #[must_use]
    pub fn rule(mut self, rule: impl Into<String>) -> Self {
        self.resources.rules.push(rule.into());
        self
    }

    /// Whether any limit is set.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }

    pub(crate) const fn resources(&self) -> &ResourceConfig {
        &self.resources
    }
}

/// Everything needed to create a container: name, release to clone, confinement.
///
/// ```
/// use blackship::{ContainerSpec, Limits, Mount, Network};
///
/// let spec = ContainerSpec::new("kim-42", "16.0-CURRENT")
///     .hostname("ci")
///     .network(Network::Inherit)
///     .limits(Limits::new().memory("4g").max_processes(512))
///     .mount(Mount::read_only("/var/cache/kim/distfiles", "/distfiles"))
///     .label("job", "42");
/// assert_eq!(spec.name(), "kim-42");
/// ```
#[derive(Debug, Clone)]
pub struct ContainerSpec {
    name: String,
    release: String,
    hostname: Option<String>,
    network: Network,
    limits: Limits,
    mounts: Vec<Mount>,
    labels: BTreeMap<String, String>,
    boot: bool,
    raw_sockets: bool,
    chflags: bool,
    nameservers: Vec<IpAddr>,
    params: Vec<String>,
}

impl ContainerSpec {
    /// A container named `name` cloned from `release`, a bootstrapped
    /// release or an image from [`Container::commit`] / [`Host::commit_image`].
    pub fn new(name: impl Into<String>, release: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            release: release.into(),
            hostname: None,
            network: Network::default(),
            limits: Limits::default(),
            mounts: Vec::new(),
            labels: BTreeMap::new(),
            boot: false,
            raw_sockets: false,
            chflags: false,
            nameservers: Vec::new(),
            params: Vec::new(),
        }
    }

    /// The hostname seen inside; defaults to the container name.
    #[must_use]
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// How the container reaches the network; [`Network::None`] by default.
    #[must_use]
    pub fn network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Resolve names through `server`; repeat for more. Replaces the
    /// `/etc/resolv.conf` the container would otherwise get from the host,
    /// and is the way out when the host resolves through a local cache
    /// (`local_unbound` on 127.0.0.1) that a VNET container cannot reach.
    #[must_use]
    pub fn nameserver(mut self, server: impl Into<IpAddr>) -> Self {
        self.nameservers.push(server.into());
        self
    }

    /// Resource limits; none by default.
    #[must_use]
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Add a nullfs mount. The jail-side directory is created when missing.
    #[must_use]
    pub fn mount(mut self, mount: Mount) -> Self {
        self.mounts.push(mount);
        self
    }

    /// Attach a label, matched by [`Selector::label`].
    #[must_use]
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Run `/etc/rc` when the container starts. Off by default.
    #[must_use]
    pub const fn boot(mut self) -> Self {
        self.boot = true;
        self
    }

    /// Allow raw sockets (ping, traceroute) inside the container.
    #[must_use]
    pub const fn allow_raw_sockets(mut self) -> Self {
        self.raw_sockets = true;
        self
    }

    /// Let root inside the container set and clear system file flags
    /// (`schg`, `sunlnk`, ...), as `allow.chflags`.
    ///
    /// Installing base packages needs it: pkgbase packages such as
    /// `FreeBSD-clibs-lib32` flag their files, and pkg refuses to install them
    /// without it. Bake images with it, not jobs: flags set on a read-write
    /// mount stay on the host files and block their removal until cleared.
    #[must_use]
    pub const fn allow_chflags(mut self) -> Self {
        self.chflags = true;
        self
    }

    /// Pass a raw jail(8) parameter, `name=value` or a bare flag like `allow.mlock`.
    #[must_use]
    pub fn jail_param(mut self, param: impl Into<String>) -> Self {
        self.params.push(param.into());
        self
    }

    /// The container (and jail) name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The release the container clones.
    #[must_use]
    pub fn release(&self) -> &str {
        &self.release
    }
}

/// A live container. Dropping a handle from [`Host::create`] destroys it;
/// [`keep`](Self::keep) and [`hand_over`](Self::hand_over) opt out,
/// [`destroy`](Self::destroy) surfaces errors.
/// Handles from [`Host::open`] are kept by default.
#[derive(Debug)]
pub struct Container {
    layout: Arc<Layout>,
    name: String,
    jid: i32,
    root: PathBuf,
    dataset: Option<String>,
    destroy_on_drop: bool,
}

impl Container {
    /// The container (and jail) name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The kernel jail id.
    #[must_use]
    pub const fn jid(&self) -> i32 {
        self.jid
    }

    /// The container's root directory on the host.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The ZFS dataset holding the root, when the host uses ZFS.
    #[must_use]
    pub fn dataset(&self) -> Option<&str> {
        self.dataset.as_deref()
    }

    /// Run a command inside the container and wait for it. A non-zero exit
    /// is not an error; a timeout kills every process in the container.
    ///
    /// # Errors
    ///
    /// Not root, an empty argv, or the command cannot be spawned in the jail.
    pub fn exec(&self, exec: Exec<'_>) -> Result<ExecOutput> {
        Error::require_root("running a command in a container")?;
        exec::run(self.jid, exec)
    }

    /// Copy a host file or directory to absolute `jail_path`, whose parent must exist.
    ///
    /// # Errors
    ///
    /// Not root, a destination escaping the root, or a failed copy.
    pub fn copy_in(&self, host_path: impl AsRef<Path>, jail_path: impl AsRef<str>) -> Result<()> {
        Error::require_root("copying into a container")?;
        transfer(
            &copy::Side::Host(host_path.as_ref()),
            &copy::Side::Jail(self.jail_side(jail_path.as_ref())),
            true,
        )
    }

    /// Copy a file or directory out of the container to the host.
    ///
    /// # Errors
    ///
    /// Not root, a source escaping the root, or a failed copy.
    pub fn copy_out(&self, jail_path: impl AsRef<str>, host_path: impl AsRef<Path>) -> Result<()> {
        Error::require_root("copying out of a container")?;
        transfer(
            &copy::Side::Jail(self.jail_side(jail_path.as_ref())),
            &copy::Side::Host(host_path.as_ref()),
            true,
        )
    }

    /// Freeze the container's filesystem into a reusable release (ZFS only).
    /// The snapshot is taken live; quiesce writers first.
    ///
    /// # Errors
    ///
    /// Not root, not on ZFS, an invalid or taken name, or a failed snapshot/clone.
    pub fn commit(&self, release: &str) -> Result<crate::Release> {
        Error::require_root("committing a container")?;
        let zfs = self.layout.zfs().ok_or(Error::ZfsNotEnabled)?;
        let dataset = self.dataset.as_deref().ok_or(Error::ZfsNotEnabled)?;
        crate::release::commit_dataset(&self.layout, &zfs, dataset, release)
    }

    /// Leave the container running past this handle; it is never an orphan.
    ///
    /// # Errors
    ///
    /// The ownership record could not be rewritten; the handle still destroys on drop.
    pub fn keep(&mut self) -> Result<()> {
        registry::disown(&self.layout, &self.name)?;
        self.destroy_on_drop = false;
        Ok(())
    }

    /// Make `pid` the container's owner and let it outlive this handle.
    ///
    /// For a short-lived creator (a privileged helper, say) working for a
    /// long-lived process: from here on the container is an orphan, and
    /// [`Host::reap_orphans`] destroys it, once `pid` is gone. Until the call
    /// the creator owns it, so a creator dying before handing over leaves an
    /// orphan rather than a container nobody knows about.
    ///
    /// # Errors
    ///
    /// `pid` is not a running process, or the ownership record could not be
    /// rewritten; either way the handle still destroys on drop.
    pub fn hand_over(&mut self, pid: u32) -> Result<()> {
        registry::hand_over(&self.layout, &self.name, pid)?;
        self.destroy_on_drop = false;
        Ok(())
    }

    /// Tear the container down. See [`Host::destroy_container`].
    ///
    /// # Errors
    ///
    /// As [`Host::destroy_container`].
    pub fn destroy(mut self) -> Result<()> {
        self.destroy_on_drop = false;
        teardown::destroy(&self.layout, &self.name)
    }

    fn jail_side(&self, path: &str) -> JailSide {
        JailSide {
            jid: Some(self.jid),
            root: self.root.clone(),
            path: path.to_string(),
        }
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        if self.destroy_on_drop {
            // Errors stay with the orphan record for `reap_orphans`.
            let _ = teardown::destroy(&self.layout, &self.name);
        }
    }
}

impl Host {
    /// Create and start a container. A failure at any step tears down
    /// whatever was built.
    ///
    /// # Errors
    ///
    /// Not root, an invalid or taken name, a missing release, or the failing step's error.
    pub fn create(&self, spec: &ContainerSpec) -> Result<Container> {
        create::create(self.layout(), spec)
    }

    /// A kept handle on a running container, possibly from another process.
    ///
    /// # Errors
    ///
    /// Not root, an invalid name, or [`Error::JailNotRunning`].
    pub fn open(&self, name: &str) -> Result<Container> {
        Error::require_root("opening a container")?;
        validate_container_name(name)?;
        let jid = crate::jail::jail_getid(name).map_err(|_| Error::JailNotRunning(name.into()))?;
        let record = registry::load(self.layout(), name);
        let root = record
            .as_ref()
            .map_or_else(|| self.layout().container_root(name), |r| r.root.clone());
        Ok(Container {
            layout: Arc::clone(self.layout()),
            name: name.to_string(),
            jid,
            root,
            dataset: record.and_then(|r| r.dataset),
            destroy_on_drop: false,
        })
    }

    /// Destroy a container by name. Idempotent: every step tolerates its
    /// resource being gone, so half-built containers clean up too.
    ///
    /// # Errors
    ///
    /// Not root, an invalid name, or [`Error::JailOperation`] listing failed steps.
    pub fn destroy_container(&self, name: &str) -> Result<()> {
        teardown::destroy(self.layout(), name)
    }

    /// Every container this host knows about: records, datasets and roots.
    ///
    /// # Errors
    ///
    /// None today; unreadable entries are skipped.
    pub fn containers(&self) -> Result<Vec<ContainerInfo>> {
        Ok(registry::list(self.layout()))
    }

    /// Containers matching `selector` whose owner (the creating process, or
    /// whoever it was [handed over](Container::hand_over) to) is gone.
    ///
    /// # Errors
    ///
    /// As [`Host::containers`].
    pub fn orphans(&self, selector: &Selector) -> Result<Vec<ContainerInfo>> {
        Ok(self
            .containers()?
            .into_iter()
            .filter(|info| info.is_orphan() && selector.matches(info))
            .collect())
    }

    /// Destroy every orphan matching `selector`; returns the destroyed names.
    ///
    /// # Errors
    ///
    /// Not root, or the first teardown failure after every orphan was tried.
    pub fn reap_orphans(&self, selector: &Selector) -> Result<Vec<String>> {
        Error::require_root("reaping orphaned containers")?;
        let mut reaped = Vec::new();
        let mut first_error = None;
        for orphan in self.orphans(selector)? {
            match self.destroy_container(&orphan.name) {
                Ok(()) => reaped.push(orphan.name),
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(reaped),
        }
    }
}

/// Validate a container name; dots are out since jail(8) reads `a.b` as a child jail.
pub fn validate_container_name(name: &str) -> Result<()> {
    validate_name("container", name)?;
    if name.contains('.') {
        return Err(Error::ConfigValidation(format!(
            "container name '{name}' must not contain '.' (jail(8) reads it as a child jail)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
