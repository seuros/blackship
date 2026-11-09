//! Releases: the userlands containers are cloned from, whether
//! bootstrapped from FreeBSD's mirrors or committed from a container.

use crate::error::{Error, Result};
use crate::host::{Host, Layout};
use crate::manifest::validate_name;
use crate::network::store::FileLock;
use crate::provision::Provisioner;
use crate::zfs::ZfsManager;
use std::path::PathBuf;

/// A release on this host, ready to create containers from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// Release name, e.g. `16.0-CURRENT`, or the name an image was committed as.
    pub name: String,
    /// Where the userland lives.
    pub path: PathBuf,
    /// Backing dataset, on ZFS hosts.
    pub dataset: Option<String>,
    /// Whether containers clone it (`@pristine` exists) rather than copy it.
    pub cloneable: bool,
}

/// What to bootstrap, and how. FreeBSD 16+ always uses pkgbase; older
/// releases fetch MANIFEST-checked `base.txz` unless told otherwise.
///
/// ```
/// use blackship::Bootstrap;
///
/// let plan = Bootstrap::release("15.1-RELEASE").archives(["base", "lib32"]);
/// # let _ = plan;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrap {
    release: String,
    force: bool,
    archives: Option<Vec<String>>,
    pkgbase: bool,
}

impl Bootstrap {
    /// Bootstrap `release`, e.g. `15.1-RELEASE` or `16.0-CURRENT`.
    pub fn release(release: impl Into<String>) -> Self {
        Self {
            release: release.into(),
            force: false,
            archives: None,
            pkgbase: false,
        }
    }

    /// Extract again even when the release is already there.
    #[must_use]
    pub const fn force(mut self) -> Self {
        self.force = true;
        self
    }

    /// Distribution sets to fetch instead of the host's default (`base`).
    #[must_use]
    pub fn archives<I, S>(mut self, archives: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.archives = Some(archives.into_iter().map(Into::into).collect());
        self
    }

    /// Use pkgbase even where distribution sets still exist.
    #[must_use]
    pub const fn pkgbase(mut self) -> Self {
        self.pkgbase = true;
        self
    }

    fn uses_pkgbase(&self) -> bool {
        self.pkgbase
            || crate::sys::OsVersion::parse(&self.release).is_ok_and(|v| v.requires_pkgbase())
    }
}

impl Host {
    /// Every release on this host, sorted by name.
    ///
    /// # Errors
    ///
    /// An unsupported arch, an invalid name, or an unreadable releases directory.
    pub fn releases(&self) -> Result<Vec<Release>> {
        let layout = self.layout();
        Ok(provisioner(layout, None)?
            .list_releases()?
            .into_iter()
            .map(|r| describe(layout, r.name, r.path))
            .collect())
    }

    /// The named release, if it is bootstrapped (or committed) here.
    ///
    /// # Errors
    ///
    /// An unsupported arch, an invalid name, or an unreadable releases directory.
    pub fn release(&self, name: &str) -> Result<Option<Release>> {
        let layout = self.layout();
        let provisioner = provisioner(layout, None)?;
        if !provisioner.is_bootstrapped(name)? {
            return Ok(None);
        }
        Ok(Some(describe(
            layout,
            name.to_string(),
            provisioner.release_path(name)?,
        )))
    }

    /// Whether the named release exists here.
    ///
    /// # Errors
    ///
    /// As [`Host::release`].
    pub fn has_release(&self, name: &str) -> Result<bool> {
        Ok(self.release(name)?.is_some())
    }

    /// Fetch and extract a release; on ZFS it gets its own `@pristine` dataset.
    ///
    /// # Errors
    ///
    /// Not root, an invalid or existing name, or a failed fetch, extract or ZFS step.
    pub fn bootstrap(&self, plan: &Bootstrap) -> Result<Release> {
        Error::require_root("bootstrapping a release")?;
        let layout = self.layout();
        let release = plan.release.as_str();
        validate_name("release", release)?;
        let _lock = bootstrap_lock(layout, release)?;

        let provisioner = provisioner(layout, plan.archives.clone())?;
        let release_path = provisioner.release_path(release)?;

        let zfs = layout.zfs();
        let mut dataset_backed = false;
        if let Some(zfs) = &zfs {
            if zfs.release_dataset_exists(release)? {
                dataset_backed = true;
            } else if !release_path.exists() {
                zfs.create_release_dataset(release, &release_path)?;
                dataset_backed = true;
            } else if plan.force {
                // Legacy plain-dir release: replace it with a clone-ready dataset.
                crate::sys::remove_tree_with_flags(&release_path).map_err(|e| {
                    Error::Zfs(format!(
                        "Failed to remove legacy release dir '{}': {}",
                        release_path.display(),
                        e
                    ))
                })?;
                zfs.create_release_dataset(release, &release_path)?;
                dataset_backed = true;
            }
        }

        if plan.uses_pkgbase() {
            provisioner.bootstrap_pkgbase(release, plan.force)?;
        } else {
            provisioner.bootstrap(release, plan.force)?;
        }

        if dataset_backed && let Some(zfs) = &zfs {
            zfs.snapshot_release_pristine(release)?;
        }
        Ok(describe(layout, release.to_string(), release_path))
    }

    /// The named release, bootstrapping it first when missing. Concurrency-safe.
    ///
    /// # Errors
    ///
    /// As [`Host::bootstrap`].
    pub fn ensure_release(&self, name: &str) -> Result<Release> {
        if let Some(release) = self.release(name)? {
            return Ok(release);
        }
        match self.bootstrap(&Bootstrap::release(name)) {
            Err(Error::ReleaseAlreadyExists(_)) => self
                .release(name)?
                .ok_or_else(|| Error::ReleaseNotFound(name.to_string())),
            other => other,
        }
    }

    /// Delete a release. Idempotent; refused while containers or images clone it.
    ///
    /// # Errors
    ///
    /// Not root, an invalid name, dependents on ZFS, or a failed removal.
    pub fn remove_release(&self, name: &str) -> Result<()> {
        Error::require_root("removing a release")?;
        validate_name("release", name)?;
        let layout = self.layout();
        let path = layout.releases_dir().join(name);
        if let Some(zfs) = layout.zfs()
            && zfs.release_dataset_exists(name)?
        {
            zfs.destroy_dataset_without_dependents(&zfs.release_dataset(name))?;
            let _ = std::fs::remove_dir(&path); // empty mountpoint, harmless if it lingers
            return Ok(());
        }
        if path.exists() {
            crate::blueprint::context::reject_symlink_ancestors(layout.data_dir(), &path)?;
            crate::sys::remove_tree_with_flags(&path)?;
        }
        Ok(())
    }
}

fn provisioner(layout: &Layout, archives: Option<Vec<String>>) -> Result<Provisioner> {
    let config = &layout.config().config;
    Provisioner::new(
        config.mirror_url.clone(),
        config.releases_dir.clone(),
        config.cache_dir.clone(),
        archives.unwrap_or_else(|| config.bootstrap_archives.clone()),
        config.retry.clone(),
    )
}

/// One bootstrap per release at a time, across threads and processes.
fn bootstrap_lock(layout: &Layout, release: &str) -> Result<FileLock> {
    let path = layout
        .config()
        .config
        .cache_dir
        .join("locks")
        .join(format!("bootstrap-{release}.lock"));
    FileLock::acquire(&path)
}

fn describe(layout: &Layout, name: String, path: PathBuf) -> Release {
    let zfs = layout.zfs();
    let dataset = zfs
        .as_ref()
        .filter(|zfs| zfs.release_dataset_exists(&name).unwrap_or(false))
        .map(|zfs| zfs.release_dataset(&name));
    let cloneable = zfs
        .as_ref()
        .is_some_and(|zfs| zfs.release_is_cloneable(&name));
    Release {
        name,
        path,
        dataset,
        cloneable,
    }
}

/// Freeze `dataset` into the release `release`.
pub fn commit_dataset(
    layout: &Layout,
    zfs: &ZfsManager,
    dataset: &str,
    release: &str,
) -> Result<Release> {
    validate_name("release", release)?;
    let release_path = layout.releases_dir().join(release);
    if release_path.exists() {
        return Err(Error::ReleaseAlreadyExists(release.to_string()));
    }
    zfs.commit_dataset_to_release(dataset, release, &release_path)?;
    Ok(describe(layout, release.to_string(), release_path))
}

#[cfg(test)]
mod tests;
