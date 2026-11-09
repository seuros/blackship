//! The host a library consumer drives: where releases, containers and
//! their state live, and which ZFS dataset backs them.

use crate::error::Result;
use crate::manifest::{self, BlackshipConfig};
use crate::zfs::ZfsManager;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A FreeBSD host as Blackship sees it: a cheap, `Send + Sync` description
/// that touches nothing on disk until used.
///
/// ```no_run
/// use blackship::Host;
///
/// let host = Host::new("/var/db/kim/blackship").with_zfs("zroot", "kim/blackship");
/// assert!(host.uses_zfs());
/// ```
#[derive(Debug, Clone)]
pub struct Host {
    layout: Arc<Layout>,
}

impl Host {
    /// A host keeping roots, releases, downloads and state under `data_dir`.
    /// Without [`with_zfs`](Self::with_zfs) every container is a full copy.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        let mut config = BlackshipConfig::default();
        config.config.releases_dir = data_dir.join("releases");
        config.config.cache_dir = data_dir.join("cache");
        config.config.data_dir = data_dir;
        Self::from_layout(Layout {
            config,
            scoped_state: true,
        })
    }

    /// The host described by a `blackship.toml`, or defaults when it is missing.
    ///
    /// # Errors
    ///
    /// The manifest exists but cannot be read, parsed or validated.
    pub fn from_manifest(path: &Path) -> Result<Self> {
        Ok(Self::from_config(Some(manifest::load_or_default(path)?)))
    }

    /// Back releases and containers with datasets under `pool/dataset`;
    /// containers become clones of a `@pristine` release snapshot.
    #[must_use]
    pub fn with_zfs(mut self, pool: impl Into<String>, dataset: impl Into<String>) -> Self {
        let config = &mut self.layout_mut().config.config;
        config.zfs_enabled = true;
        config.zpool = Some(pool.into());
        config.dataset = dataset.into();
        self
    }

    /// Keep releases somewhere other than `data_dir/releases`.
    #[must_use]
    pub fn with_releases_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.layout_mut().config.config.releases_dir = dir.into();
        self
    }

    /// Keep downloads somewhere other than `data_dir/cache`.
    #[must_use]
    pub fn with_cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.layout_mut().config.config.cache_dir = dir.into();
        self
    }

    /// Fetch distribution sets from another FreeBSD mirror.
    #[must_use]
    pub fn with_mirror(mut self, url: impl Into<String>) -> Self {
        self.layout_mut().config.config.mirror_url = url.into();
        self
    }

    /// Where container roots and state live.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        self.layout.data_dir()
    }

    /// Where releases live.
    #[must_use]
    pub fn releases_dir(&self) -> &Path {
        self.layout.releases_dir()
    }

    /// Whether releases and containers are ZFS datasets.
    #[must_use]
    pub fn uses_zfs(&self) -> bool {
        self.layout.zfs().is_some()
    }

    /// The CLI's view: a loaded manifest, or none at all.
    pub(crate) fn from_config(config: Option<BlackshipConfig>) -> Self {
        let scoped_state = config.is_some();
        Self::from_layout(Layout {
            config: config.unwrap_or_default(),
            scoped_state,
        })
    }

    pub(crate) const fn layout(&self) -> &Arc<Layout> {
        &self.layout
    }

    fn from_layout(layout: Layout) -> Self {
        Self {
            layout: Arc::new(layout),
        }
    }

    fn layout_mut(&mut self) -> &mut Layout {
        Arc::make_mut(&mut self.layout)
    }
}

/// Paths and datasets, resolved once per host.
#[derive(Debug, Clone)]
pub struct Layout {
    config: BlackshipConfig,
    /// Whether the network stores read this config or the CLI's default.
    scoped_state: bool,
}

impl Layout {
    pub(crate) const fn config(&self) -> &BlackshipConfig {
        &self.config
    }

    /// The config handed to state stores (`NetworkLeaseStore::from_config` and friends).
    pub(crate) fn state_config(&self) -> Option<&BlackshipConfig> {
        self.scoped_state.then_some(&self.config)
    }

    pub(crate) fn data_dir(&self) -> &Path {
        &self.config.config.data_dir
    }

    pub(crate) fn releases_dir(&self) -> &Path {
        &self.config.config.releases_dir
    }

    /// Parent of every ephemeral container root.
    pub(crate) fn containers_dir(&self) -> PathBuf {
        self.data_dir().join("containers")
    }

    /// Where a container's root lives when it has no record saying otherwise.
    pub(crate) fn container_root(&self, name: &str) -> PathBuf {
        self.containers_dir().join(name)
    }

    /// Per-container ownership records (see `container::registry`).
    pub(crate) fn registry_dir(&self) -> PathBuf {
        self.data_dir().join("container-state")
    }

    /// The dataset manager, when ZFS is enabled and has a pool.
    pub(crate) fn zfs(&self) -> Option<ZfsManager> {
        let config = &self.config.config;
        if !config.zfs_enabled {
            return None;
        }
        config
            .zpool
            .as_ref()
            .map(|pool| ZfsManager::new(pool, &config.dataset, config.jails_dir()))
    }
}

#[cfg(test)]
mod tests;
