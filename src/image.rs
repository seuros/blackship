//! Images: jail roots built from a Jailfile with the layer cache, and
//! committed into releases that containers clone.

use crate::blueprint::instructions::Jailfile;
use crate::blueprint::{self, BuildContext, TemplateExecutor, parse_jailfile};
use crate::error::{Error, Result};
use crate::host::Host;
use crate::release::{Bootstrap, Release};
use std::path::{Path, PathBuf};

/// A Jailfile build: file, context directory, name and build arguments.
///
/// ```
/// use blackship::Build;
///
/// let toolchain = Build::jailfile("images/rust/Jailfile")
///     .name("kim-rust")
///     .arg("RUST_VERSION", "1.99");
/// # let _ = toolchain;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Build {
    file: PathBuf,
    context: Option<PathBuf>,
    name: Option<String>,
    args: Vec<(String, String)>,
}

impl Build {
    /// Build from the Jailfile at `path`.
    pub fn jailfile(path: impl Into<PathBuf>) -> Self {
        Self {
            file: path.into(),
            context: None,
            name: None,
            args: Vec::new(),
        }
    }

    /// Directory `COPY` reads from; the Jailfile's own directory by default.
    #[must_use]
    pub fn context(mut self, dir: impl Into<PathBuf>) -> Self {
        self.context = Some(dir.into());
        self
    }

    /// Name of the built root; defaults to the Jailfile's metadata name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set an `ARG`.
    #[must_use]
    pub fn arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.args.push((key.into(), value.into()));
        self
    }
}

/// A built jail root, ready to commit into a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// The name it was built under.
    pub name: String,
    /// The root directory on the host.
    pub root: PathBuf,
    /// The release named by `FROM`, if any.
    pub base: Option<String>,
}

impl Host {
    /// Build a jail root from a Jailfile, bootstrapping `FROM` when missing.
    /// On ZFS each `RUN`/`COPY` is a cached layer.
    ///
    /// # Errors
    ///
    /// Not root, an unreadable or unnamed Jailfile, a failed bootstrap, or a failed step.
    pub fn build(&self, build: &Build) -> Result<Image> {
        Error::require_root("building an image")?;
        let jailfile = read_jailfile(&build.file)?;
        let name = build
            .name
            .clone()
            .or_else(|| jailfile.metadata.name.clone())
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "{} has no name; give the build one",
                    build.file.display()
                ))
            })?;
        let context = build
            .context
            .clone()
            .unwrap_or_else(|| context_of(&build.file));
        build_root(
            self,
            &jailfile,
            &context,
            &name,
            build.args.clone(),
            BuildMode::Real { verbose: false },
        )
    }

    /// Commit a built image into a cloneable release (ZFS only).
    ///
    /// # Errors
    ///
    /// Not root, no ZFS, an invalid or taken name, or a failed clone.
    pub fn commit_image(&self, image: &Image, release: &str) -> Result<Release> {
        Error::require_root("committing an image")?;
        let layout = self.layout();
        let zfs = layout.zfs().ok_or(Error::ZfsNotEnabled)?;
        let dataset = zfs.jail_dataset_name(&image.name);
        crate::release::commit_dataset(layout, &zfs, &dataset, release)
    }

    /// Delete a built image root by name. Idempotent.
    ///
    /// # Errors
    ///
    /// Not root, an invalid name, dependent releases on ZFS, or a failed removal.
    pub fn remove_image(&self, name: &str) -> Result<()> {
        Error::require_root("removing an image")?;
        crate::manifest::validate_name("jail", name)?;
        let layout = self.layout();
        let root = layout.config().config.jail_root(name);
        if let Some(zfs) = layout.zfs()
            && zfs.jail_dataset_exists(name)?
        {
            zfs.destroy_dataset_without_dependents(&zfs.jail_dataset_name(name))?;
            let _ = std::fs::remove_dir(&root); // empty mountpoint, harmless if it lingers
            return Ok(());
        }
        if root.exists() {
            crate::blueprint::context::reject_symlink_ancestors(layout.data_dir(), &root)?;
            crate::sys::remove_tree_with_flags(&root)?;
        }
        Ok(())
    }
}

/// Read and parse a Jailfile.
pub fn read_jailfile(path: &Path) -> Result<Jailfile> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        Error::TemplateParseFailed(format!("Failed to read {}: {}", path.display(), e))
    })?;
    parse_jailfile(&content)
}

/// The directory a Jailfile sits in, as its default build context.
pub fn context_of(file: &Path) -> PathBuf {
    match file.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Whether a build changes anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildMode {
    /// Report what would happen (the CLI's `--dry-run`).
    DryRun,
    /// Build it; `verbose` echoes each command's output.
    Real { verbose: bool },
}

/// Build `jailfile` into the jail root named `name`.
pub fn build_root(
    host: &Host,
    jailfile: &Jailfile,
    context_dir: &Path,
    name: &str,
    build_args: Vec<(String, String)>,
    mode: BuildMode,
) -> Result<Image> {
    crate::manifest::validate_name("jail", name)?;
    let layout = host.layout();
    let config = &layout.config().config;
    let dry_run = mode == BuildMode::DryRun;
    let target_path = config.jail_root(name);

    let zfs = layout.zfs();
    if !dry_run && let Some(zfs) = &zfs {
        zfs.init()?;
    }

    blueprint::context::reject_symlink_ancestors(&config.data_dir, &target_path)?;
    blueprint::context::reject_symlink_target(&target_path)?;

    if let Some(release) = &jailfile.from {
        crate::manifest::validate_name("release", release)?;
        let release_path = config.releases_dir.join(release);

        if dry_run {
            if !release_path.exists() {
                let shown =
                    std::path::absolute(&release_path).unwrap_or_else(|_| release_path.clone());
                println!(
                    "Would bootstrap base release '{release}' into {} (downloads the base archives)",
                    shown.display()
                );
            }
        } else {
            if !release_path.exists() {
                host.bootstrap(&Bootstrap::release(release))?;
            }

            if let Some(zfs) = &zfs
                && !zfs.jail_dataset_exists(name)?
            {
                if zfs.release_is_cloneable(release) {
                    zfs.clone_jail_from_release(release, name)?;
                } else {
                    zfs.create_jail_dataset(name)?;
                }
            }

            // A fresh dataset mounts as an empty directory, so probe ./bin.
            if !target_path.join("bin").exists() {
                std::fs::create_dir_all(&target_path)?;
                copy_release_to(&release_path, &target_path)?;
            }
        }
    }

    // Base and build args seed the cache so changing either invalidates it.
    let layer_cache = zfs.map(|zfs| {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(jailfile.from.as_deref().unwrap_or("scratch").as_bytes());
        let mut sorted_args = build_args.clone();
        sorted_args.sort();
        for (key, value) in &sorted_args {
            hasher.update(key.as_bytes());
            hasher.update(value.as_bytes());
        }
        blueprint::LayerCache {
            zfs,
            jail: name.to_string(),
            seed: hex::encode(hasher.finalize()),
        }
    });

    let verbose = matches!(mode, BuildMode::Real { verbose: true });
    let mut ctx = BuildContext::new(context_dir, &target_path, name).verbose(verbose);
    for (key, value) in build_args {
        ctx.set_arg(&key, &value);
    }

    TemplateExecutor::new(ctx)
        .dry_run(dry_run)
        .layer_cache(layer_cache)
        .execute(jailfile)?;

    Ok(Image {
        name: name.to_string(),
        root: target_path,
        base: jailfile.from.clone(),
    })
}

/// Copy a release directory into a target jail path using `cp -a`.
pub fn copy_release_to(release_path: &Path, target: &Path) -> Result<()> {
    let status = std::process::Command::new("/bin/cp")
        .arg("-a")
        .arg(format!("{}/.", release_path.display()))
        .arg(target)
        .status()
        .map_err(|e| Error::BuildFailed {
            step: "FROM".to_string(),
            message: format!("Failed to copy base release: {e}"),
        })?;
    if !status.success() {
        return Err(Error::BuildFailed {
            step: "FROM".to_string(),
            message: "cp command failed".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
