//! Template executor for building jails
//!
//! Executes Jailfile instructions to build a jail.

use crate::blueprint::context::{BuildContext, reject_symlink_ancestors};
use crate::blueprint::instructions::{CopySpec, Instruction, Jailfile};
use crate::error::{Error, Result};
use crate::jail::jexec::chroot_exec;
use nix::unistd::{Group, User};
use std::ffi::CString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// ZFS-backed build layer cache: one snapshot per filesystem-mutating
/// instruction, keyed by the rolling hash of everything before it.
pub struct LayerCache {
    /// ZFS manager for the jail dataset
    pub zfs: crate::zfs::ZfsManager,
    /// Full jail name (dataset leaf)
    pub jail: String,
    /// Cache seed: identifies the base release and build arguments
    pub seed: String,
}

/// Template executor for building jails
pub struct TemplateExecutor {
    /// Build context
    context: BuildContext,
    /// Dry run mode (don't execute, just print)
    dry_run: bool,
    /// Optional ZFS layer cache
    layer_cache: Option<LayerCache>,
}

impl TemplateExecutor {
    /// Create a new template executor
    pub fn new(context: BuildContext) -> Self {
        Self {
            context,
            dry_run: false,
            layer_cache: None,
        }
    }

    /// Enable dry run mode
    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Enable the ZFS layer cache
    pub fn layer_cache(mut self, cache: Option<LayerCache>) -> Self {
        self.layer_cache = cache;
        self
    }

    /// Rolling hash key for an instruction, chained from the previous key.
    /// COPY keys include the source content so edits invalidate the layer.
    fn instruction_key(&self, prev: &str, instruction: &Instruction) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(prev.as_bytes());
        hasher.update(format!("{:?}", instruction).as_bytes());
        if let Instruction::Copy(spec) = instruction
            && let Ok(src_path) = self.context.resolve_source(&spec.src)
        {
            hash_path_contents(&mut hasher, &src_path);
        }
        hex_digest(hasher)
    }

    /// True when an instruction changes the jail filesystem (snapshot-worthy)
    fn is_layer_boundary(instruction: &Instruction) -> bool {
        matches!(instruction, Instruction::Run(_) | Instruction::Copy(_))
    }

    /// Execute a Jailfile to build a jail
    pub fn execute(&mut self, jailfile: &Jailfile) -> Result<()> {
        self.context.log(&format!(
            "Building jail '{}' from {:?}",
            self.context.jail_name(),
            jailfile.from
        ));

        // Process ARG instructions first to set defaults
        for arg in &jailfile.args {
            if self.context.get_arg(&arg.name).is_none()
                && let Some(default) = &arg.default
            {
                self.context.set_arg(&arg.name, default);
            }
        }

        // Precompute the layer hash chain and find the longest cached prefix.
        let mut resume_from = 0usize;
        let mut keys: Vec<String> = Vec::new();
        if let Some(cache) = &self.layer_cache {
            let mut hash = cache.seed.clone();
            let mut last_cached: Option<(usize, String)> = None;
            let mut chain_intact = true;
            for (index, instruction) in jailfile.instructions.iter().enumerate() {
                hash = self.instruction_key(&hash, instruction);
                keys.push(hash.clone());
                if chain_intact && Self::is_layer_boundary(instruction) {
                    let layer = crate::zfs::ZfsManager::layer_snapshot_name(index, &hash[..12]);
                    if cache.zfs.has_layer(&cache.jail, &layer) {
                        last_cached = Some((index, layer));
                    } else {
                        chain_intact = false;
                    }
                }
            }
            if let Some((index, layer)) = last_cached {
                if !self.dry_run {
                    cache.zfs.rollback_to_layer(&cache.jail, &layer)?;
                }
                println!("CACHED steps 1-{} (layer {})", index + 1, layer);
                resume_from = index + 1;
            }
        }

        // Execute each instruction, snapshotting mutating steps as layers
        for (index, instruction) in jailfile.instructions.iter().enumerate() {
            if index < resume_from {
                // Still apply metadata so ENV/WORKDIR reach later steps.
                if !Self::is_layer_boundary(instruction) {
                    self.execute_instruction(instruction)?;
                }
                continue;
            }
            self.execute_instruction(instruction)?;
            if !self.dry_run
                && Self::is_layer_boundary(instruction)
                && let Some(cache) = &self.layer_cache
            {
                let layer = crate::zfs::ZfsManager::layer_snapshot_name(index, &keys[index][..12]);
                if let Err(e) = cache.zfs.create_layer(&cache.jail, &layer) {
                    eprintln!("Warning: failed to snapshot build layer: {}", e);
                }
            }
        }

        self.context.log(&format!(
            "Build complete for '{}'",
            self.context.jail_name()
        ));

        Ok(())
    }

    /// Execute a single instruction
    fn execute_instruction(&mut self, instruction: &Instruction) -> Result<()> {
        match instruction {
            Instruction::From(release) => {
                self.context.log(&format!("FROM {}", release));
                // FROM is handled at a higher level (bootstrap)
                // The jail root should already be populated from the base release
            }

            Instruction::Arg(arg) => {
                self.context.log(&format!(
                    "ARG {}{}",
                    arg.name,
                    arg.default
                        .as_ref()
                        .map(|d| format!("={}", d))
                        .unwrap_or_default()
                ));
                // Args are processed before instruction execution
            }

            Instruction::Env(name, value) => {
                let value = self.context.substitute(value);
                self.context.log(&format!("ENV {}={}", name, value));
                self.context.set_env(name, &value);
            }

            Instruction::Run(command) => {
                let command = self.context.substitute(command);
                self.context.log(&format!("RUN {}", command));
                if !self.dry_run {
                    self.execute_run(&command)?;
                }
            }

            Instruction::Copy(spec) => {
                self.context
                    .log(&format!("COPY {} -> {}", spec.src, spec.dest));
                if !self.dry_run {
                    self.execute_copy(spec)?;
                }
            }

            Instruction::Workdir(path) => {
                let path = self.context.substitute(path);
                self.context.log(&format!("WORKDIR {}", path));
                self.context.set_workdir(&path);

                // Create the directory in the jail if it doesn't exist
                if !self.dry_run {
                    let full_path = self.context.resolve_dest(&path)?;

                    // Reject symlink ancestors: mkdir could otherwise escape the jail root.
                    let canonical_target =
                        self.context.target_path().canonicalize().map_err(|e| {
                            Error::BuildFailed {
                                step: "WORKDIR".to_string(),
                                message: format!(
                                    "Failed to canonicalize target path '{}': {}",
                                    self.context.target_path().display(),
                                    e
                                ),
                            }
                        })?;

                    let mut ancestor = full_path.as_path();
                    while !ancestor.exists() {
                        match ancestor.parent() {
                            Some(p) => ancestor = p,
                            None => break,
                        }
                    }
                    if ancestor.exists() {
                        let canonical_ancestor =
                            ancestor.canonicalize().map_err(|e| Error::BuildFailed {
                                step: "WORKDIR".to_string(),
                                message: format!(
                                    "Failed to canonicalize '{}': {}",
                                    ancestor.display(),
                                    e
                                ),
                            })?;
                        if !canonical_ancestor.starts_with(&canonical_target) {
                            return Err(Error::BuildFailed {
                                step: "WORKDIR".to_string(),
                                message: format!(
                                    "WORKDIR path '{}' resolves outside the jail root '{}'",
                                    full_path.display(),
                                    canonical_target.display()
                                ),
                            });
                        }
                    }

                    if !full_path.exists() {
                        fs::create_dir_all(&full_path).map_err(|e| Error::BuildFailed {
                            step: "WORKDIR".to_string(),
                            message: format!("Failed to create {}: {}", full_path.display(), e),
                        })?;
                    }
                }
            }

            Instruction::Expose(port) => {
                self.context
                    .log(&format!("EXPOSE {}/{}", port.port, port.protocol));
                // Expose is metadata - no action needed during build
            }

            Instruction::Cmd(cmd) => {
                let cmd = self.context.substitute(cmd);
                self.context.log(&format!("CMD {}", cmd));
                // CMD is metadata - stored for jail start
            }

            Instruction::Entrypoint(cmd) => {
                let cmd = self.context.substitute(cmd);
                self.context.log(&format!("ENTRYPOINT {}", cmd));
                // Entrypoint is metadata - stored for jail start
            }

            Instruction::User(user) => {
                let user = self.context.substitute(user);
                self.context.log(&format!("USER {}", user));
                // User is metadata - stored for jail config
            }

            Instruction::Label(key, value) => {
                let value = self.context.substitute(value);
                self.context.log(&format!("LABEL {}={}", key, value));
                // Labels are metadata
            }

            Instruction::Volume(path) => {
                let path = self.context.substitute(path);
                self.context.log(&format!("VOLUME {}", path));

                // Create the volume mount point
                if !self.dry_run {
                    let full_path = self.context.resolve_dest(&path)?;

                    let canonical_target =
                        self.context.target_path().canonicalize().map_err(|e| {
                            Error::BuildFailed {
                                step: "VOLUME".to_string(),
                                message: format!(
                                    "Failed to canonicalize target path '{}': {}",
                                    self.context.target_path().display(),
                                    e
                                ),
                            }
                        })?;

                    let mut ancestor = full_path.as_path();
                    while !ancestor.exists() {
                        match ancestor.parent() {
                            Some(p) => ancestor = p,
                            None => break,
                        }
                    }
                    if ancestor.exists() {
                        let canonical_ancestor =
                            ancestor.canonicalize().map_err(|e| Error::BuildFailed {
                                step: "VOLUME".to_string(),
                                message: format!(
                                    "Failed to canonicalize '{}': {}",
                                    ancestor.display(),
                                    e
                                ),
                            })?;
                        if !canonical_ancestor.starts_with(&canonical_target) {
                            return Err(Error::BuildFailed {
                                step: "VOLUME".to_string(),
                                message: format!(
                                    "VOLUME path '{}' resolves outside the jail root '{}'",
                                    full_path.display(),
                                    canonical_target.display()
                                ),
                            });
                        }
                    }

                    if !full_path.exists() {
                        fs::create_dir_all(&full_path).map_err(|e| Error::BuildFailed {
                            step: "VOLUME".to_string(),
                            message: format!("Failed to create {}: {}", full_path.display(), e),
                        })?;
                    }
                }
            }

            Instruction::Comment(_) => {
                // Comments are ignored during execution
            }
        }

        Ok(())
    }

    /// Execute a RUN command inside the jail
    fn execute_run(&self, command: &str) -> Result<()> {
        let target_path = self.context.target_path();
        let dev_path = target_path.join("dev");
        let resolv_path = target_path.join("etc/resolv.conf");

        // Reject symlink ancestors (e.g. etc -> /host/etc) before writing.
        reject_symlink_ancestors(target_path, &resolv_path)?;

        // create_new() is atomic, so a symlink swapped in mid-flight cannot win the race.
        if !resolv_path.exists()
            && let Ok(content) = fs::read("/etc/resolv.conf")
        {
            if let Some(parent) = resolv_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Ok(mut f) = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&resolv_path)
            {
                use std::io::Write;
                let _ = f.write_all(&content);
            }
        }

        reject_symlink_ancestors(target_path, &dev_path)?;

        // Mount devfs for the chroot environment
        let need_devfs = !dev_path.join("null").exists();
        if need_devfs {
            std::fs::create_dir_all(&dev_path).ok();

            if let Err(e) = crate::sys::mount_devfs(&dev_path) {
                eprintln!("Warning: {}", e);
            }
        }

        // Use native chroot(2) syscall to run command in jail environment
        let env_vars: Vec<(String, String)> = self
            .context
            .env()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let result = chroot_exec(target_path.to_str().unwrap(), command, &env_vars);

        // Unmount devfs if we mounted it
        if need_devfs {
            crate::sys::unmount_quiet(&dev_path);
        }

        let (exit_code, stdout, stderr) = result.map_err(|e| Error::BuildFailed {
            step: "RUN".to_string(),
            message: format!("Failed to execute chroot: {}", e),
        })?;

        if exit_code != 0 {
            let stderr_str = String::from_utf8_lossy(&stderr);
            return Err(Error::BuildFailed {
                step: "RUN".to_string(),
                message: format!(
                    "Command failed with exit code {}: {}",
                    exit_code, stderr_str
                ),
            });
        }

        // Print stdout if verbose
        if self.context.is_verbose() {
            let stdout_str = String::from_utf8_lossy(&stdout);
            if !stdout_str.is_empty() {
                for line in stdout_str.lines() {
                    println!("  {}", line);
                }
            }
        }

        Ok(())
    }

    /// Execute a COPY instruction
    fn execute_copy(&self, spec: &CopySpec) -> Result<()> {
        let src = self.context.substitute(&spec.src);
        let dest = self.context.substitute(&spec.dest);

        let src_path = self.context.resolve_source(&src)?;
        let dest_path = self.context.resolve_dest(&dest)?;

        // Ensure source exists
        if !src_path.exists() {
            return Err(Error::BuildFailed {
                step: "COPY".to_string(),
                message: format!("Source not found: {}", src_path.display()),
            });
        }

        // Canonicalize: lexical checks alone miss symlink escapes from the context.
        let canonical_src = src_path.canonicalize().map_err(|e| Error::BuildFailed {
            step: "COPY".to_string(),
            message: format!(
                "Failed to canonicalize source '{}': {}",
                src_path.display(),
                e
            ),
        })?;
        let canonical_context =
            self.context
                .context_dir()
                .canonicalize()
                .map_err(|e| Error::BuildFailed {
                    step: "COPY".to_string(),
                    message: format!(
                        "Failed to canonicalize context dir '{}': {}",
                        self.context.context_dir().display(),
                        e
                    ),
                })?;
        if !canonical_src.starts_with(&canonical_context) {
            return Err(Error::BuildFailed {
                step: "COPY".to_string(),
                message: format!(
                    "Source '{}' resolves to '{}' which is outside the build context '{}'",
                    src_path.display(),
                    canonical_src.display(),
                    canonical_context.display()
                ),
            });
        }

        let canonical_target =
            self.context
                .target_path()
                .canonicalize()
                .map_err(|e| Error::BuildFailed {
                    step: "COPY".to_string(),
                    message: format!(
                        "Failed to canonicalize target path '{}': {}",
                        self.context.target_path().display(),
                        e
                    ),
                })?;

        let check_path = if dest_path.exists() {
            dest_path.canonicalize().map_err(|e| Error::BuildFailed {
                step: "COPY".to_string(),
                message: format!(
                    "Failed to canonicalize dest '{}': {}",
                    dest_path.display(),
                    e
                ),
            })?
        } else if let Some(parent) = dest_path.parent()
            && parent.exists()
        {
            parent.canonicalize().map_err(|e| Error::BuildFailed {
                step: "COPY".to_string(),
                message: format!(
                    "Failed to canonicalize dest parent '{}': {}",
                    parent.display(),
                    e
                ),
            })?
        } else {
            canonical_target.clone()
        };

        if !check_path.starts_with(&canonical_target) {
            return Err(Error::BuildFailed {
                step: "COPY".to_string(),
                message: format!(
                    "Destination '{}' resolves outside the jail root '{}'",
                    dest_path.display(),
                    canonical_target.display()
                ),
            });
        }

        // Create destination parent directory if needed
        if let Some(parent) = dest_path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent).map_err(|e| Error::BuildFailed {
                step: "COPY".to_string(),
                message: format!("Failed to create directory {}: {}", parent.display(), e),
            })?;
        }

        // canonical_src, not src_path: the original could be swapped after validation.
        if canonical_src.is_dir() {
            copy_dir_recursive(&canonical_src, &dest_path)?;
        } else {
            // If dest ends with /, treat as directory
            let final_dest = if dest.ends_with('/') {
                dest_path.join(canonical_src.file_name().unwrap_or_default())
            } else {
                dest_path
            };

            if let Ok(meta) = fs::symlink_metadata(&final_dest)
                && meta.file_type().is_symlink()
            {
                return Err(Error::BuildFailed {
                    step: "COPY".to_string(),
                    message: format!(
                        "Destination {} is a symlink, refusing to overwrite",
                        final_dest.display()
                    ),
                });
            }

            fs::copy(&canonical_src, &final_dest).map_err(|e| Error::BuildFailed {
                step: "COPY".to_string(),
                message: format!(
                    "Failed to copy {} to {}: {}",
                    src_path.display(),
                    final_dest.display(),
                    e
                ),
            })?;

            // Strip setuid/setgid: no privilege escalation inside the chroot.
            if let Some(mode) = spec.mode {
                let safe_mode = mode & 0o1777; // Strip setuid (4000) and setgid (2000)
                let permissions = fs::Permissions::from_mode(safe_mode);
                fs::set_permissions(&final_dest, permissions).map_err(|e| Error::BuildFailed {
                    step: "COPY".to_string(),
                    message: format!(
                        "Failed to set permissions on {}: {}",
                        final_dest.display(),
                        e
                    ),
                })?;
            }

            if spec.mode.is_none()
                && let Ok(meta) = fs::metadata(&final_dest)
            {
                let current_mode = meta.permissions().mode();
                if current_mode & 0o6000 != 0 {
                    let safe_mode = current_mode & 0o1777;
                    let _ = fs::set_permissions(&final_dest, fs::Permissions::from_mode(safe_mode));
                }
            }

            // Set owner if specified (requires running as root)
            if let Some(owner) = &spec.owner {
                set_owner(&final_dest, owner)?;
            }
        }

        Ok(())
    }

    /// Get the build context (_unused: future feature)
    #[allow(dead_code)]
    pub fn context(&self) -> &BuildContext {
        &self.context
    }

    /// Get mutable build context (_unused: future feature)
    #[allow(dead_code)]
    pub fn context_mut(&mut self) -> &mut BuildContext {
        &mut self.context
    }
}

/// Recursively copy a directory
fn copy_dir_recursive(src: &Path, dest: &Path) -> Result<()> {
    if !dest.exists() {
        fs::create_dir_all(dest).map_err(|e| Error::BuildFailed {
            step: "COPY".to_string(),
            message: format!("Failed to create directory {}: {}", dest.display(), e),
        })?;
    }

    for entry in fs::read_dir(src).map_err(|e| Error::BuildFailed {
        step: "COPY".to_string(),
        message: format!("Failed to read directory {}: {}", src.display(), e),
    })? {
        let entry = entry.map_err(|e| Error::BuildFailed {
            step: "COPY".to_string(),
            message: format!("Failed to read directory entry: {}", e),
        })?;

        let src_path = entry.path();
        let dest_path = dest.join(entry.file_name());

        // symlink_metadata does not follow; skipping symlinks keeps us in the context.
        let metadata = fs::symlink_metadata(&src_path).map_err(|e| Error::BuildFailed {
            step: "COPY".to_string(),
            message: format!("Failed to read metadata for {}: {}", src_path.display(), e),
        })?;

        if metadata.file_type().is_symlink() {
            eprintln!(
                "Warning: skipping symlink '{}' during recursive copy",
                src_path.display()
            );
            continue;
        }

        if metadata.is_dir() {
            // A symlinked destination dir would redirect the whole subtree out of the jail.
            if dest_path.exists()
                && let Ok(dest_meta) = fs::symlink_metadata(&dest_path)
                && dest_meta.file_type().is_symlink()
            {
                return Err(Error::BuildFailed {
                    step: "COPY".to_string(),
                    message: format!(
                        "Destination directory '{}' is a symlink, refusing to recurse",
                        dest_path.display()
                    ),
                });
            }
            copy_dir_recursive(&src_path, &dest_path)?;
        } else {
            if let Ok(dest_meta) = fs::symlink_metadata(&dest_path)
                && dest_meta.file_type().is_symlink()
            {
                eprintln!(
                    "Warning: skipping copy to '{}' because destination is a symlink",
                    dest_path.display()
                );
                continue;
            }

            fs::copy(&src_path, &dest_path).map_err(|e| Error::BuildFailed {
                step: "COPY".to_string(),
                message: format!(
                    "Failed to copy {} to {}: {}",
                    src_path.display(),
                    dest_path.display(),
                    e
                ),
            })?;

            if let Ok(meta) = fs::metadata(&dest_path) {
                let current_mode = meta.permissions().mode();
                if current_mode & 0o6000 != 0 {
                    let safe_mode = current_mode & 0o1777;
                    let _ = fs::set_permissions(&dest_path, fs::Permissions::from_mode(safe_mode));
                }
            }
        }
    }

    Ok(())
}

/// Set file owner using chown syscall
fn set_owner(path: &Path, owner: &str) -> Result<()> {
    // Parse owner string (format: "user", "user:group", or ":group")
    let parts: Vec<&str> = owner.split(':').collect();

    let uid = if !parts[0].is_empty() {
        // Look up user by name
        User::from_name(parts[0])
            .map_err(|e| Error::BuildFailed {
                step: "COPY".to_string(),
                message: format!("Failed to lookup user {}: {}", parts[0], e),
            })?
            .ok_or_else(|| Error::BuildFailed {
                step: "COPY".to_string(),
                message: format!("User not found: {}", parts[0]),
            })?
            .uid
            .as_raw()
    } else {
        // No user specified, use -1 to keep unchanged
        u32::MAX
    };

    let gid = if parts.len() > 1 && !parts[1].is_empty() {
        // Look up group by name
        Group::from_name(parts[1])
            .map_err(|e| Error::BuildFailed {
                step: "COPY".to_string(),
                message: format!("Failed to lookup group {}: {}", parts[1], e),
            })?
            .ok_or_else(|| Error::BuildFailed {
                step: "COPY".to_string(),
                message: format!("Group not found: {}", parts[1]),
            })?
            .gid
            .as_raw()
    } else {
        // No group specified, use -1 to keep unchanged
        u32::MAX
    };

    // Use native chown(2) syscall instead of spawning process
    let path_cstr = CString::new(path.to_str().unwrap()).map_err(|e| Error::BuildFailed {
        step: "COPY".to_string(),
        message: format!("Invalid path: {}", e),
    })?;

    let result = unsafe { libc::chown(path_cstr.as_ptr(), uid, gid) };

    if result != 0 {
        return Err(Error::BuildFailed {
            step: "COPY".to_string(),
            message: format!("chown syscall failed: {}", std::io::Error::last_os_error()),
        });
    }

    Ok(())
}

/// Render a Sha256 as lowercase hex
fn hex_digest(hasher: sha2::Sha256) -> String {
    use sha2::Digest;
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Feed a file's or directory tree's contents into a hasher (sorted walk)
fn hash_path_contents(hasher: &mut sha2::Sha256, path: &Path) {
    use sha2::Digest;
    if path.is_file() {
        if let Ok(bytes) = fs::read(path) {
            hasher.update(&bytes);
        }
    } else if path.is_dir()
        && let Ok(entries) = fs::read_dir(path)
    {
        let mut paths: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for child in paths {
            hasher.update(child.to_string_lossy().as_bytes());
            hash_path_contents(hasher, &child);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blueprint::instructions::Jailfile;

    #[test]
    fn test_executor_creation() {
        let ctx = BuildContext::new(
            Path::new("/build/context"),
            Path::new("/jails/test"),
            "test",
        );
        let executor = TemplateExecutor::new(ctx);
        assert_eq!(executor.context().jail_name(), "test");
    }

    #[test]
    fn test_dry_run_mode() {
        let ctx = BuildContext::new(
            Path::new("/build/context"),
            Path::new("/jails/test"),
            "test",
        );
        let mut executor = TemplateExecutor::new(ctx).dry_run(true);

        // Create a simple jailfile with RUN
        let jailfile = Jailfile::from_release("14.2-RELEASE").run("echo test");

        // Dry run should not fail even with non-existent paths
        let result = executor.execute(&jailfile);
        assert!(result.is_ok());
    }

    #[test]
    fn test_variable_substitution_in_instructions() {
        let ctx = BuildContext::new(
            Path::new("/build/context"),
            Path::new("/jails/test"),
            "myapp",
        );
        let mut executor = TemplateExecutor::new(ctx).dry_run(true);
        executor.context_mut().set_arg("VERSION", "1.0");

        let jailfile = Jailfile::from_release("14.2-RELEASE")
            .arg("VERSION", Some("1.0"))
            .env("APP_VERSION", "${VERSION}")
            .env("APP_NAME", "${JAIL_NAME}");

        executor.execute(&jailfile).unwrap();

        assert_eq!(
            executor.context().env().get("APP_VERSION"),
            Some(&"1.0".to_string())
        );
        assert_eq!(
            executor.context().env().get("APP_NAME"),
            Some(&"myapp".to_string())
        );
    }
}
