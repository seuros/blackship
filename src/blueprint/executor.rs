//! Template executor for building jails
//!
//! Executes Jailfile instructions to build a jail.

use crate::error::{Error, Result};
use crate::blueprint::context::BuildContext;
use crate::blueprint::instructions::{CopySpec, Instruction, Jailfile};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

/// Template executor for building jails
pub struct TemplateExecutor {
    /// Build context
    context: BuildContext,
    /// Dry run mode (don't execute, just print)
    dry_run: bool,
}

impl TemplateExecutor {
    /// Create a new template executor
    pub fn new(context: BuildContext) -> Self {
        Self {
            context,
            dry_run: false,
        }
    }

    /// Enable dry run mode
    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
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
                && let Some(default) = &arg.default {
                    self.context.set_arg(&arg.name, default);
                }
        }

        // Execute each instruction
        for instruction in &jailfile.instructions {
            self.execute_instruction(instruction)?;
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
                    let full_path = self.context.resolve_dest(&path);
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
                    let full_path = self.context.resolve_dest(&path);
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

        // Use chroot to run command in jail environment
        let output = Command::new("/usr/sbin/chroot")
            .arg(target_path)
            .arg("/bin/sh")
            .arg("-c")
            .arg(command)
            .envs(self.context.env())
            .output()
            .map_err(|e| Error::BuildFailed {
                step: "RUN".to_string(),
                message: format!("Failed to execute chroot: {}", e),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::BuildFailed {
                step: "RUN".to_string(),
                message: format!(
                    "Command failed with exit code {:?}: {}",
                    output.status.code(),
                    stderr
                ),
            });
        }

        // Print stdout if verbose
        if self.context.is_verbose() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.is_empty() {
                for line in stdout.lines() {
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

        let src_path = self.context.resolve_source(&src);
        let dest_path = self.context.resolve_dest(&dest);

        // Ensure source exists
        if !src_path.exists() {
            return Err(Error::BuildFailed {
                step: "COPY".to_string(),
                message: format!("Source not found: {}", src_path.display()),
            });
        }

        // Create destination parent directory if needed
        if let Some(parent) = dest_path.parent()
            && !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| Error::BuildFailed {
                    step: "COPY".to_string(),
                    message: format!("Failed to create directory {}: {}", parent.display(), e),
                })?;
            }

        // Copy file or directory
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dest_path)?;
        } else {
            // If dest ends with /, treat as directory
            let final_dest = if dest.ends_with('/') {
                dest_path.join(src_path.file_name().unwrap_or_default())
            } else {
                dest_path
            };

            fs::copy(&src_path, &final_dest).map_err(|e| Error::BuildFailed {
                step: "COPY".to_string(),
                message: format!(
                    "Failed to copy {} to {}: {}",
                    src_path.display(),
                    final_dest.display(),
                    e
                ),
            })?;

            // Set mode if specified
            if let Some(mode) = spec.mode {
                let permissions = fs::Permissions::from_mode(mode);
                fs::set_permissions(&final_dest, permissions).map_err(|e| Error::BuildFailed {
                    step: "COPY".to_string(),
                    message: format!(
                        "Failed to set permissions on {}: {}",
                        final_dest.display(),
                        e
                    ),
                })?;
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

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dest_path)?;
        } else {
            fs::copy(&src_path, &dest_path).map_err(|e| Error::BuildFailed {
                step: "COPY".to_string(),
                message: format!(
                    "Failed to copy {} to {}: {}",
                    src_path.display(),
                    dest_path.display(),
                    e
                ),
            })?;
        }
    }

    Ok(())
}

/// Set file owner using chown
fn set_owner(path: &Path, owner: &str) -> Result<()> {
    let output = Command::new("/usr/sbin/chown")
        .arg(owner)
        .arg(path)
        .output()
        .map_err(|e| Error::BuildFailed {
            step: "COPY".to_string(),
            message: format!("Failed to run chown: {}", e),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::BuildFailed {
            step: "COPY".to_string(),
            message: format!("chown failed: {}", stderr),
        });
    }

    Ok(())
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
