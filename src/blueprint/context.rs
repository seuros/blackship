//! Build context for template execution
//!
//! Manages the build environment including:
//! - Build arguments
//! - Working directory
//! - File copying context

use crate::strings::replace_in_place;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Reject `path` if any existing directory component under `root` is a symlink.
pub fn reject_symlink_ancestors(
    root: &Path,
    path: &Path,
) -> std::result::Result<(), crate::error::Error> {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        if !current.exists() {
            break; // Rest of path doesn't exist yet, safe
        }
        if let Ok(meta) = std::fs::symlink_metadata(&current)
            && meta.file_type().is_symlink()
        {
            return Err(crate::error::Error::BuildFailed {
                step: "path".to_string(),
                message: format!(
                    "Path component '{}' is a symlink, which could escape the jail root",
                    current.display()
                ),
            });
        }
    }
    Ok(())
}

/// Reject a build target path that is itself a pre-existing symlink.
pub fn reject_symlink_target(target_path: &Path) -> std::result::Result<(), crate::error::Error> {
    if let Ok(meta) = std::fs::symlink_metadata(target_path)
        && meta.file_type().is_symlink()
    {
        return Err(crate::error::Error::BuildFailed {
            step: "FROM".to_string(),
            message: format!(
                "Build target path '{}' is a symlink, refusing to use it",
                target_path.display()
            ),
        });
    }
    Ok(())
}

/// Reject any `..` component; `boundary` names what the path could escape.
fn reject_parent_components(
    path: &Path,
    original: &str,
    boundary: &str,
) -> std::result::Result<(), crate::error::Error> {
    for component in path.components() {
        if component == std::path::Component::ParentDir {
            return Err(crate::error::Error::BuildFailed {
                step: "path".to_string(),
                message: format!(
                    "Path '{original}' contains '..' which could escape the {boundary}"
                ),
            });
        }
    }
    Ok(())
}

/// Canonicalize a path; `what` labels it in the error message.
fn canonicalize_or_fail(
    path: &Path,
    what: &str,
) -> std::result::Result<PathBuf, crate::error::Error> {
    path.canonicalize()
        .map_err(|e| crate::error::Error::BuildFailed {
            step: "path".to_string(),
            message: format!(
                "Failed to canonicalize {} '{}': {}",
                what,
                path.display(),
                e
            ),
        })
}

/// Build context for template execution
#[derive(Debug)]
pub struct BuildContext {
    /// Context directory (where Jailfile and files are located)
    context_dir: PathBuf,
    /// Build arguments (ARG name=value)
    args: HashMap<String, String>,
    /// Environment variables
    env: HashMap<String, String>,
    /// Target jail root path
    target_path: PathBuf,
    /// Current working directory inside jail
    workdir: PathBuf,
    /// Jail name being built
    jail_name: String,
    /// Verbose output
    verbose: bool,
}

impl BuildContext {
    /// Create a new build context
    pub fn new(context_dir: &Path, target_path: &Path, jail_name: &str) -> Self {
        Self {
            context_dir: context_dir.to_path_buf(),
            args: HashMap::new(),
            env: HashMap::new(),
            target_path: target_path.to_path_buf(),
            workdir: PathBuf::from("/"),
            jail_name: jail_name.to_string(),
            verbose: false,
        }
    }

    /// Enable verbose output
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Set a build argument
    pub fn set_arg(&mut self, name: &str, value: &str) {
        self.args.insert(name.to_string(), value.to_string());
    }

    /// Get a build argument
    pub fn get_arg(&self, name: &str) -> Option<&str> {
        self.args.get(name).map(std::string::String::as_str)
    }

    /// Set an environment variable
    pub fn set_env(&mut self, name: &str, value: &str) {
        self.env.insert(name.to_string(), value.to_string());
    }

    /// Get all environment variables
    pub fn env(&self) -> &HashMap<String, String> {
        &self.env
    }

    /// Set the working directory
    pub fn set_workdir(&mut self, path: &str) {
        self.workdir = PathBuf::from(path);
    }

    /// Get the context directory
    pub fn context_dir(&self) -> &Path {
        &self.context_dir
    }

    /// Get the target jail path
    pub fn target_path(&self) -> &Path {
        &self.target_path
    }

    /// Get the jail name
    pub fn jail_name(&self) -> &str {
        &self.jail_name
    }

    /// Check if verbose mode is enabled
    pub fn is_verbose(&self) -> bool {
        self.verbose
    }

    /// Resolve a source path against the context dir; rejects absolute and `..` paths.
    pub fn resolve_source(&self, src: &str) -> std::result::Result<PathBuf, crate::error::Error> {
        if Path::new(src).is_absolute() {
            return Err(crate::error::Error::BuildFailed {
                step: "path".to_string(),
                message: format!(
                    "Absolute source path '{src}' is not allowed; use a path relative to the build context"
                ),
            });
        }

        let joined = self.context_dir.join(src);

        reject_parent_components(Path::new(src), src, "build context")?;

        // Defense-in-depth: canonicalize existing paths to catch symlinks leaving the context.
        if joined.exists() {
            let canonical = canonicalize_or_fail(&joined, "source path")?;
            let canonical_context = canonicalize_or_fail(&self.context_dir, "context directory")?;
            if !canonical.starts_with(&canonical_context) {
                return Err(crate::error::Error::BuildFailed {
                    step: "path".to_string(),
                    message: format!(
                        "Source path '{}' resolves to '{}' which is outside the build context '{}'",
                        src,
                        canonical.display(),
                        canonical_context.display()
                    ),
                });
            }
        }

        Ok(joined)
    }

    /// Resolve a destination path against the target jail; rejects `..` traversal.
    pub fn resolve_dest(&self, dest: &str) -> std::result::Result<PathBuf, crate::error::Error> {
        let path = if Path::new(dest).is_absolute() {
            PathBuf::from(dest)
        } else {
            self.workdir.join(dest)
        };

        // Make it relative to target path by stripping leading /
        let relative = path.strip_prefix("/").unwrap_or(&path);

        reject_parent_components(relative, dest, "jail root")?;

        let joined = self.target_path.join(relative);

        // Only checkable when the path exists on disk: real builds, not unit tests.
        if self.target_path.exists() {
            let canonical_target = canonicalize_or_fail(&self.target_path, "target path")?;

            if joined.exists() {
                let canonical = canonicalize_or_fail(&joined, "dest path")?;
                if !canonical.starts_with(&canonical_target) {
                    return Err(crate::error::Error::BuildFailed {
                        step: "path".to_string(),
                        message: format!(
                            "Destination '{}' resolves to '{}' which is outside the jail root '{}'",
                            dest,
                            canonical.display(),
                            canonical_target.display()
                        ),
                    });
                }
            } else {
                let mut ancestor = joined.as_path();
                loop {
                    match ancestor.parent() {
                        Some(parent) if parent.exists() => {
                            let canonical_ancestor = canonicalize_or_fail(parent, "ancestor")?;
                            if !canonical_ancestor.starts_with(&canonical_target) {
                                return Err(crate::error::Error::BuildFailed {
                                    step: "path".to_string(),
                                    message: format!(
                                        "Destination '{}' has ancestor '{}' resolving to '{}' which is outside the jail root '{}'",
                                        dest,
                                        parent.display(),
                                        canonical_ancestor.display(),
                                        canonical_target.display()
                                    ),
                                });
                            }
                            break;
                        }
                        Some(parent) => {
                            ancestor = parent;
                        }
                        None => break,
                    }
                }
            }
        }

        Ok(joined)
    }

    /// Substitute variables in a string
    ///
    /// Supports:
    /// - ${ARG_NAME} - Build arguments
    /// - $ARG_NAME - Build arguments (simple form)
    /// - ${JAIL_NAME} - Current jail name
    /// - ${WORKDIR} - Current working directory
    pub fn substitute(&self, input: &str) -> String {
        if !input.contains('$') {
            return input.to_string();
        }

        let mut result = input.to_string();
        let mut needle = String::new();
        let mut apply_var = |result: &mut String, name: &str, value: &str| {
            needle.clear();
            needle.push_str("${");
            needle.push_str(name);
            needle.push('}');
            replace_in_place(result, &needle, value);

            needle.clear();
            needle.push('$');
            needle.push_str(name);
            replace_in_place(result, &needle, value);
        };

        for (name, value) in &self.args {
            apply_var(&mut result, name, value);
        }

        for (name, value) in &self.env {
            apply_var(&mut result, name, value);
        }

        let workdir = self.workdir.to_str().unwrap_or("/");
        replace_in_place(&mut result, "${JAIL_NAME}", &self.jail_name);
        replace_in_place(&mut result, "$JAIL_NAME", &self.jail_name);
        replace_in_place(&mut result, "${WORKDIR}", workdir);
        replace_in_place(&mut result, "$WORKDIR", workdir);

        result
    }

    /// Log a message if verbose mode is enabled
    pub fn log(&self, message: std::fmt::Arguments<'_>) {
        if self.verbose {
            println!("[build] {message}");
        }
    }
}

#[cfg(test)]
impl BuildContext {
    /// Get the working directory
    pub fn workdir(&self) -> &Path {
        &self.workdir
    }
}

#[cfg(test)]
mod tests;
