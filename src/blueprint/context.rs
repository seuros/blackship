//! Build context for template execution
//!
//! Manages the build environment including:
//! - Build arguments
//! - Working directory
//! - File copying context

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
                    "Path '{}' contains '..' which could escape the {}",
                    original, boundary
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
        self.args.get(name).map(|s| s.as_str())
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

    /// Get the working directory (_unused: future feature)
    #[allow(dead_code)]
    pub fn workdir(&self) -> &Path {
        &self.workdir
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
                    "Absolute source path '{}' is not allowed; use a path relative to the build context",
                    src
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
        fn apply_var(mut s: String, name: &str, value: &str) -> String {
            s = s.replace(&format!("${{{}}}", name), value);
            s = s.replace(&format!("${}", name), value);
            s
        }

        let mut result = input.to_string();

        // Replace build args
        for (name, value) in &self.args {
            result = apply_var(result, name, value);
        }

        // Replace environment variables
        for (name, value) in &self.env {
            result = apply_var(result, name, value);
        }

        // Replace built-in variables
        result = result.replace("${JAIL_NAME}", &self.jail_name);
        result = result.replace("$JAIL_NAME", &self.jail_name);
        result = result.replace("${WORKDIR}", self.workdir.to_str().unwrap_or("/"));
        result = result.replace("$WORKDIR", self.workdir.to_str().unwrap_or("/"));

        result
    }

    /// Log a message if verbose mode is enabled
    pub fn log(&self, message: &str) {
        if self.verbose {
            println!("[build] {}", message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_context_creation() {
        let ctx = BuildContext::new(
            Path::new("/build/context"),
            Path::new("/jails/test"),
            "test",
        );

        assert_eq!(ctx.context_dir(), Path::new("/build/context"));
        assert_eq!(ctx.target_path(), Path::new("/jails/test"));
        assert_eq!(ctx.jail_name(), "test");
    }

    #[test]
    fn test_variable_substitution() {
        let mut ctx = BuildContext::new(Path::new("/build"), Path::new("/jails/myapp"), "myapp");
        ctx.set_arg("VERSION", "1.0");
        ctx.set_env("PREFIX", "/usr/local");

        assert_eq!(ctx.substitute("version=${VERSION}"), "version=1.0");
        assert_eq!(ctx.substitute("prefix=$PREFIX"), "prefix=/usr/local");
        assert_eq!(ctx.substitute("jail=${JAIL_NAME}"), "jail=myapp");
    }

    #[test]
    fn test_path_resolution() {
        let ctx = BuildContext::new(
            Path::new("/build/context"),
            Path::new("/jails/test"),
            "test",
        );

        assert_eq!(
            ctx.resolve_source("nginx.conf").unwrap(),
            PathBuf::from("/build/context/nginx.conf")
        );

        assert_eq!(
            ctx.resolve_dest("/etc/nginx/nginx.conf").unwrap(),
            PathBuf::from("/jails/test/etc/nginx/nginx.conf")
        );
    }

    #[test]
    fn test_resolve_source_rejects_absolute_path() {
        let ctx = BuildContext::new(
            Path::new("/build/context"),
            Path::new("/jails/test"),
            "test",
        );

        let result = ctx.resolve_source("/etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_source_rejects_parent_dir() {
        let ctx = BuildContext::new(
            Path::new("/build/context"),
            Path::new("/jails/test"),
            "test",
        );

        let result = ctx.resolve_source("../../../etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn test_workdir() {
        let mut ctx = BuildContext::new(Path::new("/build"), Path::new("/jails/test"), "test");

        assert_eq!(ctx.workdir(), Path::new("/"));

        ctx.set_workdir("/usr/local");
        assert_eq!(ctx.workdir(), Path::new("/usr/local"));

        // Relative dest should use workdir
        assert_eq!(
            ctx.resolve_dest("bin/app").unwrap(),
            PathBuf::from("/jails/test/usr/local/bin/app")
        );
    }
}
