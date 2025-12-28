//! Build context for template execution
//!
//! Manages the build environment including:
//! - Build arguments
//! - Working directory
//! - File copying context

use std::collections::HashMap;
use std::path::{Path, PathBuf};

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

    /// Get the context directory (_unused: future feature)
    #[allow(dead_code)]
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

    /// Resolve a source path relative to context directory
    pub fn resolve_source(&self, src: &str) -> PathBuf {
        if Path::new(src).is_absolute() {
            PathBuf::from(src)
        } else {
            self.context_dir.join(src)
        }
    }

    /// Resolve a destination path relative to target jail
    pub fn resolve_dest(&self, dest: &str) -> PathBuf {
        let path = if Path::new(dest).is_absolute() {
            PathBuf::from(dest)
        } else {
            self.workdir.join(dest)
        };

        // Make it relative to target path by stripping leading /
        let relative = path.strip_prefix("/").unwrap_or(&path);
        self.target_path.join(relative)
    }

    /// Substitute variables in a string
    ///
    /// Supports:
    /// - ${ARG_NAME} - Build arguments
    /// - $ARG_NAME - Build arguments (simple form)
    /// - ${JAIL_NAME} - Current jail name
    /// - ${WORKDIR} - Current working directory
    pub fn substitute(&self, input: &str) -> String {
        let mut result = input.to_string();

        // Replace build args
        for (name, value) in &self.args {
            result = result.replace(&format!("${{{}}}", name), value);
            result = result.replace(&format!("${}", name), value);
        }

        // Replace environment variables
        for (name, value) in &self.env {
            result = result.replace(&format!("${{{}}}", name), value);
            result = result.replace(&format!("${}", name), value);
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
            ctx.resolve_source("nginx.conf"),
            PathBuf::from("/build/context/nginx.conf")
        );

        assert_eq!(
            ctx.resolve_dest("/etc/nginx/nginx.conf"),
            PathBuf::from("/jails/test/etc/nginx/nginx.conf")
        );
    }

    #[test]
    fn test_workdir() {
        let mut ctx = BuildContext::new(Path::new("/build"), Path::new("/jails/test"), "test");

        assert_eq!(ctx.workdir(), Path::new("/"));

        ctx.set_workdir("/usr/local");
        assert_eq!(ctx.workdir(), Path::new("/usr/local"));

        // Relative dest should use workdir
        assert_eq!(
            ctx.resolve_dest("bin/app"),
            PathBuf::from("/jails/test/usr/local/bin/app")
        );
    }
}
