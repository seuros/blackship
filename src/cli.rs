//! Command-line interface for Blackship
//!
//! Uses usage-rs derives for type-safe CLI parsing

use std::path::PathBuf;
use std::str::FromStr;

/// Blackship - FreeBSD jail orchestrator
#[derive(usage::Cli)]
#[usage(bin = "blackship", version, completion)]
pub struct Cli {
    /// Configuration file path
    #[usage(short, long, default = "blackship.toml")]
    pub config: PathBuf,

    /// Enable verbose output
    #[usage(short, long)]
    pub verbose: bool,

    #[usage(subcommand)]
    pub command: Commands,
}

/// Available commands
#[derive(usage::Subcommands)]
pub enum Commands {
    /// Start jails (respecting dependencies)
    Up {
        /// Specific jail to start (with its dependencies)
        jail: Option<String>,

        /// Start all jails (required if no jail specified)
        #[usage(long, conflicts = "jail")]
        all: bool,

        /// Show what would be done without making changes
        #[usage(long)]
        dry_run: bool,
    },

    /// Stop jails (in reverse dependency order)
    Down {
        /// Specific jail to stop (with its dependents)
        jail: Option<String>,

        /// Stop all jails (required if no jail specified)
        #[usage(long, conflicts = "jail")]
        all: bool,

        /// Show what would be done without making changes
        #[usage(long)]
        dry_run: bool,
    },

    /// Restart jails
    Restart {
        /// Specific jail to restart
        jail: Option<String>,

        /// Restart all jails (required if no jail specified)
        #[usage(long, conflicts = "jail")]
        all: bool,

        /// Show what would be done without making changes
        #[usage(long)]
        dry_run: bool,
    },

    /// Hot-update running jails to match the config (no restart)
    Eva {
        /// Specific jail to update (with its dependencies)
        jail: Option<String>,

        /// Update all running jails (required if no jail specified)
        #[usage(long, conflicts = "jail")]
        all: bool,

        /// Show the diff without applying changes
        #[usage(long)]
        dry_run: bool,
    },

    /// List jail status
    Ps {
        /// Output in JSON format
        #[usage(long)]
        json: bool,
    },

    /// Validate configuration
    Check,

    /// System setup (PF firewall anchor, etc.)
    Setup {
        /// Enable PF if it is not running: write a minimal /etc/pf.conf
        /// with blackship anchors if none exists, set pf_enable=YES, start pf
        #[usage(long)]
        enable_pf: bool,
    },

    /// Initialize a new Jailfile in the current directory
    Init {
        /// Output file name
        #[usage(short, long, default = "Jailfile")]
        file: PathBuf,

        /// Base FreeBSD release
        #[usage(short, long)]
        release: Option<String>,

        /// Use TOML format instead of Dockerfile-like format
        #[usage(long)]
        toml: bool,

        /// Overwrite existing file
        #[usage(short = 'y', long)]
        force: bool,
    },

    /// Orchestrate multiple jails (like docker-compose)
    Armada {
        /// Configuration files (can specify multiple, merged in order)
        #[usage(short, long = "file", var, default = "blackship.toml")]
        files: Vec<PathBuf>,

        #[usage(subcommand)]
        action: ArmadaAction,
    },

    /// Execute a command in a running jail
    Exec {
        /// Jail name or ID
        jail: String,

        /// User to run as
        #[usage(short, long, default = "root")]
        user: String,

        /// Working directory inside the jail
        #[usage(short = 'w', long)]
        workdir: Option<String>,

        /// Environment variables (KEY=VALUE format, can be repeated)
        #[usage(short = 'e', long = "env", var)]
        env: Vec<KeyVal>,

        /// Command to execute (use -- to separate from options)
        #[usage(value_name = "COMMAND", double_dash = "required", required = true)]
        command: Vec<String>,
    },

    /// Run a command in a new ephemeral jail (always cleans up when command exits)
    Run {
        /// Jail name
        #[usage(long)]
        name: String,

        /// FreeBSD release to use (e.g., 15.1-RELEASE)
        #[usage(long)]
        release: String,

        /// Run in background (detached mode) - jail persists until removed with 'blackship rm'
        #[usage(short = 'd', long)]
        detach: bool,

        /// Network to attach to
        #[usage(long)]
        network: Option<String>,

        /// Command to execute (use -- to separate from options)
        #[usage(value_name = "COMMAND", double_dash = "required")]
        command: Vec<String>,
    },

    /// Copy files between host and jail
    Cp {
        /// Source path (use jail:path for jail paths)
        source: String,

        /// Destination path (use jail:path for jail paths)
        dest: String,

        /// Preserve file attributes
        #[usage(short, long)]
        preserve: bool,
    },

    /// Remove/destroy jails
    Rm {
        /// Jail names to remove
        jails: Vec<String>,

        /// Force removal even if jail is running
        #[usage(short, long)]
        force: bool,

        /// Remove associated ZFS datasets
        #[usage(long)]
        volumes: bool,
    },

    /// Open an interactive console in a running jail
    Console {
        /// Jail name or ID
        jail: String,

        /// User to run as
        #[usage(short, long, default = "root")]
        user: String,
    },

    /// Bootstrap a FreeBSD release for jail creation
    Bootstrap {
        /// Release to bootstrap (e.g., 14.2-RELEASE)
        release: String,

        /// Force re-download even if release exists
        #[usage(short, long)]
        force: bool,

        /// Archives to download (default: base)
        #[usage(short, long, delimiter = ',')]
        archives: Option<Vec<String>>,

        /// Bootstrap from base packages instead of base.txz
        /// (automatic for FreeBSD 16 and newer, which have no dist sets)
        #[usage(long)]
        pkgbase: bool,
    },

    /// List or manage releases
    Releases {
        #[usage(subcommand)]
        action: Option<ReleasesAction>,

        /// Output in JSON format (for list action)
        #[usage(long)]
        json: bool,
    },

    /// Network management
    Network {
        #[usage(subcommand)]
        action: NetworkAction,
    },

    /// Migrate a jail to another host (zfs send | ssh zfs receive)
    Migrate {
        /// Jail to migrate (must be stopped)
        jail: String,

        /// Target host (user@host, ssh BatchMode)
        target: String,

        /// Remote dataset (default: zroot/blackship/jails/<jail>)
        #[usage(long)]
        remote_dataset: Option<String>,

        /// Keep the local jail after transfer (default: keep, prints removal hint)
        #[usage(long)]
        keep: bool,
    },

    /// Per-jail CPU, memory, and process statistics
    Stats {
        /// Specific jail (shows all running jails if omitted)
        jail: Option<String>,

        /// Output in JSON format
        #[usage(long)]
        json: bool,
    },

    /// Health check status and monitoring
    Health {
        /// Specific jail to check (shows all if not specified)
        jail: Option<String>,

        /// Watch mode - continuously monitor health
        #[usage(short, long)]
        watch: bool,

        /// Update interval in seconds (for watch mode)
        #[usage(short, long, default = "5")]
        interval: u64,

        /// Output in JSON format
        #[usage(long)]
        json: bool,
    },

    /// Build a jail from a Jailfile
    Build {
        /// Path to Jailfile (default: ./Jailfile)
        #[usage(short, long, default = "Jailfile")]
        file: PathBuf,

        /// Jail name (overrides metadata name)
        #[usage(short, long)]
        name: Option<String>,

        /// Build arguments (KEY=VALUE)
        #[usage(long = "build-arg", var)]
        build_args: Vec<KeyVal>,

        /// Build context directory (default: directory containing Jailfile)
        #[usage(short, long)]
        context: Option<PathBuf>,

        /// Don't execute, just show what would be done
        #[usage(long)]
        dry_run: bool,
    },

    /// Template management
    Template {
        #[usage(subcommand)]
        action: TemplateAction,
    },

    /// Expose a jail port to the host
    Expose {
        /// Jail name
        jail: String,

        /// External port (host-side)
        #[usage(short = 'p', long)]
        port: u16,

        /// Internal port (jail-side, defaults to external port)
        #[usage(short, long)]
        internal: Option<u16>,

        /// Protocol (tcp or udp)
        #[usage(long, default = "tcp")]
        proto: String,

        /// Bind to specific host IP (defaults to all interfaces)
        #[usage(short = 'I', long)]
        bind_ip: Option<String>,
    },

    /// List exposed ports
    Ports {
        /// Filter by jail name
        jail: Option<String>,
    },

    /// Remove all port forwards for a jail
    Unexpose {
        /// Jail name
        jail: String,
    },

    /// Clean up a failed jail (remove leftover resources)
    Cleanup {
        /// Jail name to clean up
        jail: String,

        /// Force cleanup even if errors occur
        #[usage(short, long)]
        force: bool,
    },

    /// Export a jail to an archive
    Export {
        /// Jail name to export
        jail: String,

        /// Output file path (default: <jail>.tar.zst)
        #[usage(short, long)]
        output: Option<PathBuf>,

        /// Use ZFS send for faster export (requires ZFS)
        #[usage(long)]
        zfs_send: bool,
    },

    /// Import a jail from an archive
    Import {
        /// Archive file to import
        file: PathBuf,

        /// Name for the imported jail (default: original name)
        #[usage(short, long)]
        name: Option<String>,

        /// Overwrite existing jail
        #[usage(long)]
        force: bool,

        /// Source manager: iocage, ezjail, rootfs, or auto (native when omitted)
        #[usage(long)]
        from: Option<String>,
    },

    /// Manage jail snapshots
    Snapshot {
        #[usage(subcommand)]
        action: SnapshotAction,
    },

    /// Freeze a jail into a reusable release (zero-copy snapshot + promote)
    Commit {
        /// Jail to commit
        jail: String,

        /// Name of the new release (used as FROM in Jailfiles or release =
        /// in jail definitions)
        release: String,
    },

    /// Clone a jail from a snapshot
    Clone {
        /// Source jail and snapshot (format: jail@snapshot)
        source: String,

        /// Name for the new jail
        name: String,
    },

    /// Generate shell completion scripts
    Completion {
        /// Shell to generate completion for
        #[usage(value_enum)]
        shell: Shell,
    },

    /// Start the Warden supervisor to monitor and auto-restart jails
    Supervise,

    /// Tail logs from a running jail
    Logs {
        /// Jail name
        jail: String,

        /// Follow log output (like tail -f)
        #[usage(short = 'f', long)]
        follow: bool,

        /// Number of lines to show
        #[usage(short = 'n', long, default = "100")]
        lines: usize,
    },
}

/// A KEY=VALUE pair, parsed at the CLI boundary
#[derive(Clone, Debug)]
pub struct KeyVal {
    pub key: String,
    pub value: String,
}

impl FromStr for KeyVal {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pos = s
            .find('=')
            .ok_or_else(|| format!("invalid KEY=VALUE: no `=` found in `{s}`"))?;
        Ok(Self {
            key: s[..pos].to_string(),
            value: s[pos + 1..].to_string(),
        })
    }
}

impl From<KeyVal> for (String, String) {
    fn from(kv: KeyVal) -> Self {
        (kv.key, kv.value)
    }
}

/// Convert parsed KEY=VALUE pairs into plain tuples for downstream APIs
pub fn into_pairs(pairs: Vec<KeyVal>) -> Vec<(String, String)> {
    pairs.into_iter().map(Into::into).collect()
}

/// Shells completion scripts can be generated for
#[derive(Clone, Copy, usage::ValueEnum)]
pub enum Shell {
    Bash,
    Elvish,
    Fish,
    Nu,
    Zsh,
}

impl Shell {
    fn runtime(self) -> usage::complete::Shell {
        match self {
            Self::Bash => usage::complete::Shell::Bash,
            Self::Elvish => usage::complete::Shell::Elvish,
            Self::Fish => usage::complete::Shell::Fish,
            Self::Nu => usage::complete::Shell::Nu,
            Self::Zsh => usage::complete::Shell::Zsh,
        }
    }
}

/// Actions for the template command
#[derive(usage::Subcommands)]
pub enum TemplateAction {
    /// List available templates
    List,

    /// Inspect a template or Jailfile
    Inspect {
        /// Path to Jailfile or template name
        template: String,
    },

    /// Validate a Jailfile
    Validate {
        /// Path to Jailfile
        #[usage(default = "Jailfile")]
        file: PathBuf,
    },
}

/// Actions for the releases command
#[derive(usage::Subcommands)]
pub enum ReleasesAction {
    /// List all bootstrapped releases (default)
    List,

    /// Delete a bootstrapped release
    Delete {
        /// Release to delete
        release: String,
    },

    /// Verify a bootstrapped release
    Verify {
        /// Release to verify
        release: String,
    },
}

/// Actions for the snapshot command
#[derive(usage::Subcommands)]
pub enum SnapshotAction {
    /// Create a snapshot of a jail
    Create {
        /// Jail name
        jail: String,

        /// Snapshot name (auto-generated if not specified)
        name: Option<String>,
    },

    /// List snapshots for a jail
    List {
        /// Jail name
        jail: String,

        /// Output in JSON format
        #[usage(long)]
        json: bool,
    },

    /// Rollback a jail to a snapshot
    Rollback {
        /// Jail name
        jail: String,

        /// Snapshot name
        snapshot: String,

        /// Force rollback, destroying newer snapshots
        #[usage(short, long)]
        force: bool,
    },

    /// Delete a snapshot
    Delete {
        /// Jail name
        jail: String,

        /// Snapshot name
        snapshot: String,
    },
}

/// Actions for the armada command (docker-compose style orchestration)
#[derive(usage::Subcommands)]
pub enum ArmadaAction {
    /// Initialize a new blackship.toml
    Init {
        /// Output file name
        #[usage(short, long, default = "blackship.toml")]
        file: PathBuf,

        /// Overwrite existing file
        #[usage(short = 'y', long)]
        force: bool,
    },

    /// Start all jails (auto-builds if needed)
    Up {
        /// Run in background (warden mode)
        #[usage(short, long)]
        detach: bool,

        /// Only start specific jails
        jails: Vec<String>,

        /// Force rebuild even if jail exists
        #[usage(long, conflicts = "--no-build")]
        build: bool,

        /// Don't build, fail if jail doesn't exist
        #[usage(long)]
        no_build: bool,

        /// Show what would be done without making changes
        #[usage(long)]
        dry_run: bool,
    },

    /// Stop all jails
    Down {
        /// Only stop specific jails
        jails: Vec<String>,

        /// Show what would be done without making changes
        #[usage(long)]
        dry_run: bool,
    },

    /// Build jail images from Jailfiles
    Build {
        /// Only build specific jails
        jails: Vec<String>,

        /// Show what would be done without making changes
        #[usage(long)]
        dry_run: bool,
    },

    /// Show status of all jails
    Ps {
        /// Output in JSON format
        #[usage(long)]
        json: bool,
    },

    /// Validate and show configuration
    Config {
        /// Show resolved (merged) configuration
        #[usage(long)]
        show: bool,
    },
}

/// Actions for the network command
#[derive(usage::Subcommands)]
pub enum NetworkAction {
    /// Create a new network
    Create {
        /// Network name
        name: String,

        /// Subnet in CIDR notation (e.g., 10.0.1.0/24)
        #[usage(short, long)]
        subnet: String,

        /// Gateway address (defaults to first usable in subnet)
        #[usage(short, long)]
        gateway: Option<String>,

        /// Bridge interface name (defaults to blackship0)
        #[usage(short, long, default = "blackship0")]
        bridge: String,

        /// Network backend: epair (if_bridge) or netgraph (ng_bridge with a
        /// host gateway eiface)
        #[usage(long, default = "epair")]
        backend: String,
    },

    /// Destroy a network
    Destroy {
        /// Network name
        name: String,

        /// Force destruction even if jails are attached
        #[usage(short, long)]
        force: bool,
    },

    /// List all networks
    List,
}

impl Commands {
    pub fn requires_root(&self) -> bool {
        match self {
            Self::Up { dry_run, .. }
            | Self::Down { dry_run, .. }
            | Self::Restart { dry_run, .. }
            | Self::Eva { dry_run, .. } => !dry_run,
            Self::Setup { .. }
            | Self::Exec { .. }
            | Self::Run { .. }
            | Self::Cp { .. }
            | Self::Rm { .. }
            | Self::Console { .. }
            | Self::Bootstrap { .. }
            | Self::Expose { .. }
            | Self::Unexpose { .. }
            | Self::Cleanup { .. }
            | Self::Export { .. }
            | Self::Import { .. }
            | Self::Clone { .. }
            | Self::Commit { .. }
            | Self::Migrate { .. }
            | Self::Supervise => true,
            Self::Armada { action, .. } => action.requires_root(),
            Self::Releases { action, .. } => {
                action.as_ref().is_some_and(ReleasesAction::requires_root)
            }
            Self::Network { action } => action.requires_root(),
            Self::Snapshot { action } => action.requires_root(),
            Self::Ps { .. }
            | Self::Check
            | Self::Init { .. }
            | Self::Health { .. }
            | Self::Build { .. }
            | Self::Template { .. }
            | Self::Ports { .. }
            | Self::Logs { .. }
            | Self::Stats { .. }
            | Self::Completion { .. } => false,
        }
    }
}

impl ReleasesAction {
    fn requires_root(&self) -> bool {
        matches!(self, Self::Delete { .. })
    }
}

impl SnapshotAction {
    fn requires_root(&self) -> bool {
        !matches!(self, Self::List { .. })
    }
}

impl ArmadaAction {
    fn requires_root(&self) -> bool {
        match self {
            Self::Up { dry_run, .. } | Self::Down { dry_run, .. } => !dry_run,
            Self::Init { .. } | Self::Build { .. } | Self::Ps { .. } | Self::Config { .. } => false,
        }
    }
}

impl NetworkAction {
    fn requires_root(&self) -> bool {
        matches!(self, Self::Create { .. } | Self::Destroy { .. })
    }
}

impl Cli {
    /// Parse CLI arguments
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Generate shell completion scripts
    pub fn generate_completion(shell: Shell) {
        print!("{}", Self::completion_script(shell.runtime()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_create_requires_root() {
        let command = Commands::Network {
            action: NetworkAction::Create {
                name: "default".into(),
                subnet: "10.0.1.0/24".into(),
                gateway: None,
                bridge: "blackship0".into(),
                backend: "epair".into(),
            },
        };

        assert!(command.requires_root());
    }

    #[test]
    fn test_network_list_does_not_require_root() {
        let command = Commands::Network {
            action: NetworkAction::List,
        };

        assert!(!command.requires_root());
    }

    #[test]
    fn test_bootstrap_requires_root() {
        let command = Commands::Bootstrap {
            release: "15.0-RELEASE".into(),
            force: false,
            archives: None,
            pkgbase: false,
        };

        assert!(command.requires_root());
    }

    #[test]
    fn test_up_dry_run_does_not_require_root() {
        let command = Commands::Up {
            jail: None,
            all: true,
            dry_run: true,
        };

        assert!(!command.requires_root());
    }

    #[test]
    fn test_armada_up_dry_run_does_not_require_root() {
        let command = Commands::Armada {
            files: vec![PathBuf::from("blackship.toml")],
            action: ArmadaAction::Up {
                detach: false,
                jails: Vec::new(),
                build: false,
                no_build: false,
                dry_run: true,
            },
        };

        assert!(!command.requires_root());
    }
}
