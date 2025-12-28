//! Command-line interface for Blackship
//!
//! Uses clap with derive for type-safe CLI parsing

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;

/// Blackship - FreeBSD jail orchestrator
#[derive(Parser)]
#[command(name = "blackship")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "blackship.toml")]
    pub config: PathBuf,

    /// Enable verbose output
    #[arg(short, long)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

/// Available commands
#[derive(Subcommand)]
pub enum Commands {
    /// Start jails (respecting dependencies)
    Up {
        /// Specific jail to start (with its dependencies)
        jail: Option<String>,

        /// Start all jails (required if no jail specified)
        #[arg(long, conflicts_with = "jail")]
        all: bool,

        /// Show what would be done without making changes
        #[arg(long)]
        dry_run: bool,
    },

    /// Stop jails (in reverse dependency order)
    Down {
        /// Specific jail to stop (with its dependents)
        jail: Option<String>,

        /// Stop all jails (required if no jail specified)
        #[arg(long, conflicts_with = "jail")]
        all: bool,

        /// Show what would be done without making changes
        #[arg(long)]
        dry_run: bool,
    },

    /// Restart jails
    Restart {
        /// Specific jail to restart
        jail: Option<String>,

        /// Restart all jails (required if no jail specified)
        #[arg(long, conflicts_with = "jail")]
        all: bool,

        /// Show what would be done without making changes
        #[arg(long)]
        dry_run: bool,
    },

    /// List jail status
    Ps {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Validate configuration
    Check,

    /// Initialize ZFS datasets
    Init,

    /// Execute a command in a running jail
    Exec {
        /// Jail name or ID
        jail: String,

        /// User to run as
        #[arg(short, long, default_value = "root")]
        user: String,

        /// Command to execute (use -- to separate from options)
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Open an interactive console in a running jail
    Console {
        /// Jail name or ID
        jail: String,

        /// User to run as
        #[arg(short, long, default_value = "root")]
        user: String,
    },

    /// Bootstrap a FreeBSD release for jail creation
    Bootstrap {
        /// Release to bootstrap (e.g., 14.2-RELEASE)
        release: String,

        /// Force re-download even if release exists
        #[arg(short, long)]
        force: bool,

        /// Archives to download (default: base)
        #[arg(short, long, value_delimiter = ',')]
        archives: Option<Vec<String>>,
    },

    /// List or manage releases
    Releases {
        #[command(subcommand)]
        action: Option<ReleasesAction>,

        /// Output in JSON format (for list action)
        #[arg(long)]
        json: bool,
    },

    /// Network management
    Network {
        #[command(subcommand)]
        action: NetworkAction,
    },

    /// Health check status and monitoring
    Health {
        /// Specific jail to check (shows all if not specified)
        jail: Option<String>,

        /// Watch mode - continuously monitor health
        #[arg(short, long)]
        watch: bool,

        /// Update interval in seconds (for watch mode)
        #[arg(short, long, default_value = "5")]
        interval: u64,

        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Build a jail from a Jailfile
    Build {
        /// Path to Jailfile (default: ./Jailfile)
        #[arg(short, long, default_value = "Jailfile")]
        file: PathBuf,

        /// Jail name (overrides metadata name)
        #[arg(short, long)]
        name: Option<String>,

        /// Build arguments (KEY=VALUE)
        #[arg(long = "build-arg", value_parser = parse_key_val)]
        build_args: Vec<(String, String)>,

        /// Build context directory (default: directory containing Jailfile)
        #[arg(short, long)]
        context: Option<PathBuf>,

        /// Don't execute, just show what would be done
        #[arg(long)]
        dry_run: bool,
    },

    /// Template management
    Template {
        #[command(subcommand)]
        action: TemplateAction,
    },

    /// Expose a jail port to the host
    Expose {
        /// Jail name
        jail: String,

        /// External port (host-side)
        #[arg(short = 'p', long)]
        port: u16,

        /// Internal port (jail-side, defaults to external port)
        #[arg(short, long)]
        internal: Option<u16>,

        /// Protocol (tcp or udp)
        #[arg(long, default_value = "tcp")]
        proto: String,

        /// Bind to specific host IP (defaults to all interfaces)
        #[arg(short = 'I', long)]
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
        #[arg(short, long)]
        force: bool,
    },

    /// Export a jail to an archive
    Export {
        /// Jail name to export
        jail: String,

        /// Output file path (default: <jail>.tar.zst)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Use ZFS send for faster export (requires ZFS)
        #[arg(long)]
        zfs_send: bool,
    },

    /// Import a jail from an archive
    Import {
        /// Archive file to import
        file: PathBuf,

        /// Name for the imported jail (default: original name)
        #[arg(short, long)]
        name: Option<String>,

        /// Overwrite existing jail
        #[arg(long)]
        force: bool,
    },

    /// Manage jail snapshots
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
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
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Start the Warden supervisor to monitor and auto-restart jails
    Supervise,

    /// Tail logs from a running jail
    Logs {
        /// Jail name
        jail: String,

        /// Follow log output (like tail -f)
        #[arg(short = 'f', long)]
        follow: bool,

        /// Number of lines to show
        #[arg(short = 'n', long, default_value = "100")]
        lines: usize,
    },
}

/// Parse key=value pairs for build arguments
fn parse_key_val(s: &str) -> Result<(String, String), String> {
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=VALUE: no `=` found in `{s}`"))?;
    Ok((s[..pos].to_string(), s[pos + 1..].to_string()))
}

/// Actions for the template command
#[derive(Subcommand)]
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
        #[arg(default_value = "Jailfile")]
        file: PathBuf,
    },
}

/// Actions for the releases command
#[derive(Subcommand)]
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
#[derive(Subcommand)]
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
        #[arg(long)]
        json: bool,
    },

    /// Rollback a jail to a snapshot
    Rollback {
        /// Jail name
        jail: String,

        /// Snapshot name
        snapshot: String,

        /// Force rollback, destroying newer snapshots
        #[arg(short, long)]
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

/// Actions for the network command
#[derive(Subcommand)]
pub enum NetworkAction {
    /// Create a new network
    Create {
        /// Network name
        name: String,

        /// Subnet in CIDR notation (e.g., 10.0.1.0/24)
        #[arg(short, long)]
        subnet: String,

        /// Gateway address (defaults to first usable in subnet)
        #[arg(short, long)]
        gateway: Option<String>,

        /// Bridge interface name (defaults to blackship0)
        #[arg(short, long, default_value = "blackship0")]
        bridge: String,
    },

    /// Destroy a network
    Destroy {
        /// Network name
        name: String,

        /// Force destruction even if jails are attached
        #[arg(short, long)]
        force: bool,
    },

    /// List all networks
    List,

    /// Attach a jail to a network
    Attach {
        /// Jail name
        jail: String,

        /// Network name
        network: String,

        /// IP address (auto-assigned if not specified)
        #[arg(short, long)]
        ip: Option<String>,
    },

    /// Detach a jail from a network
    Detach {
        /// Jail name
        jail: String,

        /// Network name
        network: String,
    },
}

impl Cli {
    /// Parse CLI arguments
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Generate shell completion scripts
    pub fn generate_completion(shell: Shell) {
        let mut cmd = Self::command();
        clap_complete::generate(shell, &mut cmd, "blackship", &mut std::io::stdout());
    }
}
