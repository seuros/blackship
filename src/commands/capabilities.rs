//! Runtime capability discovery for CLI clients.

use std::ffi::OsStr;

use serde::Serialize;

use crate::app::{ESCALATORS, is_executable};
use crate::cli::Cli;
use crate::error::{Error, Result};
use crate::output::SCHEMA_VERSION;
use crate::sys::OsVersion;

#[derive(Debug, Serialize)]
pub struct CapabilityReport {
    pub blackship_version: &'static str,
    pub output_schema_version: u32,
    pub platform: PlatformCapabilities,
    pub build_features: BuildFeatures,
    pub cli: CliCapabilities,
    pub facilities: Vec<Facility>,
    pub privilege_escalators: Vec<Facility>,
}

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools, reason = "one flag per capability")]
pub struct PlatformCapabilities {
    pub os: &'static str,
    pub arch: &'static str,
    pub kernel_release: String,
    pub vlan_filtering: bool,
    pub pkgbase_required: bool,
    pub jail_descriptors: bool,
    pub jail_kqueue: bool,
}

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools, reason = "one flag per capability")]
pub struct BuildFeatures {
    pub cli: bool,
    pub mcp: bool,
    pub ui: bool,
    pub telemetry: bool,
    pub inspect: bool,
}

#[derive(Debug, Serialize)]
pub struct Facility {
    pub name: &'static str,
    pub path: &'static str,
    pub available: bool,
}

/// Stable CLI feature discovery for management clients.
#[derive(Debug, Serialize)]
pub struct CliCapabilities {
    pub output_formats: Vec<&'static str>,
    pub machine_output: Vec<CommandCapability>,
}

/// One exact command mode that supports the global `--format json` contract.
#[derive(Debug, Serialize)]
pub struct CommandCapability {
    /// Stable identifier for feature checks; not a shell command.
    pub operation: &'static str,
    /// Human-readable invocation, without the `blackship` prefix.
    pub invocation: &'static str,
    /// Whether this mode asks the CLI to elevate when not already root.
    pub requires_root: bool,
    /// Whether this exact mode changes host or jail state.
    pub mutates: bool,
}

struct OperationSpec {
    operation: &'static str,
    invocation: &'static str,
    args: &'static [&'static str],
}

const FACILITIES: [(&str, &str); 5] = [
    ("jail", "/usr/sbin/jail"),
    ("jls", "/usr/sbin/jls"),
    ("jexec", "/usr/sbin/jexec"),
    ("pf", "/sbin/pfctl"),
    ("zfs", "/sbin/zfs"),
];

const OPERATION_SPECS: &[OperationSpec] = &[
    spec("capabilities", "capabilities", &["capabilities"]),
    spec("host", "host", &["host"]),
    spec("ps", "ps", &["ps"]),
    spec("ps.host", "ps --host", &["ps", "--host"]),
    spec("check", "check", &["check"]),
    spec("ports", "ports", &["ports"]),
    spec("network.list", "network list", &["network", "list"]),
    spec("releases.list", "releases list", &["releases", "list"]),
    spec("stats", "stats", &["stats"]),
    spec("health", "health", &["health"]),
    spec("audit", "audit <jail>", &["audit", "jail"]),
    spec(
        "snapshot.list",
        "snapshot list <jail>",
        &["snapshot", "list", "jail"],
    ),
    spec(
        "up.dry_run",
        "up --all --dry-run",
        &["up", "--all", "--dry-run"],
    ),
    spec(
        "down.dry_run",
        "down --all --dry-run",
        &["down", "--all", "--dry-run"],
    ),
    spec(
        "restart.dry_run",
        "restart --all --dry-run",
        &["restart", "--all", "--dry-run"],
    ),
    spec(
        "eva.dry_run",
        "eva --all --dry-run",
        &["eva", "--all", "--dry-run"],
    ),
    spec(
        "autostart.dry_run",
        "autostart --dry-run",
        &["autostart", "--dry-run"],
    ),
    spec("armada.init", "armada init", &["armada", "init"]),
    spec("armada.config", "armada config", &["armada", "config"]),
    spec("armada.ps", "armada ps", &["armada", "ps"]),
    spec("armada.up", "armada up", &["armada", "up"]),
    spec(
        "armada.up.dry_run",
        "armada up --dry-run",
        &["armada", "up", "--dry-run"],
    ),
    spec("armada.down", "armada down", &["armada", "down"]),
    spec(
        "armada.down.dry_run",
        "armada down --dry-run",
        &["armada", "down", "--dry-run"],
    ),
    spec("armada.build", "armada build", &["armada", "build"]),
    spec(
        "armada.build.dry_run",
        "armada build --dry-run",
        &["armada", "build", "--dry-run"],
    ),
];

fn facility(name: &'static str, path: &'static str) -> Facility {
    Facility {
        name,
        path,
        available: is_executable(path),
    }
}

const fn spec(
    operation: &'static str,
    invocation: &'static str,
    args: &'static [&'static str],
) -> OperationSpec {
    OperationSpec {
        operation,
        invocation,
        args,
    }
}

/// The machine-readable operations, each derived from the real command it names.
///
/// A row whose arguments do not parse, or whose mode has no JSON contract, is a bug in
/// this table and fails loudly instead of vanishing from the report.
pub fn cli_capabilities() -> Result<CliCapabilities> {
    let machine_output = OPERATION_SPECS
        .iter()
        .map(|spec| {
            let args = spec.args.iter().map(OsStr::new).collect::<Vec<_>>();
            let cli = Cli::parse_from(&args).map_err(|e| {
                Error::State(format!(
                    "capability '{}' does not parse: {e:?}",
                    spec.operation
                ))
            })?;
            if !cli.command.supports_machine_output() {
                return Err(Error::State(format!(
                    "capability '{}' has no machine-readable mode",
                    spec.operation
                )));
            }
            Ok(CommandCapability {
                operation: spec.operation,
                invocation: spec.invocation,
                requires_root: cli.command.requires_root(),
                mutates: cli.command.mutates(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(CliCapabilities {
        output_formats: vec!["text", "json"],
        machine_output,
    })
}

/// Inspect the binary and host without requiring a manifest or root access.
pub fn data() -> Result<CapabilityReport> {
    let kernel = OsVersion::detect_kernel()?;
    Ok(CapabilityReport {
        blackship_version: env!("CARGO_PKG_VERSION"),
        output_schema_version: SCHEMA_VERSION,
        platform: PlatformCapabilities {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            kernel_release: kernel.to_string(),
            vlan_filtering: kernel.supports_vlan_filtering(),
            pkgbase_required: kernel.requires_pkgbase(),
            jail_descriptors: kernel.supports_jail_descriptors(),
            jail_kqueue: kernel.supports_jail_kqueue(),
        },
        build_features: BuildFeatures {
            cli: cfg!(feature = "cli"),
            mcp: cfg!(feature = "mcp"),
            ui: cfg!(feature = "ui"),
            telemetry: cfg!(feature = "telemetry"),
            inspect: cfg!(feature = "inspect"),
        },
        cli: cli_capabilities()?,
        facilities: FACILITIES
            .into_iter()
            .map(|(name, path)| facility(name, path))
            .collect(),
        privilege_escalators: ESCALATORS
            .into_iter()
            .map(|path| facility(path.rsplit('/').next().unwrap_or(path), path))
            .collect(),
    })
}

pub fn handle() -> Result<()> {
    let report = data()?;
    println!(
        "Blackship {} on {} {} ({})",
        report.blackship_version,
        report.platform.os,
        report.platform.arch,
        report.platform.kernel_release
    );
    println!("Output schema: v{}", report.output_schema_version);

    let features = [
        ("cli", report.build_features.cli),
        ("mcp", report.build_features.mcp),
        ("ui", report.build_features.ui),
        ("telemetry", report.build_features.telemetry),
        ("inspect", report.build_features.inspect),
    ]
    .into_iter()
    .filter_map(|(name, enabled)| enabled.then_some(name))
    .collect::<Vec<_>>()
    .join(", ");
    println!("Build features: {features}");

    println!("Machine-readable operations:");
    for operation in report.cli.machine_output {
        let privilege = if operation.requires_root {
            "root"
        } else {
            "user"
        };
        let effect = if operation.mutates { "write" } else { "read" };
        println!(
            "  {:<24} {privilege:<4} {effect:<5} {}",
            operation.operation, operation.invocation
        );
    }

    println!("Host facilities:");
    for facility in report.facilities {
        let status = if facility.available { "yes" } else { "no" };
        println!("  {:<8} {status:<3} {}", facility.name, facility.path);
    }

    println!("Privilege escalators:");
    for escalator in report.privilege_escalators {
        let status = if escalator.available { "yes" } else { "no" };
        println!("  {:<8} {status:<3} {}", escalator.name, escalator.path);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
