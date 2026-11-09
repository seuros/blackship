//! Runtime capability discovery for CLI clients.

use std::os::unix::fs::PermissionsExt;

use serde::Serialize;

use crate::error::Result;
use crate::output::SCHEMA_VERSION;
use crate::sys::OsVersion;

#[derive(Debug, Serialize)]
pub struct CapabilityReport {
    pub blackship_version: &'static str,
    pub output_schema_version: u32,
    pub platform: PlatformCapabilities,
    pub build_features: BuildFeatures,
    pub facilities: Vec<Facility>,
    pub privilege_escalators: Vec<Facility>,
}

#[derive(Debug, Serialize)]
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
pub struct BuildFeatures {
    pub cli: bool,
    pub mcp: bool,
    pub telemetry: bool,
    pub inspect: bool,
}

#[derive(Debug, Serialize)]
pub struct Facility {
    pub name: &'static str,
    pub path: &'static str,
    pub available: bool,
}

const FACILITIES: [(&str, &str); 5] = [
    ("jail", "/usr/sbin/jail"),
    ("jls", "/usr/sbin/jls"),
    ("jexec", "/usr/sbin/jexec"),
    ("pf", "/sbin/pfctl"),
    ("zfs", "/sbin/zfs"),
];

const ESCALATORS: [(&str, &str); 4] = [
    ("mdo", "/usr/bin/mdo"),
    ("doas", "/usr/local/bin/doas"),
    ("sudo", "/usr/local/bin/sudo"),
    ("sudo", "/usr/bin/sudo"),
];

fn is_executable(path: &str) -> bool {
    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

fn facilities(entries: &'static [(&'static str, &'static str)]) -> Vec<Facility> {
    entries
        .iter()
        .map(|(name, path)| Facility {
            name,
            path,
            available: is_executable(path),
        })
        .collect()
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
            telemetry: cfg!(feature = "telemetry"),
            inspect: cfg!(feature = "inspect"),
        },
        facilities: facilities(&FACILITIES),
        privilege_escalators: facilities(&ESCALATORS),
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
        ("telemetry", report.build_features.telemetry),
        ("inspect", report.build_features.inspect),
    ]
    .into_iter()
    .filter_map(|(name, enabled)| enabled.then_some(name))
    .collect::<Vec<_>>()
    .join(", ");
    println!("Build features: {features}");

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
mod tests {
    use super::*;

    #[test]
    fn report_is_manifestless_and_machine_serializable() {
        let report = data().unwrap();
        let value = serde_json::to_value(report).unwrap();

        assert_eq!(value["output_schema_version"], SCHEMA_VERSION);
        assert_eq!(value["platform"]["os"], "freebsd");
        assert!(value["facilities"].is_array());
        assert!(value["privilege_escalators"].is_array());
    }
}
