//! Machine-consumable host planning profile.

use crate::manifest;

/// Collect the same best-effort host profile exposed by the MCP resource.
pub fn data(config_path: &(impl manifest::ConfigSource + ?Sized)) -> serde_json::Value {
    crate::host_profile::collect(config_path)
}

/// Print the profile for interactive inspection.
pub fn handle(config_path: &(impl manifest::ConfigSource + ?Sized)) {
    println!(
        "{}",
        serde_json::to_string_pretty(&data(config_path))
            .expect("serde_json::Value always serializes")
    );
}
