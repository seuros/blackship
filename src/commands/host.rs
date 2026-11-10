//! Machine-consumable host planning profile.

use std::path::Path;

/// Collect the same best-effort host profile exposed by the MCP resource.
pub fn data(config_path: &Path) -> serde_json::Value {
    crate::host_profile::collect(config_path)
}

/// Print the profile for interactive inspection.
pub fn handle(config_path: &Path) {
    println!(
        "{}",
        serde_json::to_string_pretty(&data(config_path))
            .expect("serde_json::Value always serializes")
    );
}
