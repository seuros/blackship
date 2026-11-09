//! OTLP telemetry export; a no-op without `[telemetry]` or the `telemetry` feature.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[cfg(feature = "telemetry")]
mod otlp;
#[cfg(not(feature = "telemetry"))]
pub use disabled::{emit, init, record_usage, shutdown};
#[cfg(all(feature = "telemetry", test))]
pub use otlp::meter;
#[cfg(feature = "telemetry")]
pub use otlp::{emit, init, record_usage, shutdown};

const DEFAULT_SERVICE_NAME: &str = "blackship";

/// `[telemetry]` in blackship.toml. Transport is OTLP over HTTP/protobuf.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelemetryConfig {
    /// Collector base URL. Defaults to `http://localhost:4318`.
    pub endpoint: Option<String>,

    /// `service.name` reported on the `OTel` resource.
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Per-export timeout.
    pub timeout_secs: Option<u64>,

    /// Metric push interval. Defaults to 30s.
    pub metrics_interval_secs: Option<u64>,

    /// Extra headers on every export, e.g. collector authentication.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

fn default_service_name() -> String {
    DEFAULT_SERVICE_NAME.to_string()
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            service_name: default_service_name(),
            timeout_secs: None,
            metrics_interval_secs: None,
            headers: BTreeMap::new(),
        }
    }
}

/// Stand-ins for a build without the exporter.
#[cfg(not(feature = "telemetry"))]
mod disabled {
    // Same signatures as the exporter-backed functions, which cannot be const.
    #![allow(clippy::missing_const_for_fn)]

    use super::TelemetryConfig;
    use crate::audit::AuditRecord;

    pub fn init(_config: Option<&TelemetryConfig>) {}

    pub fn emit(_record: &AuditRecord) {}

    pub fn record_usage(_jail: &str, _sample: &std::collections::HashMap<String, u64>) {}

    pub fn shutdown() {}
}

#[cfg(test)]
mod tests;
