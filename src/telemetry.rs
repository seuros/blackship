//! OTLP telemetry export. Every entry point is a no-op without `[telemetry]`.

use crate::audit::AuditRecord;
use rama::http::HeaderMap;
use rama::http::client::DefaultHttpWebClient;
use rama::telemetry::opentelemetry::collector::OtelExporter;
use rama::telemetry::opentelemetry::metrics::{Counter, Gauge, Meter, MeterProvider};
use rama::telemetry::opentelemetry::sdk::Resource;
use rama::telemetry::opentelemetry::sdk::metrics::{PeriodicReader, SdkMeterProvider};
use rama::telemetry::opentelemetry::sdk::trace::{BatchSpanProcessor, SdkTracerProvider};
use rama::telemetry::opentelemetry::trace::{Span, SpanKind, Tracer, TracerProvider};
use rama::telemetry::opentelemetry::{KeyValue, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "http://localhost:4318";
const DEFAULT_SERVICE_NAME: &str = "blackship";
const DEFAULT_METRICS_INTERVAL_SECS: u64 = 30;
const SCOPE_NAME: &str = "blackship";

/// `[telemetry]` in blackship.toml. Transport is OTLP over HTTP/protobuf.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelemetryConfig {
    /// Collector base URL. Defaults to `http://localhost:4318`.
    pub endpoint: Option<String>,

    /// `service.name` reported on the OTel resource.
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

struct Telemetry {
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
    meter: Meter,
    lifecycle_events: Counter<u64>,
    /// One gauge per racct resource, created on first sight of that resource.
    usage_gauges: std::sync::Mutex<std::collections::HashMap<String, Gauge<u64>>>,
    _runtime: tokio::runtime::Runtime,
}

static TELEMETRY: OnceLock<Option<Telemetry>> = OnceLock::new();

/// Build the exporter once. Idempotent, and a no-op for `None`.
pub fn init(config: Option<&TelemetryConfig>) {
    TELEMETRY.get_or_init(|| {
        let config = config?;
        match build(config) {
            Ok(telemetry) => Some(telemetry),
            Err(e) => {
                eprintln!("Warning: telemetry disabled: {}", e);
                None
            }
        }
    });
}

fn build(config: &TelemetryConfig) -> Result<Telemetry, String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .thread_name("blackship-otlp")
        .build()
        .map_err(|e| format!("failed to start telemetry runtime: {}", e))?;

    let endpoint = config.endpoint.as_deref().unwrap_or(DEFAULT_ENDPOINT);
    let uri = endpoint
        .parse()
        .map_err(|e| format!("invalid endpoint '{}': {}", endpoint, e))?;

    let mut exporter = OtelExporter::new_http(DefaultHttpWebClient::default())
        .with_endpoint(uri)
        .maybe_with_timeout(config.timeout_secs.map(Duration::from_secs))
        .with_runtime(runtime.handle().clone());

    if !config.headers.is_empty() {
        exporter = exporter.with_headers(build_headers(&config.headers)?);
    }

    let resource = Resource::builder()
        .with_service_name(Value::from(config.service_name.clone()))
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .with_attribute(KeyValue::new("host.name", host_name()))
        .build();

    let tracer_provider = SdkTracerProvider::builder()
        .with_span_processor(BatchSpanProcessor::builder(exporter.clone()).build())
        .with_resource(resource.clone())
        .build();

    let interval = Duration::from_secs(
        config
            .metrics_interval_secs
            .unwrap_or(DEFAULT_METRICS_INTERVAL_SECS),
    );
    let meter_provider = SdkMeterProvider::builder()
        .with_reader(
            PeriodicReader::builder(exporter)
                .with_interval(interval)
                .build(),
        )
        .with_resource(resource)
        .build();

    let meter = meter_provider.meter(SCOPE_NAME);
    let lifecycle_events = meter
        .u64_counter("blackship.jail.lifecycle_events")
        .with_description("Jail lifecycle transitions recorded by the audit log")
        .build();

    Ok(Telemetry {
        tracer_provider,
        meter_provider,
        meter,
        lifecycle_events,
        usage_gauges: std::sync::Mutex::new(std::collections::HashMap::new()),
        _runtime: runtime,
    })
}

fn build_headers(headers: &BTreeMap<String, String>) -> Result<HeaderMap, String> {
    let mut map = HeaderMap::new();
    for (key, value) in headers {
        let name: rama::http::HeaderName = key
            .parse()
            .map_err(|e| format!("invalid telemetry header name '{}': {}", key, e))?;
        let value: rama::http::HeaderValue = value
            .parse()
            .map_err(|e| format!("invalid telemetry header value for '{}': {}", key, e))?;
        map.insert(name, value);
    }
    Ok(map)
}

fn host_name() -> String {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len() - 1) };
    if rc != 0 {
        return "unknown".to_string();
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..len]).into_owned()
}

fn active() -> Option<&'static Telemetry> {
    TELEMETRY.get()?.as_ref()
}

/// Export an audit record as a span plus a lifecycle counter increment.
pub fn emit(record: &AuditRecord) {
    let Some(telemetry) = active() else {
        return;
    };

    let attributes = vec![
        KeyValue::new("jail", record.jail.clone()),
        KeyValue::new("event", record.event.as_str()),
    ];
    telemetry.lifecycle_events.add(1, &attributes);

    let tracer = telemetry.tracer_provider.tracer(SCOPE_NAME);
    let mut span = tracer
        .span_builder(format!("jail.{}", record.event.as_str()))
        .with_kind(SpanKind::Internal)
        .with_attributes(attributes)
        .start(&tracer);
    for (key, value) in &record.detail {
        span.set_attribute(KeyValue::new(key.clone(), value.clone()));
    }
    span.end();
}

/// The meter racct gauges are recorded through. `None` when telemetry is off.
#[cfg(test)]
pub fn meter() -> Option<&'static Meter> {
    active().map(|telemetry| &telemetry.meter)
}

/// Export one racct sample as a gauge per resource, attributed with the jail.
pub fn record_usage(jail: &str, sample: &std::collections::HashMap<String, u64>) {
    let Some(telemetry) = active() else {
        return;
    };

    let Ok(mut gauges) = telemetry.usage_gauges.lock() else {
        return;
    };

    let attributes = [KeyValue::new("jail", jail.to_string())];
    for (resource, value) in sample {
        let gauge = gauges.entry(resource.clone()).or_insert_with(|| {
            telemetry
                .meter
                .u64_gauge(format!("blackship.jail.{}", resource))
                .with_description("racct resource usage sampled by the warden")
                .build()
        });
        gauge.record(*value, &attributes);
    }
}

/// Flush and stop the exporters. Required on every process exit path.
pub fn shutdown() {
    let Some(telemetry) = active() else {
        return;
    };
    if let Err(e) = telemetry.tracer_provider.force_flush() {
        eprintln!("Warning: failed to flush telemetry traces: {}", e);
    }
    if let Err(e) = telemetry.meter_provider.force_flush() {
        eprintln!("Warning: failed to flush telemetry metrics: {}", e);
    }
    let _ = telemetry.tracer_provider.shutdown();
    let _ = telemetry.meter_provider.shutdown();
}

#[cfg(test)]
mod tests;
