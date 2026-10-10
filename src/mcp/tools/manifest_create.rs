//! Render a `blackship.toml` and write it only if the operator approves.
//!
//! The parameter set is deliberately a subset of the manifest. It covers what
//! a project cannot start without — project name, data locations, ZFS, and the
//! jails themselves with their release, network, and resource limits — and
//! leaves the long tail (telemetry, named networks, hooks, health checks,
//! drain, QoS phases, cascade, mounts, rate limiting, retry, bridge VLANs) to
//! hand-editing. Those keys all have working defaults, so a manifest without
//! them is a manifest that runs; `params` is the escape hatch for raw jail
//! parameters that would otherwise need a new field here.
//!
//! The rendered text is parsed and semantically validated through the crate's
//! own types before the operator is asked anything, so an approval can never
//! produce a manifest `blackship up` would reject.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpToolRouter;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use toml::{Table, Value as TomlValue};

use super::super::McpState;
use super::super::elicit;

/// A manifest to author.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ManifestParams {
    /// Where to write the manifest. Defaults to the server's configured
    /// manifest path, which is where `blackship` looks by default.
    pub path: Option<String>,

    /// Project name. Prefixed to every jail name, and restricted to ASCII
    /// alphanumerics, dash, underscore, and dot.
    pub project: String,

    /// Base directory for jail roots and state. Omit to use the default.
    pub data_dir: Option<String>,

    /// Directory holding bootstrapped FreeBSD releases. Omit to use the
    /// default; `host_facts` reports the one in effect.
    pub releases_dir: Option<String>,

    /// ZFS pool to carve jail datasets from. Setting this turns ZFS on; the
    /// pool must already be imported, which `host_facts` reports.
    pub zpool: Option<String>,

    /// Dataset name under `zpool`. Ignored without `zpool`.
    pub dataset: Option<String>,

    /// The jails in this project.
    #[serde(default)]
    pub jails: Vec<JailParams>,
}

/// One jail entry.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct JailParams {
    /// Jail name, unique in the project. Same character rules as `project`.
    pub name: String,

    /// FreeBSD release to provision from, for example `15.1-RELEASE`. Use one
    /// `host_facts` reports as bootstrapped.
    pub release: Option<String>,

    /// Explicit jail root. Omit to let blackship derive it from `data_dir`.
    pub path: Option<String>,

    /// Build context directory containing a Jailfile.
    pub build: Option<String>,

    /// Explicit Jailfile path, as an alternative to `build`.
    pub jailfile: Option<String>,

    /// Hostname inside the jail.
    pub hostname: Option<String>,

    /// Names of jails in this manifest that must start first.
    #[serde(default)]
    pub depends_on: Vec<String>,

    /// Tags for group targeting, as in `blackship down <tag>`.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Run `/etc/rc` at start. Set false for a jail that execs one command.
    pub init: Option<bool>,

    /// Command run inside the jail before teardown.
    pub stop: Option<String>,

    /// Network configuration.
    pub network: Option<NetworkParams>,

    /// Resource limits, applied through rctl. `host_facts` reports whether
    /// rctl is usable on this host; cpuset pinning works regardless.
    pub resources: Option<ResourceParams>,

    /// Raw jail parameters, for example `allow.raw_sockets` or `exec.start`.
    /// Reserved parameters blackship manages itself are ignored at start.
    #[serde(default)]
    pub params: std::collections::BTreeMap<String, JailParamValue>,
}

/// A raw jail parameter value, limited to what `jail_set(2)` accepts here.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum JailParamValue {
    /// A boolean parameter, such as `allow.mount`.
    Bool(bool),
    /// An integer parameter, such as `children.max`.
    Integer(i64),
    /// A string parameter, such as `exec.start`.
    Text(String),
}

/// Networking for one jail.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct NetworkParams {
    /// Give the jail its own network stack through an epair.
    #[serde(default)]
    pub vnet: bool,

    /// Bridge the epair attaches to. Required for VNET.
    pub bridge: Option<String>,

    /// Address with prefix for a VNET jail, for example `10.0.1.10/24`.
    pub ip_cidr: Option<String>,

    /// Address without a prefix, for a jail sharing the host stack.
    pub ip: Option<String>,

    /// Default gateway for a VNET jail.
    pub gateway: Option<String>,

    /// Resolvers written into the jail. Empty inherits the host's.
    #[serde(default)]
    pub nameservers: Vec<String>,
}

/// Resource limits for one jail.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResourceParams {
    /// Memory limit, for example `1g` or `512m`.
    pub memory: Option<String>,

    /// Swap limit, in the same form as `memory`.
    pub swap: Option<String>,

    /// CPU percentage, where `100` is one core.
    pub cpu: Option<String>,

    /// Process count limit.
    pub maxproc: Option<u32>,

    /// Open file limit.
    pub openfiles: Option<u32>,

    /// Pin the jail to this many cores, chosen least-loaded.
    pub cores: Option<u16>,

    /// Pin the jail to an explicit CPU list, for example `0,1`. Wins over
    /// `cores`.
    pub cpuset: Option<String>,
}

impl McpState {
    /// Render a manifest, validate it, and ask the operator to approve it.
    #[mcp_tool(
        name = "manifest_create",
        description = "Render a blackship.toml from a project name and a list of jails, validate \
                       it with the same parser and semantic checks blackship itself uses, and \
                       write it only after the operator approves an elicitation. Returns the \
                       diagnostics and writes nothing when the rendered manifest is invalid, and \
                       never replaces an existing file unless the operator grants `overwrite`.",
        destructive = true,
        open_world = false
    )]
    async fn manifest_create(
        &self,
        ctx: Ctx<'_>,
        params: Parameters<ManifestParams>,
    ) -> ToolResult {
        let params = params.0;
        let path = self.manifest_path(params.path.as_deref());

        let rendered = render(&params)
            .map_err(|e| ToolError::Execution(format!("Failed to render manifest: {e}")))?;

        let report = super::manifest_validate::validate_text(
            json!({
                "path": path.display().to_string(),
                "stages": ["parse", "validate"],
                "rendered": rendered,
            }),
            &rendered,
        );

        if report["valid"] != json!(true) {
            let text = serde_json::to_string_pretty(&json!({
                "written": false,
                "reason": "The rendered manifest does not validate, so the operator was not \
                           asked. Fix the diagnostics and call this tool again.",
                "validation": report,
            }))
            .map_err(|e| ToolError::Execution(format!("Failed to serialize result: {e}")))?;

            return Ok(ToolOutput::text(text));
        }

        let outcome = elicit::write_with_approval(
            &ctx,
            &path,
            &format!("a blackship.toml for project `{}`", params.project),
            &rendered,
        )
        .await?;

        let mut payload = outcome;
        if let Some(object) = payload.as_object_mut() {
            object.insert("rendered".to_string(), json!(rendered));
        }

        let text = serde_json::to_string_pretty(&payload)
            .map_err(|e| ToolError::Execution(format!("Failed to serialize result: {e}")))?;

        Ok(ToolOutput::text(text))
    }
}

/// Render the manifest text.
///
/// Built as a TOML document rather than formatted by hand, so string escaping
/// and table ordering are the `toml` crate's problem and not this module's.
pub(in crate::mcp) fn render(params: &ManifestParams) -> Result<String, toml::ser::Error> {
    let mut root = Table::new();
    root.insert("config".to_string(), TomlValue::Table(global_table(params)));

    if !params.jails.is_empty() {
        root.insert(
            "jails".to_string(),
            TomlValue::Array(params.jails.iter().map(jail_table).collect()),
        );
    }

    toml::to_string_pretty(&root)
}

/// The `[config]` table.
fn global_table(params: &ManifestParams) -> Table {
    let mut table = Table::new();
    table.insert(
        "project".to_string(),
        TomlValue::String(params.project.clone()),
    );
    insert_string(&mut table, "data_dir", params.data_dir.as_deref());
    insert_string(&mut table, "releases_dir", params.releases_dir.as_deref());

    if let Some(zpool) = &params.zpool {
        table.insert("zfs_enabled".to_string(), TomlValue::Boolean(true));
        table.insert("zpool".to_string(), TomlValue::String(zpool.clone()));
        insert_string(&mut table, "dataset", params.dataset.as_deref());
    }

    table
}

/// One `[[jails]]` entry.
fn jail_table(jail: &JailParams) -> TomlValue {
    let mut table = Table::new();
    table.insert("name".to_string(), TomlValue::String(jail.name.clone()));
    insert_string(&mut table, "release", jail.release.as_deref());
    insert_string(&mut table, "path", jail.path.as_deref());
    insert_string(&mut table, "build", jail.build.as_deref());
    insert_string(&mut table, "jailfile", jail.jailfile.as_deref());
    insert_string(&mut table, "hostname", jail.hostname.as_deref());
    insert_string(&mut table, "stop", jail.stop.as_deref());

    if let Some(init) = jail.init {
        table.insert("init".to_string(), TomlValue::Boolean(init));
    }
    insert_strings(&mut table, "depends_on", &jail.depends_on);
    insert_strings(&mut table, "tags", &jail.tags);

    if !jail.params.is_empty() {
        let params = jail
            .params
            .iter()
            .map(|(key, value)| (key.clone(), param_value(value)))
            .collect();
        table.insert("params".to_string(), TomlValue::Table(params));
    }

    if let Some(network) = &jail.network {
        table.insert(
            "network".to_string(),
            TomlValue::Table(network_table(network)),
        );
    }

    if let Some(resources) = &jail.resources {
        let resources = resource_table(resources);
        if !resources.is_empty() {
            table.insert("resources".to_string(), TomlValue::Table(resources));
        }
    }

    TomlValue::Table(table)
}

/// The `[jails.network]` table.
fn network_table(network: &NetworkParams) -> Table {
    let mut table = Table::new();
    if network.vnet {
        table.insert("vnet".to_string(), TomlValue::Boolean(true));
    }
    insert_string(&mut table, "bridge", network.bridge.as_deref());
    insert_string(&mut table, "ip_cidr", network.ip_cidr.as_deref());
    insert_string(&mut table, "ip", network.ip.as_deref());
    insert_string(&mut table, "gateway", network.gateway.as_deref());

    if !network.nameservers.is_empty() {
        let mut dns = Table::new();
        insert_strings(&mut dns, "nameservers", &network.nameservers);
        dns.insert("mode".to_string(), TomlValue::String("custom".to_string()));
        table.insert("dns".to_string(), TomlValue::Table(dns));
    }

    table
}

/// The `[jails.resources]` table.
fn resource_table(resources: &ResourceParams) -> Table {
    let mut table = Table::new();
    insert_string(&mut table, "memory", resources.memory.as_deref());
    insert_string(&mut table, "swap", resources.swap.as_deref());
    insert_string(&mut table, "cpu", resources.cpu.as_deref());
    insert_string(&mut table, "cpuset", resources.cpuset.as_deref());

    if let Some(maxproc) = resources.maxproc {
        table.insert("maxproc".to_string(), TomlValue::Integer(maxproc.into()));
    }
    if let Some(openfiles) = resources.openfiles {
        table.insert("openfiles".to_string(), TomlValue::Integer(openfiles.into()));
    }
    if let Some(cores) = resources.cores {
        table.insert("cores".to_string(), TomlValue::Integer(cores.into()));
    }

    table
}

/// A raw jail parameter, keeping its TOML type: `jail_set(2)` distinguishes a
/// boolean from the string `"true"`.
fn param_value(value: &JailParamValue) -> TomlValue {
    match value {
        JailParamValue::Bool(flag) => TomlValue::Boolean(*flag),
        JailParamValue::Integer(number) => TomlValue::Integer(*number),
        JailParamValue::Text(text) => TomlValue::String(text.clone()),
    }
}

/// Insert `key` only when the caller supplied a value.
fn insert_string(table: &mut Table, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        table.insert(key.to_string(), TomlValue::String(value.to_string()));
    }
}

/// Insert `key` only when the list is non-empty, so defaults stay implicit.
fn insert_strings(table: &mut Table, key: &str, values: &[String]) {
    if !values.is_empty() {
        table.insert(
            key.to_string(),
            TomlValue::Array(
                values
                    .iter()
                    .map(|value| TomlValue::String(value.clone()))
                    .collect(),
            ),
        );
    }
}

pub fn mount(router: McpToolRouter<McpState>) -> McpToolRouter<McpState> {
    router.with_tool(
        McpState::manifest_create_tool_info(),
        McpState::manifest_create_handler,
        None,
    )
}

#[cfg(test)]
#[path = "manifest_create/tests.rs"]
mod tests;
