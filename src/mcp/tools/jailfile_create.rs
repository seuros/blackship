//! Render a TOML Jailfile and write it only if the operator approves.
//!
//! The TOML format is the one emitted, for two reasons: it is the only format
//! that can express a `[metadata]` table, and it is reflectable, so the
//! rendered text goes through the same parser `blackship build` uses before
//! anyone is asked to approve it.
//!
//! The parameter set mirrors what the TOML parser accepts in
//! `src/blueprint/parser.rs` and nothing more. In particular there is no
//! `volumes` field: the TOML Jailfile schema has no place to put one, even
//! though the line format has a `VOLUME` keyword.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpToolRouter;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use toml::{Table, Value as TomlValue};

use super::super::McpState;
use super::super::elicit;
use crate::blueprint::parser::{JailfileFormat, parse_jailfile_as};

/// A Jailfile to author.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct JailfileCreateParams {
    /// Where to write the Jailfile. A build context conventionally holds it as
    /// `Jailfile` in the directory named by the manifest's `build` key.
    pub path: String,

    /// Template metadata: name, version, description, author, labels.
    pub metadata: Option<MetadataParams>,

    /// Base release and build steps.
    pub build: Option<BuildParams>,

    /// What the jail runs once it is up.
    pub start: Option<StartParams>,

    /// Command run inside the jail before teardown.
    pub stop: Option<String>,
}

/// The `[metadata]` table, which only the TOML format can express.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct MetadataParams {
    /// Template name.
    pub name: Option<String>,
    /// Template version.
    pub version: Option<String>,
    /// What this template is for.
    pub description: Option<String>,
    /// Who maintains it.
    pub author: Option<String>,
    /// Free-form labels.
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
}

/// The `[build]` table.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct BuildParams {
    /// Base release, for example `15.1-RELEASE`. Use one `host_facts` reports
    /// as bootstrapped.
    pub from: Option<String>,

    /// Working directory for subsequent steps.
    pub workdir: Option<String>,

    /// Build arguments, substitutable into later steps.
    #[serde(default)]
    pub args: Vec<ArgParams>,

    /// Environment variables baked into the jail.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,

    /// Commands run inside the jail, in order.
    #[serde(default)]
    pub run: Vec<String>,

    /// Files copied from the build context into the jail.
    #[serde(default)]
    pub copy: Vec<CopyParams>,

    /// Ports the jail serves. Documentation only; nothing is published.
    #[serde(default)]
    pub expose: Vec<ExposeParams>,
}

/// One build argument.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ArgParams {
    /// Argument name.
    pub name: String,
    /// Value used when the build does not supply one.
    pub default: Option<String>,
}

/// One copy step.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CopyParams {
    /// Source path, relative to the build context.
    pub src: String,
    /// Destination path inside the jail.
    pub dest: String,
    /// Octal mode to set on the destination, as a number such as `493`.
    pub mode: Option<u32>,
    /// Owner to set on the destination.
    pub owner: Option<String>,
}

/// One exposed port.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExposeParams {
    /// Port number.
    pub port: u16,
    /// Protocol, `tcp` or `udp`. Defaults to `tcp`.
    pub protocol: Option<String>,
}

/// The `[start]` table.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct StartParams {
    /// Command the jail runs.
    pub cmd: Option<String>,
    /// Entrypoint the command is passed to.
    pub entrypoint: Option<String>,
    /// User the command runs as.
    pub user: Option<String>,
}

impl McpState {
    /// Render a TOML Jailfile, validate it, and ask the operator to approve it.
    #[mcp_tool(
        name = "jailfile_create",
        description = "Render a Jailfile in the TOML format, validate it with the same parser \
                       `blackship build` uses, and write it only after the operator approves an \
                       elicitation. Returns the diagnostics and writes nothing when the rendered \
                       Jailfile does not parse, and never replaces an existing file unless the \
                       operator grants `overwrite`. Read blackship:///reference/jailfile first: \
                       several Dockerfile constructs have no equivalent here.",
        destructive = true,
        open_world = false
    )]
    async fn jailfile_create(
        &self,
        ctx: Ctx<'_>,
        params: Parameters<JailfileCreateParams>,
    ) -> ToolResult {
        let params = params.0;
        let path = std::path::PathBuf::from(&params.path);

        let rendered = render(&params)
            .map_err(|e| ToolError::Execution(format!("Failed to render Jailfile: {e}")))?;

        if let Err(e) = parse_jailfile_as(&rendered, JailfileFormat::Toml) {
            let text = serde_json::to_string_pretty(&json!({
                "path": path.display().to_string(),
                "written": false,
                "reason": "The rendered Jailfile does not parse, so the operator was not asked. \
                           Fix the diagnostics and call this tool again.",
                "format": "toml",
                "diagnostics": [{ "message": e.to_string() }],
                "rendered": rendered,
            }))
            .map_err(|e| ToolError::Execution(format!("Failed to serialize result: {e}")))?;

            return Ok(ToolOutput::text(text));
        }

        let outcome =
            elicit::write_with_approval(&ctx, &path, "a TOML Jailfile", &rendered).await?;

        let mut payload = outcome;
        if let Some(object) = payload.as_object_mut() {
            object.insert("format".to_string(), json!("toml"));
            object.insert("rendered".to_string(), json!(rendered));
        }

        let text = serde_json::to_string_pretty(&payload)
            .map_err(|e| ToolError::Execution(format!("Failed to serialize result: {e}")))?;

        Ok(ToolOutput::text(text))
    }
}

/// Render the Jailfile text as a TOML document.
pub(in crate::mcp) fn render(params: &JailfileCreateParams) -> Result<String, toml::ser::Error> {
    let mut root = Table::new();

    if let Some(metadata) = &params.metadata {
        let table = metadata_table(metadata);
        if !table.is_empty() {
            root.insert("metadata".to_string(), TomlValue::Table(table));
        }
    }

    if let Some(build) = &params.build {
        let table = build_table(build);
        if !table.is_empty() {
            root.insert("build".to_string(), TomlValue::Table(table));
        }
    }

    if let Some(start) = &params.start {
        let table = start_table(start);
        if !table.is_empty() {
            root.insert("start".to_string(), TomlValue::Table(table));
        }
    }

    if let Some(stop) = &params.stop {
        let mut table = Table::new();
        table.insert("cmd".to_string(), TomlValue::String(stop.clone()));
        root.insert("stop".to_string(), TomlValue::Table(table));
    }

    if root.is_empty() {
        root.insert("build".to_string(), TomlValue::Table(Table::new()));
    }

    toml::to_string_pretty(&root)
}

/// The `[metadata]` table.
fn metadata_table(metadata: &MetadataParams) -> Table {
    let mut table = Table::new();
    insert_string(&mut table, "name", metadata.name.as_deref());
    insert_string(&mut table, "version", metadata.version.as_deref());
    insert_string(&mut table, "description", metadata.description.as_deref());
    insert_string(&mut table, "author", metadata.author.as_deref());

    if !metadata.labels.is_empty() {
        let labels = metadata
            .labels
            .iter()
            .map(|(key, value)| (key.clone(), TomlValue::String(value.clone())))
            .collect();
        table.insert("labels".to_string(), TomlValue::Table(labels));
    }

    table
}

/// The `[build]` table, including its arrays of tables.
fn build_table(build: &BuildParams) -> Table {
    let mut table = Table::new();
    insert_string(&mut table, "from", build.from.as_deref());
    insert_string(&mut table, "workdir", build.workdir.as_deref());

    if !build.env.is_empty() {
        let env = build
            .env
            .iter()
            .map(|(key, value)| (key.clone(), TomlValue::String(value.clone())))
            .collect();
        table.insert("env".to_string(), TomlValue::Table(env));
    }

    if !build.args.is_empty() {
        table.insert(
            "args".to_string(),
            TomlValue::Array(
                build
                    .args
                    .iter()
                    .map(|arg| {
                        let mut entry = Table::new();
                        entry.insert("name".to_string(), TomlValue::String(arg.name.clone()));
                        insert_string(&mut entry, "default", arg.default.as_deref());
                        TomlValue::Table(entry)
                    })
                    .collect(),
            ),
        );
    }

    if !build.run.is_empty() {
        table.insert(
            "run".to_string(),
            TomlValue::Array(
                build
                    .run
                    .iter()
                    .map(|command| {
                        let mut entry = Table::new();
                        entry.insert(
                            "command".to_string(),
                            TomlValue::String(command.clone()),
                        );
                        TomlValue::Table(entry)
                    })
                    .collect(),
            ),
        );
    }

    if !build.copy.is_empty() {
        table.insert(
            "copy".to_string(),
            TomlValue::Array(build.copy.iter().map(copy_entry).collect()),
        );
    }

    if !build.expose.is_empty() {
        table.insert(
            "expose".to_string(),
            TomlValue::Array(
                build
                    .expose
                    .iter()
                    .map(|expose| {
                        let mut entry = Table::new();
                        entry.insert(
                            "port".to_string(),
                            TomlValue::Integer(expose.port.into()),
                        );
                        insert_string(&mut entry, "protocol", expose.protocol.as_deref());
                        TomlValue::Table(entry)
                    })
                    .collect(),
            ),
        );
    }

    table
}

/// One `[[build.copy]]` entry.
fn copy_entry(copy: &CopyParams) -> TomlValue {
    let mut entry = Table::new();
    entry.insert("src".to_string(), TomlValue::String(copy.src.clone()));
    entry.insert("dest".to_string(), TomlValue::String(copy.dest.clone()));

    if let Some(mode) = copy.mode {
        entry.insert("mode".to_string(), TomlValue::Integer(mode.into()));
    }
    insert_string(&mut entry, "owner", copy.owner.as_deref());

    TomlValue::Table(entry)
}

/// The `[start]` table.
fn start_table(start: &StartParams) -> Table {
    let mut table = Table::new();
    insert_string(&mut table, "cmd", start.cmd.as_deref());
    insert_string(&mut table, "entrypoint", start.entrypoint.as_deref());
    insert_string(&mut table, "user", start.user.as_deref());
    table
}

/// Insert `key` only when the caller supplied a value.
fn insert_string(table: &mut Table, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        table.insert(key.to_string(), TomlValue::String(value.to_string()));
    }
}

pub fn mount(router: McpToolRouter<McpState>) -> McpToolRouter<McpState> {
    router.with_tool(
        McpState::jailfile_create_tool_info(),
        McpState::jailfile_create_handler,
        None,
    )
}

#[cfg(test)]
#[path = "jailfile_create/tests.rs"]
mod tests;
