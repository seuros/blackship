//! Tool router, auto-mounted from `src/mcp/tools/`.
//!
//! Every file in that directory exposes one `pub fn mount(router) -> router`.
//! Adding or removing a file requires touching this file so the macro
//! re-expands; content edits are tracked for you.

use super::McpState;

mcp_host::auto_tools!(McpState, "src/mcp/tools");

use mcp_host::prelude::{ToolError, ToolOutput, ToolResult};
use toml::{Table, Value as TomlValue};

/// Pretty JSON as the tool's text output.
fn json_output(value: &impl serde::Serialize) -> ToolResult {
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| ToolError::Execution(format!("Failed to serialize result: {e}")))?;
    Ok(ToolOutput::text(text))
}

/// Insert `key` only when the caller supplied a value.
fn insert_string(table: &mut Table, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        table.insert(key.to_string(), TomlValue::String(value.to_string()));
    }
}
