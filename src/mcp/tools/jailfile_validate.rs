//! Report every diagnostic in a Jailfile, with line and column.

use std::path::Path;

use mcp_host::prelude::*;
use mcp_host::registry::router::McpToolRouter;
use serde_json::{Value, json};

use super::super::McpState;
use super::jailfile_inspect::{JailfileParams, format_name};
use crate::blueprint::parser::{JailfileFormat, diagnose, resolve_format};

impl McpState {
    /// Collect every parse problem in a Jailfile.
    #[mcp_tool(
        name = "jailfile_validate",
        description = "Jailfile diagnostics with 1-based line/column and the parser used. Line format: one per bad line; TOML: first error only.",
        read_only = true,
        idempotent = true
    )]
    async fn jailfile_validate(
        &self,
        _ctx: Ctx<'_>,
        params: Parameters<JailfileParams>,
    ) -> ToolResult {
        let path = Path::new(&params.0.path);
        let content = std::fs::read_to_string(path).map_err(|e| {
            ToolError::InvalidArguments(format!("Cannot read {}: {e}", path.display()))
        })?;

        let report = diagnostic_report(path, &content, params.0.format.into());

        let text = serde_json::to_string(&report)
            .map_err(|e| ToolError::Execution(format!("Failed to serialize diagnostics: {e}")))?;

        Ok(ToolOutput::text(text))
    }
}

/// Build the JSON body the tool returns for one Jailfile.
fn diagnostic_report(path: &Path, content: &str, requested: JailfileFormat) -> Value {
    let resolved = resolve_format(content, requested);
    let diagnostics = diagnose(content, requested);

    json!({
        "path": path.display().to_string(),
        "requested_format": format_name(requested),
        "resolved_format": format_name(resolved),
        "valid": diagnostics.is_empty(),
        "diagnostic_count": diagnostics.len(),
        "diagnostics": diagnostics,
    })
}

pub fn mount(router: McpToolRouter<McpState>) -> McpToolRouter<McpState> {
    router.with_tool(
        McpState::jailfile_validate_tool_info(),
        McpState::jailfile_validate_handler,
        None,
    )
}

#[cfg(test)]
#[path = "jailfile_validate/tests.rs"]
mod tests;
