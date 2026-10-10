//! Report every diagnostic in a Jailfile, with line and column.

use std::path::Path;

use mcp_host::prelude::*;
use mcp_host::registry::router::McpToolRouter;
use serde_json::{Value, json};

use super::super::McpState;
use super::jailfile_inspect::{JailfileParams, format_name};
use crate::blueprint::parser::{JailfileFormat, diagnose, resolve_format};

/// What the `auto` sniffer gets wrong, stated in the tool's own output.
const AUTO_SNIFF_WART: &str = "Format `auto` sniffs the text: a line-based Jailfile whose body \
                               merely contains `[build]` or `[metadata]` is parsed as TOML and \
                               will look broken. Check `resolved_format`, and pass \
                               `format: \"line\"` to override it.";

impl McpState {
    /// Collect every parse problem in a Jailfile.
    #[mcp_tool(
        name = "jailfile_validate",
        description = "Report every parse problem in a Jailfile with 1-based line and column. \
                       The line format reports one diagnostic per bad line; the TOML format \
                       can only report its first error. Also reports which parser was \
                       actually used, which matters when `format` is `auto`.",
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

        let text = serde_json::to_string_pretty(&report)
            .map_err(|e| ToolError::Execution(format!("Failed to serialize diagnostics: {e}")))?;

        Ok(ToolOutput::text(text))
    }
}

/// Build the JSON body the tool returns for one Jailfile.
fn diagnostic_report(path: &Path, content: &str, requested: JailfileFormat) -> Value {
    let resolved = resolve_format(content, requested);
    let diagnostics = diagnose(content, requested);

    let mut report = json!({
        "path": path.display().to_string(),
        "requested_format": format_name(requested),
        "resolved_format": format_name(resolved),
        "valid": diagnostics.is_empty(),
        "diagnostic_count": diagnostics.len(),
        "diagnostics": diagnostics,
    });

    if requested == JailfileFormat::Auto
        && let Some(object) = report.as_object_mut()
    {
        object.insert("format_note".to_string(), json!(AUTO_SNIFF_WART));
    }

    report
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
