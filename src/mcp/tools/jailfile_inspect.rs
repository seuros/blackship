//! Parse a Jailfile and return the resolved template as JSON.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpToolRouter;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use super::super::McpState;
use crate::blueprint::parser::JailfileFormat;

/// Which parser to use, when the caller knows better than the sniffer.
#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum FormatParam {
    /// Sniff the content and pick a parser.
    #[default]
    Auto,
    /// Force the line-based (Dockerfile-like) parser.
    Line,
    /// Force the TOML parser.
    Toml,
}

impl From<FormatParam> for JailfileFormat {
    fn from(value: FormatParam) -> Self {
        match value {
            FormatParam::Auto => Self::Auto,
            FormatParam::Line => Self::Line,
            FormatParam::Toml => Self::Toml,
        }
    }
}

/// A Jailfile path plus an optional format override.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct JailfileParams {
    /// Path to the Jailfile.
    pub path: String,
    /// Parser to use. Defaults to `auto`, which sniffs the content.
    #[serde(default)]
    pub format: FormatParam,
}

impl McpState {
    /// Parse a Jailfile and return it as JSON.
    #[mcp_tool(
        name = "jailfile_inspect",
        description = "Parse a Jailfile and return the resolved template as JSON: base \
                       release, build args, instructions, exposed ports, volumes, and \
                       environment. Accepts both the line-based (Dockerfile-like) and TOML \
                       formats; pass `format` to bypass content sniffing.",
        read_only = true,
        idempotent = true
    )]
    async fn jailfile_inspect(
        &self,
        _ctx: Ctx<'_>,
        params: Parameters<JailfileParams>,
    ) -> ToolResult {
        let path = std::path::PathBuf::from(&params.0.path);
        let content = std::fs::read_to_string(&path).map_err(|e| {
            ToolError::InvalidArguments(format!("Cannot read {}: {e}", path.display()))
        })?;

        let format = JailfileFormat::from(params.0.format);
        let jailfile = crate::blueprint::parser::parse_jailfile_as(&content, format)
            .map_err(|e| ToolError::Execution(format!("{}: {e}", path.display())))?;

        let payload = json!({
            "path": path.display().to_string(),
            "requested_format": format_name(format),
            "jailfile": jailfile,
        });

        let text = serde_json::to_string_pretty(&payload)
            .map_err(|e| ToolError::Execution(format!("Failed to serialize Jailfile: {e}")))?;

        Ok(ToolOutput::text(text))
    }
}

/// Stable lowercase name for a format, for JSON output.
pub(in crate::mcp) fn format_name(format: JailfileFormat) -> &'static str {
    match format {
        JailfileFormat::Auto => "auto",
        JailfileFormat::Line => "line",
        JailfileFormat::Toml => "toml",
    }
}

pub fn mount(router: McpToolRouter<McpState>) -> McpToolRouter<McpState> {
    router.with_tool(
        McpState::jailfile_inspect_tool_info(),
        McpState::jailfile_inspect_handler,
        None,
    )
}
