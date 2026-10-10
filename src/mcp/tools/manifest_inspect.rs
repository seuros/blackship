//! Read a `blackship.toml` back as JSON.

use std::path::PathBuf;

use mcp_host::prelude::*;
use mcp_host::registry::router::McpToolRouter;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use super::super::McpState;

/// Optional override for the manifest path.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ManifestPathParams {
    /// Path to the manifest. Defaults to the server's configured manifest path.
    pub path: Option<String>,
}

impl McpState {
    /// Parse a manifest and return it as JSON.
    #[mcp_tool(
        name = "manifest_inspect",
        description = "Parse a blackship.toml and return the fully resolved manifest as JSON, \
                       including the defaults that were filled in. Use manifest_validate \
                       instead when you want to know why a manifest is rejected.",
        read_only = true,
        idempotent = true
    )]
    async fn manifest_inspect(
        &self,
        _ctx: Ctx<'_>,
        params: Parameters<ManifestPathParams>,
    ) -> ToolResult {
        let path = self.manifest_path(params.0.path.as_deref());

        if !path.exists() {
            return Err(ToolError::InvalidArguments(format!(
                "No manifest at {}. Nothing has been authored there yet.",
                path.display()
            )));
        }

        let config = crate::manifest::load(&path)
            .map_err(|e| ToolError::Execution(format!("{}: {e}", path.display())))?;

        let payload = json!({
            "path": path.display().to_string(),
            "manifest": config,
        });

        let text = serde_json::to_string_pretty(&payload)
            .map_err(|e| ToolError::Execution(format!("Failed to serialize manifest: {e}")))?;

        Ok(ToolOutput::text(text))
    }
}

impl McpState {
    /// Resolve a caller-supplied manifest path against the server's default.
    pub(in crate::mcp) fn manifest_path(&self, requested: Option<&str>) -> PathBuf {
        requested.map_or_else(|| self.config_path.clone(), PathBuf::from)
    }
}

pub fn mount(router: McpToolRouter<McpState>) -> McpToolRouter<McpState> {
    router.with_tool(
        McpState::manifest_inspect_tool_info(),
        McpState::manifest_inspect_handler,
        None,
    )
}
