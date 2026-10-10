//! Staged manifest validation: read, then parse, then semantic checks.
//!
//! Each stage is reported separately so the model learns *where* a manifest
//! broke instead of getting one opaque message. Unlike the `build template
//! validate` CLI action this never calls `std::process::exit`.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpToolRouter;
use serde_json::{Value, json};

use super::super::McpState;
use super::manifest_inspect::ManifestPathParams;

/// The three things that can go wrong, in the order they are attempted.
const STAGES: [&str; 3] = ["read", "parse", "validate"];

impl McpState {
    /// Validate a manifest, reporting which stage failed.
    #[mcp_tool(
        name = "manifest_validate",
        description = "Validate a blackship.toml in three stages: read the file, parse the \
                       TOML, then run the semantic checks (name rules, duplicate jails, \
                       colliding full names). Reports the stage that failed and its \
                       diagnostics instead of a single opaque error.",
        read_only = true,
        idempotent = true
    )]
    async fn manifest_validate(
        &self,
        _ctx: Ctx<'_>,
        params: Parameters<ManifestPathParams>,
    ) -> ToolResult {
        let path = self.manifest_path(params.0.path.as_deref());
        let outcome = validate_stages(&path);

        let text = serde_json::to_string_pretty(&outcome)
            .map_err(|e| ToolError::Execution(format!("Failed to serialize result: {e}")))?;

        Ok(ToolOutput::text(text))
    }
}

/// Run the stages in order, stopping at the first failure.
fn validate_stages(path: &std::path::Path) -> Value {
    let base = json!({
        "path": path.display().to_string(),
        "stages": STAGES,
    });

    let content = match crate::manifest::read_config_file(path) {
        Ok(content) => content,
        Err(e) => return failure(base, "read", &e.to_string()),
    };

    validate_text(base, &content)
}

/// Parse and semantically check manifest text, merging the outcome into `base`.
///
/// Split out of [`validate_stages`] so `manifest_create` can run exactly these
/// checks on text that is not on disk yet.
pub(in crate::mcp) fn validate_text(base: Value, content: &str) -> Value {
    let config: crate::manifest::BlackshipConfig = match toml::from_str(content) {
        Ok(config) => config,
        Err(e) => return parse_failure(base, content, &e),
    };

    if let Err(e) = config.validate() {
        return failure(base, "validate", &e.to_string());
    }

    merge(
        base,
        json!({
            "valid": true,
            "failed_stage": Value::Null,
            "jails": config.jails.iter().map(|jail| jail.name.clone()).collect::<Vec<_>>(),
        }),
    )
}

/// A TOML syntax or shape error, with the position TOML reported.
fn parse_failure(base: Value, content: &str, error: &toml::de::Error) -> Value {
    let (line, column) = error.span().map_or((Value::Null, Value::Null), |span| {
        let (line, column) = byte_to_line_col(content, span.start);
        (json!(line), json!(column))
    });

    merge(
        base,
        json!({
            "valid": false,
            "failed_stage": "parse",
            "diagnostics": [{
                "line": line,
                "column": column,
                "message": error.message(),
            }],
        }),
    )
}

/// A failure with no position information.
fn failure(base: Value, stage: &str, message: &str) -> Value {
    merge(
        base,
        json!({
            "valid": false,
            "failed_stage": stage,
            "diagnostics": [{ "line": Value::Null, "column": Value::Null, "message": message }],
        }),
    )
}

/// Fold `extra`'s object fields into `base`.
fn merge(mut base: Value, extra: Value) -> Value {
    if let (Some(target), Value::Object(source)) = (base.as_object_mut(), extra) {
        target.extend(source);
    }
    base
}

pub fn mount(router: McpToolRouter<McpState>) -> McpToolRouter<McpState> {
    router.with_tool(
        McpState::manifest_validate_tool_info(),
        McpState::manifest_validate_handler,
        None,
    )
}

#[cfg(test)]
#[path = "manifest_validate/tests.rs"]
mod tests;
