//! The JSON Schema for `jailfile_create`'s parameters.
//!
//! Derived from the parameter type itself. It covers the TOML Jailfile format
//! only; `blackship:///reference/jailfile` covers the line format and the
//! Dockerfile constructs neither format supports.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpResourceRouter;

use super::super::McpState;
use super::super::tools::jailfile_create::JailfileCreateParams;

const URI: &str = "blackship:///schema/jailfile";

const MIME: &str = "application/schema+json";

impl McpState {
    /// The Jailfile authoring schema.
    #[mcp_resource(
        uri = "blackship:///schema/jailfile",
        name = "schema/jailfile",
        mime_type = "application/schema+json",
        description = "JSON Schema for the arguments `jailfile_create` accepts: the metadata, \
                       build, start, and stop sections of a TOML Jailfile. Generated from the \
                       tool's own parameter type, so a field absent here is a field the TOML \
                       Jailfile format cannot express."
    )]
    async fn schema_jailfile(&self, _ctx: Ctx<'_>) -> ResourceResult {
        let schema = serde_json::to_string_pretty(&schema_for::<JailfileCreateParams>())
            .map_err(|e| ResourceError::Internal(format!("Failed to serialize schema: {e}")))?;

        Ok(vec![text_resource_with_mime(URI, schema, MIME)])
    }
}

pub fn mount(router: McpResourceRouter<McpState>) -> McpResourceRouter<McpState> {
    router.with_resource(
        McpState::schema_jailfile_resource_info(),
        McpState::schema_jailfile_handler,
        None,
    )
}
