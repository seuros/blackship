//! The JSON Schema for `manifest_create`'s parameters.
//!
//! Derived from the parameter type itself, so it cannot drift from what the
//! tool accepts. It describes the authoring subset, not the full manifest:
//! `blackship:///man` documents the rest.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpResourceRouter;

use super::super::McpState;
use super::super::tools::manifest_create::ManifestParams;

const URI: &str = "blackship:///schema/manifest";

const MIME: &str = "application/schema+json";

impl McpState {
    /// The manifest authoring schema.
    #[mcp_resource(
        uri = "blackship:///schema/manifest",
        name = "schema/manifest",
        mime_type = "application/schema+json",
        description = "JSON Schema for the arguments `manifest_create` accepts: project name, \
                       data and release directories, ZFS pool, and the jails with their \
                       release, network, resource limits, and raw jail parameters. Generated \
                       from the tool's own parameter type. Manifest keys outside this subset \
                       keep their defaults and can be hand-edited afterwards."
    )]
    async fn schema_manifest(&self, _ctx: Ctx<'_>) -> ResourceResult {
        let schema = serde_json::to_string_pretty(&schema_for::<ManifestParams>())
            .map_err(|e| ResourceError::Internal(format!("Failed to serialize schema: {e}")))?;

        Ok(vec![text_resource_with_mime(URI, schema, MIME)])
    }
}

pub fn mount(router: McpResourceRouter<McpState>) -> McpResourceRouter<McpState> {
    router.with_resource(
        McpState::schema_manifest_resource_info(),
        McpState::schema_manifest_handler,
        None,
    )
}
