//! `blackship:///host`: the host profile as a resource, so a client can put
//! it in front of the model before any tool call.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpResourceRouter;

use super::super::McpState;

const URI: &str = "blackship:///host";

impl McpState {
    /// What this host is and has room for.
    #[mcp_resource(
        uri = "blackship:///host",
        name = "host",
        mime_type = "application/json",
        description = "Live host profile: FreeBSD version and kernel features, CPU, memory and jail claims, ZFS capacity, networks and free addresses, PF and NAT egress, releases, jails, host tools."
    )]
    async fn host(&self, _ctx: Ctx<'_>) -> ResourceResult {
        let profile = serde_json::to_string(&crate::host_profile::collect(&self.config_path))
            .map_err(|e| ResourceError::Internal(format!("Failed to serialize host profile: {e}")))?;
        Ok(vec![text_resource_with_mime(URI, profile, "application/json")])
    }
}

pub fn mount(
    router: McpResourceRouter<McpState>,
) -> Result<McpResourceRouter<McpState>, AppsError> {
    Ok(router.with_resource(McpState::host_resource_info()?, McpState::host_handler, None))
}
