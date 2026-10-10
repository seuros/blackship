//! The CLI spec as KDL.
//!
//! This is what `usage g markdown|manpage` and the completion generators read,
//! so a tool that wants structured argument data should take this rather than
//! scraping `blackship:///man`.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpResourceRouter;

use super::super::McpState;

const URI: &str = "blackship:///man.kdl";

impl McpState {
    /// The CLI spec in KDL form.
    #[mcp_resource(
        uri = "blackship:///man.kdl",
        name = "man.kdl",
        mime_type = "application/kdl",
        description = "The blackship CLI spec as KDL, machine-readable. This is the input \
                       `usage g markdown|manpage` and the shell-completion generators read, \
                       so prefer it over the rendered manual when you need structured flag \
                       and argument data."
    )]
    async fn man_kdl(&self, _ctx: Ctx<'_>) -> ResourceResult {
        Ok(vec![text_resource_with_mime(
            URI,
            crate::cli::Cli::to_kdl(),
            "application/kdl",
        )])
    }
}

pub fn mount(router: McpResourceRouter<McpState>) -> McpResourceRouter<McpState> {
    router.with_resource(
        McpState::man_kdl_resource_info(),
        McpState::man_kdl_handler,
        None,
    )
}
