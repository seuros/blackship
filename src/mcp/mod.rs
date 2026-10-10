//! MCP stdio server for authoring and validating jail configuration.
//!
//! Stdout belongs to the JSON-RPC frame stream, so nothing in this module or
//! anything it reaches may print to it. Diagnostics go to a log file under the
//! XDG state directory.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mcp_host::prelude::*;
use mcp_host::registry::router::{McpResourceTemplateRouter, McpRouter};

use crate::error;
use crate::error::Result;

mod elicit;
mod prompts;
mod resources;
mod tools;

/// Shared state handed to tool, prompt, and resource handlers.
pub(crate) struct McpState {
    config_path: PathBuf,
}

impl McpState {
    /// Combine the auto-mounted tool, prompt, and resource routers.
    ///
    /// Resource templates stay empty: every resource here has a fixed URI.
    fn router() -> McpRouter<Self> {
        McpRouter::new(
            tools::router(),
            prompts::router(),
            resources::router(),
            McpResourceTemplateRouter::new(),
        )
    }
}

const INSTRUCTIONS: &str = "This server authors and validates blackship jail configuration for \
     FreeBSD hosts. Start from a prompt rather than a bare tool call: \
     `new_project` authors a blackship.toml, `new_jailfile` authors a Jailfile, \
     and `diagnose_config` explains why an existing file is rejected. Each one \
     names the tools to call and the order to call them in. Read the \
     `blackship:///man` resource for the command surface, and \
     `blackship:///schema/manifest` and `blackship:///schema/jailfile` for \
     exactly what the creating tools accept. Call `host_facts` before drafting \
     any configuration, so that releases, interfaces, datasets, and resource \
     limits match the real host instead of guesses. Validate every draft before \
     writing it to disk. Creating or modifying files asks the operator for \
     approval through elicitation, so expect a confirmation step and do not \
     retry a declined write.";

/// Run the MCP server over stdio until the client closes the connection.
pub(crate) async fn serve(config_path: &Path) -> Result<()> {
    init_logging();

    let state = Arc::new(McpState {
        config_path: config_path.to_path_buf(),
    });

    let server = Server::builder("blackship", env!("CARGO_PKG_VERSION"))
        .with_instructions(INSTRUCTIONS)
        .with_tools(true)
        .with_prompts(true)
        .with_resources(true, false)
        .build();

    server.register_router(McpState::router(), state);

    tracing::info!(
        tools = server.tool_registry().list().len(),
        resources = server.resource_manager().list().len(),
        "blackship MCP server starting on stdio"
    );

    server
        .run(StdioTransport::new())
        .await
        .map_err(|e| error::Error::User(format!("MCP server failed: {e}")))
}

/// Install a file-backed tracing subscriber, or none at all.
///
/// A missing or unwritable log directory is not fatal: the server runs without
/// diagnostics rather than refusing to start.
fn init_logging() {
    let dir = crate::manifest::get_xdg_data_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }

    let Ok(file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("mcp.log"))
    else {
        return;
    };

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let _ = tracing_subscriber::fmt()
        .with_writer(file)
        .with_ansi(false)
        .with_env_filter(filter)
        .try_init();
}
