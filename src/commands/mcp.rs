//! MCP server command: stdio, or Streamable HTTP with `--listen`
//!
//! Does not load the manifest: the server must start in a directory that has
//! no `blackship.toml` yet, because authoring one is its purpose.

use std::path::Path;

use crate::error::Result;

pub fn handle(config_path: &Path, listen: Option<&str>) -> Result<()> {
    let transport = match listen {
        None => crate::mcp::Transport::Stdio,
        Some(addr) => crate::mcp::Transport::http(addr, std::env::var("BLACKSHIP_MCP_TOKEN").ok())?,
    };
    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(crate::mcp::serve(config_path, transport))
}
