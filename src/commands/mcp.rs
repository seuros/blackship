//! MCP stdio server command
//!
//! Does not load the manifest: the server must start in a directory that has
//! no `blackship.toml` yet, because authoring one is its purpose.

use std::path::Path;

use crate::error::Result;

pub fn handle(config_path: &Path) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(crate::mcp::serve(config_path))
}
