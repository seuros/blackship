//! Prompt router, auto-mounted from `src/mcp/prompts/`.
//!
//! Every file in that directory exposes one `pub fn mount(router) -> router`.
//! Adding or removing a file requires touching this file so the macro
//! re-expands; content edits are tracked for you.

use super::McpState;

mcp_host::auto_prompts!(McpState, "src/mcp/prompts");
