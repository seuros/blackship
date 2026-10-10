//! The blackship manual, rendered from the live CLI spec.
//!
//! Nothing here enumerates commands: the page is walked out of
//! [`crate::cli::Cli::command`], so a subcommand added to `src/cli.rs` appears
//! in the manual the day it is added.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpResourceRouter;
use usage_rs::Command;
use usage_rs::help::Style;

use super::super::McpState;

const URI: &str = "blackship:///man";

/// Separator between pages. Wide enough to be unmistakable in a wrapped body.
const RULE: &str = "\n\n================================================================\n";

impl McpState {
    /// The full command manual.
    #[mcp_resource(
        uri = "blackship:///man",
        name = "man",
        mime_type = "text/plain",
        description = "The complete blackship command manual: long help for the root command \
                       and for every subcommand, recursively, generated from the live CLI \
                       spec. Read this before proposing any blackship invocation."
    )]
    async fn man(&self, _ctx: Ctx<'_>) -> ResourceResult {
        Ok(vec![text_resource_with_mime(
            URI,
            render_manual(),
            "text/plain",
        )])
    }
}

/// Concatenate long help for the whole command tree, depth first.
fn render_manual() -> String {
    let root = crate::cli::Cli::command();
    let mut page = String::new();
    append_command(&mut page, root, &[]);
    page
}

/// Render `cmd`, then each of its subcommands, tracking the path for headings.
fn append_command(page: &mut String, cmd: &Command<'_>, ancestors: &[&str]) {
    let mut path: Vec<&str> = ancestors.to_vec();
    path.push(cmd.name);

    if !page.is_empty() {
        page.push_str(RULE);
    }
    page.push_str(&format!("# {}\n\n", path.join(" ")));

    match crate::cli::Cli::render_help_styled(cmd, true, Style::PLAIN) {
        Some(help) => page.push_str(help.trim_end()),
        None => page.push_str("(no help page available for this command)"),
    }
    page.push('\n');

    for sub in cmd.subcommands {
        append_command(page, sub, &path);
    }
}

pub fn mount(router: McpResourceRouter<McpState>) -> McpResourceRouter<McpState> {
    router.with_resource(McpState::man_resource_info(), McpState::man_handler, None)
}

#[cfg(test)]
#[path = "man/tests.rs"]
mod tests;
