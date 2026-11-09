//! Bootstrap a `blackship.toml` for a host nobody has described yet.
//!
//! The prompt carries the procedure, because the tools cannot: a model that
//! drafts before reading `blackship:///host` will invent releases and pools that do
//! not exist on this machine.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpPromptRouter;
use serde_json::Value;

use super::super::McpState;

impl McpState {
    /// Author a new project manifest, host facts first.
    #[mcp_prompt(
        name = "new_project",
        description = "Author a blackship.toml for this host.",
        argument(
            name = "goal",
            description = "What the project should run",
            required = true
        ),
        argument(
            name = "path",
            description = "Where to write the manifest. Defaults to the server's configured \
                           manifest path."
        )
    )]
    async fn new_project(&self, _ctx: Ctx<'_>, args: Value) -> PromptResult {
        let goal = args
            .get("goal")
            .and_then(|value| value.as_str())
            .unwrap_or("an unspecified workload");
        let path = args.get("path").and_then(|value| value.as_str());

        let target = match path {
            Some(path) => format!("Target: `{path}`."),
            None => format!(
                "Target: {} (omit `path`).",
                self.config_path.display()
            ),
        };

        prompt_with_description(
            format!("Author a blackship.toml for: {goal}"),
            vec![user_message(format!(
                "Author a blackship.toml for: {goal}\n\
                 Plan against `blackship:///host`: bootstrapped releases, pools, rctl, \
                 uncommitted memory, free addresses. `config.source` = `defaults` means no \
                 manifest exists yet. `manifest_create` accepts only \
                 `blackship:///schema/manifest`; anything else is hand-edited later. \
                 Validate an existing file at the target before proposing to replace it. \
                 {target} On `written: false`, report `reason` or the diagnostics; a declined \
                 write is final."
            ))],
        )
    }
}

pub fn mount(router: McpPromptRouter<McpState>) -> McpPromptRouter<McpState> {
    router.with_prompt(
        McpState::new_project_prompt_info(),
        McpState::new_project_handler,
        None,
    )
}
