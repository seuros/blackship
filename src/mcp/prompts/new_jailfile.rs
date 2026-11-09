//! Author a Jailfile without reaching for Dockerfile habits.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpPromptRouter;
use serde_json::Value;

use super::super::McpState;

impl McpState {
    /// Author a TOML Jailfile for one jail.
    #[mcp_prompt(
        name = "new_jailfile",
        description = "Author a Jailfile.",
        argument(
            name = "goal",
            description = "What the jail should build and run",
            required = true
        ),
        argument(
            name = "path",
            description = "Where to write the Jailfile, for example `./web/Jailfile`",
            required = true
        )
    )]
    async fn new_jailfile(&self, _ctx: Ctx<'_>, args: Value) -> PromptResult {
        let goal = args
            .get("goal")
            .and_then(|value| value.as_str())
            .unwrap_or("an unspecified workload");
        let path = args
            .get("path")
            .and_then(|value| value.as_str())
            .unwrap_or("./Jailfile");

        prompt_with_description(
            format!("Author a Jailfile for: {goal}"),
            vec![user_message(format!(
                "Author a Jailfile at `{path}` for: {goal}\n\
                 Base it on a release in `blackship:///host` `releases.bootstrapped`. Jailfiles \
                 are not Dockerfiles: read `blackship:///reference/jailfile` (unsupported \
                 constructs, fixed TOML step order). `jailfile_create` emits TOML per \
                 `blackship:///schema/jailfile`; volumes belong in the manifest. Validate an \
                 existing file at `{path}` first, with an explicit `format`. On \
                 `written: false`, report `reason` and diagnostics; a declined write is final. \
                 Show the `[[jails]]` entry that wires it in (`build` = directory, `jailfile` = \
                 path)."
            ))],
        )
    }
}

pub fn mount(router: McpPromptRouter<McpState>) -> McpPromptRouter<McpState> {
    router.with_prompt(
        McpState::new_jailfile_prompt_info(),
        McpState::new_jailfile_handler,
        None,
    )
}
