//! Bootstrap a `blackship.toml` for a host nobody has described yet.
//!
//! The prompt carries the procedure, because the tools cannot: a model that
//! drafts before calling `host_facts` will invent releases and pools that do
//! not exist on this machine.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpPromptRouter;
use serde_json::Value;

use super::super::McpState;

impl McpState {
    /// Author a new project manifest, host facts first.
    #[mcp_prompt(
        name = "new_project",
        description = "Author a new blackship.toml for this host: gather real host facts, draft \
                       a manifest, validate it, then ask the operator to approve the write.",
        argument(
            name = "goal",
            description = "What the project should run, in a sentence or two",
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
            Some(path) => format!("Write the manifest to `{path}`."),
            None => format!(
                "Write the manifest to the server's configured path, {}, by omitting `path`.",
                self.config_path.display()
            ),
        };

        prompt_with_description(
            format!("Author a blackship.toml for: {goal}"),
            vec![user_message(format!(
                "Author a blackship.toml for this host. The project should run: {goal}\n\n\
                 Follow this order and do not skip a step.\n\n\
                 1. Call `host_facts`. Treat its answer as the only source of truth about this \
                 machine. Use only releases it lists under `releases.bootstrapped`, only ZFS \
                 pools it lists under `zfs.host_pools`, and only resource limits it says rctl \
                 can apply. If `rctl.enabled` is false, say so and leave resource limits out \
                 except `cores`/`cpuset`, which work anyway. If `config_source` is `defaults`, \
                 say plainly that no manifest exists yet and that every path shown is a default \
                 rather than a configured value.\n\
                 2. Read `blackship:///schema/manifest` to see exactly which keys \
                 `manifest_create` accepts. Keys outside that subset are hand-edited later; do \
                 not pretend the tool takes them.\n\
                 3. Draft the manifest and show it to the operator, naming which choices came \
                 from `host_facts` and which are your judgement.\n\
                 4. If a manifest already exists at the target path, call `manifest_validate` on \
                 it first so you are not proposing to replace something that works.\n\
                 5. Call `manifest_create`. It renders and validates before writing, and then \
                 asks the operator to approve. {target}\n\
                 6. Read the result. `written: false` means nothing was written: report the \
                 `reason` or the `validation` diagnostics verbatim. If the operator declined, \
                 stop; do not re-propose the same file.\n\n\
                 Do not invent a release, a pool, a bridge, or an interface that `host_facts` \
                 did not report."
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
