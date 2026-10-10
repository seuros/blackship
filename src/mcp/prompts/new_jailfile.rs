//! Author a Jailfile without reaching for Dockerfile habits.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpPromptRouter;
use serde_json::Value;

use super::super::McpState;

impl McpState {
    /// Author a TOML Jailfile for one jail.
    #[mcp_prompt(
        name = "new_jailfile",
        description = "Author a Jailfile for one jail: gather real host facts, read the Jailfile \
                       reference, draft, validate, then ask the operator to approve the write.",
        argument(
            name = "goal",
            description = "What the jail should build and run, in a sentence or two",
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
                "Author a Jailfile at `{path}` that builds and runs: {goal}\n\n\
                 Follow this order and do not skip a step.\n\n\
                 1. Call `host_facts` and use only a release it lists under \
                 `releases.bootstrapped` as the base. A release that is not bootstrapped cannot \
                 be built from on this host.\n\
                 2. Read `blackship:///reference/jailfile` before writing anything. A Jailfile \
                 is not a Dockerfile: ADD, SHELL, HEALTHCHECK, STOPSIGNAL, JSON exec forms, COPY \
                 flags such as `--from=` or `--chown=`, and backslash line continuations do not \
                 exist. Do not use them and do not tell the operator they will work.\n\
                 3. Read `blackship:///schema/jailfile` for the fields `jailfile_create` takes. \
                 It emits the TOML format, which is the only one that can carry a `[metadata]` \
                 table. A field missing from that schema is a field the format cannot express — \
                 volumes, for instance, belong in the manifest, not here.\n\
                 4. Draft the Jailfile and show it to the operator.\n\
                 5. If a Jailfile already exists at `{path}`, call `jailfile_validate` on it \
                 first, with an explicit `format`, so you know what you are proposing to \
                 replace.\n\
                 6. Call `jailfile_create` with `path` set to `{path}`. It parses the rendered \
                 text before writing and then asks the operator to approve.\n\
                 7. Read the result. `written: false` means nothing was written: report the \
                 `reason` and the diagnostics verbatim. If the operator declined, stop.\n\n\
                 Mention how the jail is wired into a manifest: a `[[jails]]` entry pointing at \
                 this file through `build` (its directory) or `jailfile` (this exact path)."
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
