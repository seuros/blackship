//! Explain why a manifest or Jailfile is rejected, in the schema's own terms.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpPromptRouter;
use serde_json::Value;

use super::super::McpState;

impl McpState {
    /// Diagnose a configuration file and explain every diagnostic.
    #[mcp_prompt(
        name = "diagnose_config",
        description = "Validate a blackship.toml or a Jailfile and explain each diagnostic \
                       against the schema and reference resources, without writing anything.",
        argument(
            name = "path",
            description = "Path to the blackship.toml or Jailfile to diagnose",
            required = true
        ),
        argument(
            name = "kind",
            description = "`manifest` or `jailfile`. Omit to decide from the filename."
        )
    )]
    async fn diagnose_config(&self, _ctx: Ctx<'_>, args: Value) -> PromptResult {
        let path = args
            .get("path")
            .and_then(|value| value.as_str())
            .unwrap_or("blackship.toml");
        let kind = args.get("kind").and_then(|value| value.as_str());

        let instruction = match kind {
            Some("manifest") => "This file is a manifest. Call `manifest_validate` with `path` \
                                 set to it."
                .to_string(),
            Some("jailfile") => "This file is a Jailfile. Call `jailfile_validate` with `path` \
                                 set to it, and read `resolved_format` before trusting any \
                                 diagnostic; re-run with an explicit `format` if the sniffer \
                                 picked the wrong parser."
                .to_string(),
            _ => "Decide from the filename which it is: `blackship.toml` and other manifests go \
                  to `manifest_validate`, a `Jailfile` goes to `jailfile_validate`. If the name \
                  is ambiguous, try `manifest_validate` first and say which you chose."
                .to_string(),
        };

        prompt_with_description(
            format!("Diagnose {path}"),
            vec![user_message(format!(
                "Diagnose the blackship configuration at `{path}`. Change nothing: this is a \
                 read-only task, and the creating tools are not part of it.\n\n\
                 1. {instruction}\n\
                 2. For a manifest, note the `failed_stage`. `read` means the file is missing or \
                 unreadable, `parse` means the TOML itself is malformed and the line and column \
                 point at it, and `validate` means it parsed but the semantics are wrong — a bad \
                 name, a duplicate jail, a colliding project-prefixed full name, an unknown or \
                 self-referential dependency.\n\
                 3. Explain every diagnostic in terms of the schema. Quote the relevant key from \
                 `blackship:///schema/manifest` or `blackship:///schema/jailfile`, and cite \
                 `blackship:///reference/jailfile` for a Jailfile construct that does not \
                 exist and `blackship:///reference/jail-params` for a jail parameter.\n\
                 4. Call `host_facts` when a diagnostic is about something host-dependent — a \
                 release that is not bootstrapped, a pool that is not imported, an rctl limit on \
                 a host where rctl is off.\n\
                 5. Propose a concrete fix for each problem, as the exact key and value to \
                 change. Do not write the file; if the operator wants it written, that is \
                 `manifest_create` or `jailfile_create` and a separate approval."
            ))],
        )
    }
}

pub fn mount(router: McpPromptRouter<McpState>) -> McpPromptRouter<McpState> {
    router.with_prompt(
        McpState::diagnose_config_prompt_info(),
        McpState::diagnose_config_handler,
        None,
    )
}
