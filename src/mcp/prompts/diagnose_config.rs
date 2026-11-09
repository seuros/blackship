//! Explain why a manifest or Jailfile is rejected, in the schema's own terms.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpPromptRouter;
use serde_json::Value;

use super::super::McpState;

impl McpState {
    /// Diagnose a configuration file and explain every diagnostic.
    #[mcp_prompt(
        name = "diagnose_config",
        description = "Explain why a blackship.toml or Jailfile is rejected. Read-only.",
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

        let validator = match kind {
            Some("manifest") => "`manifest_validate`",
            Some("jailfile") => "`jailfile_validate` (check `resolved_format`)",
            _ => "`manifest_validate` or `jailfile_validate`, by filename",
        };

        prompt_with_description(
            format!("Diagnose {path}"),
            vec![user_message(format!(
                "Diagnose `{path}`; read-only, write nothing. Run {validator}. Manifest \
                 `failed_stage`: `read` missing/unreadable, `parse` malformed TOML at the given \
                 line, `validate` semantic (name, duplicate, colliding full name, dependency). \
                 Explain each diagnostic against `blackship:///schema/*` and \
                 `blackship:///reference/*`; check host-dependent ones against \
                 `blackship:///host`. Give each fix as the exact key and value."
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
