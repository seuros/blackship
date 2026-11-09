//! The `jail_set` parameters a manifest may not set, and why.
//!
//! The names come from `crate::sys::consts::JAIL_PARAM_*`, which `build/sys_consts.c`
//! emits from `<sys/jail.h>`, so they track the headers blackship was built
//! against. Membership is confirmed through
//! [`crate::bridge::lifecycle::is_reserved_param`], the same predicate the jail
//! builder uses, so this page cannot drift from enforcement.

use std::fmt::Write as _;

use mcp_host::prelude::*;
use mcp_host::registry::router::McpResourceRouter;

use super::super::McpState;
use crate::bridge::lifecycle::is_reserved_param;
use crate::sys::consts;

const URI: &str = "blackship:///reference/jail-params";

/// Each reserved parameter with the reason a manifest cannot set it.
fn reserved() -> Vec<(&'static str, &'static str)> {
    vec![
        (consts::JAIL_PARAM_JID, "assigned by the kernel"),
        (
            consts::JAIL_PARAM_NAME,
            "project prefix + manifest name; overriding detaches the jail from its record",
        ),
        (
            consts::JAIL_PARAM_PATH,
            "jail root from data_dir or the dataset; `/` would defeat the chroot",
        ),
        (consts::JAIL_PARAM_ERRMSG, "an output parameter; the kernel writes it"),
        (
            consts::JAIL_PARAM_PERSIST,
            "owned by the lifecycle; forcing it strands jails blackship thinks stopped",
        ),
        (consts::JAIL_PARAM_NOPERSIST, "the inverse of persist, same reason"),
        (
            consts::JAIL_PARAM_SECURELEVEL,
            "security floor; lowering it weakens kernel restrictions",
        ),
        (
            consts::JAIL_PARAM_DEVFS_RULESET,
            "device visibility; a permissive ruleset exposes raw disk and memory: escape",
        ),
        (
            consts::JAIL_PARAM_ENFORCE_STATFS,
            "controls filesystem visibility outside the jail root",
        ),
        (
            consts::JAIL_PARAM_CHILDREN_MAX,
            "nested-jail budget; raising it creates unaccounted children",
        ),
        (
            consts::JAIL_PARAM_HOST_HOSTNAME,
            "from the jail definition",
        ),
        (
            consts::JAIL_PARAM_IP4_ADDR,
            "set by the network layer; could claim another jail's or the host's address",
        ),
        (consts::JAIL_PARAM_IP6_ADDR, "same as ip4.addr"),
        (
            consts::JAIL_PARAM_VNET,
            "decides whether the jail gets its own network stack, which the network layer \
             must agree with",
        ),
    ]
}

impl McpState {
    /// The reserved jail parameter reference.
    #[mcp_resource(
        uri = "blackship:///reference/jail-params",
        name = "reference/jail-params",
        mime_type = "text/markdown",
        description = "jail_set(2) parameters a manifest may not set (all `allow.*` by prefix), and why."
    )]
    async fn reference_jail_params(&self, _ctx: Ctx<'_>) -> ResourceResult {
        Ok(vec![text_resource_with_mime(
            URI,
            render(),
            "text/markdown",
        )])
    }
}

/// Build the reference page.
fn render() -> String {
    let mut page = String::from(
        "# Reserved jail parameters\n\n\
         Manifest `params` cannot set these; blackship derives them. A reserved key is \
         dropped with a warning.\n\n\
         ## By name (from `<sys/jail.h>` at build time)\n\n",
    );

    for (name, why) in reserved() {
        let enforced = if is_reserved_param(name) {
            ""
        } else {
            " (NOT currently enforced — report this)"
        };
        let _ = writeln!(page, "- `{name}` — {why}{enforced}"); // fmt::Write into a String is infallible
    }

    page.push_str(
        "\n## By prefix\n\n\
         Every `allow.*`: kernel modules register them at runtime, so no list is complete, \
         and each one relaxes confinement.\n\n\
         Use the first-class jail fields (addresses, hostname, root, limits) instead.\n",
    );

    page
}

pub fn mount(
    router: McpResourceRouter<McpState>,
) -> Result<McpResourceRouter<McpState>, AppsError> {
    Ok(router.with_resource(
        McpState::reference_jail_params_resource_info()?,
        McpState::reference_jail_params_handler,
        None,
    ))
}
