//! The `jail_set` parameters a manifest may not set, and why.
//!
//! The names come from `crate::sys::consts::JAIL_PARAM_*`, which `build/sys_consts.c`
//! emits from `<sys/jail.h>`, so they track the headers blackship was built
//! against. Membership is confirmed through
//! [`crate::bridge::lifecycle::is_reserved_param`], the same predicate the jail
//! builder uses, so this page cannot drift from enforcement.

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
            "derived from the project prefix and the jail's manifest name; overriding it \
             would detach the jail from its record",
        ),
        (
            consts::JAIL_PARAM_PATH,
            "the jail root, computed from data_dir or the ZFS dataset. A manifest-chosen \
             path could point the jail at / and defeat the chroot entirely",
        ),
        (consts::JAIL_PARAM_ERRMSG, "an output parameter; the kernel writes it"),
        (
            consts::JAIL_PARAM_PERSIST,
            "owned by the lifecycle state machine; forcing it would strand jails that \
             blackship believes it stopped",
        ),
        (consts::JAIL_PARAM_NOPERSIST, "the inverse of persist, same reason"),
        (
            consts::JAIL_PARAM_SECURELEVEL,
            "a security floor. A manifest lowering it would weaken the kernel's own \
             restrictions on the jail",
        ),
        (
            consts::JAIL_PARAM_DEVFS_RULESET,
            "controls which device nodes the jail can see. A permissive ruleset hands the \
             jail raw disk and memory devices, which is a complete escape",
        ),
        (
            consts::JAIL_PARAM_ENFORCE_STATFS,
            "controls filesystem visibility outside the jail root",
        ),
        (
            consts::JAIL_PARAM_CHILDREN_MAX,
            "nested-jail budget; raising it lets a jail create children blackship does not \
             account for",
        ),
        (
            consts::JAIL_PARAM_HOST_HOSTNAME,
            "set from the jail definition so the hostname matches the record",
        ),
        (
            consts::JAIL_PARAM_IP4_ADDR,
            "set by the network layer from the jail's addresses; a manifest-chosen address \
             could claim another jail's or the host's IP",
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
        description = "The jail_set(2) parameters a blackship manifest may not set, taken \
                       from <sys/jail.h>, plus the rule that every `allow.*` parameter is \
                       reserved by prefix. Explains why each one would bypass jail \
                       isolation if a manifest could override it."
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
         A jail definition in `blackship.toml` may carry extra `jail_set(2)` parameters. \
         The ones below are refused: blackship computes them itself from the manifest, the \
         network layer, and the lifecycle state machine. A manifest that could set them \
         would be able to point a jail at the host's filesystem, hand it the host's \
         addresses, widen its devfs view, or lower its securelevel — that is, bypass the \
         isolation the jail exists to provide. A reserved key in a manifest is dropped with \
         a warning, not silently honoured.\n\n\
         ## Reserved by name\n\n\
         Taken from `<sys/jail.h>` at build time, so this list reflects the headers this \
         binary was compiled against.\n\n",
    );

    for (name, why) in reserved() {
        let enforced = if is_reserved_param(name) {
            ""
        } else {
            " (NOT currently enforced — report this)"
        };
        page.push_str(&format!("- `{name}` — {why}{enforced}\n"));
    }

    page.push_str(
        "\n## Reserved by prefix\n\n\
         Every parameter starting with `allow.` is reserved, including ones not listed \
         above and ones that do not exist yet. `allow.*` parameters are registered by \
         kernel modules as runtime sysctl entries, so no header can enumerate them and no \
         fixed list can stay complete. They are exactly the switches that relax jail \
         confinement — `allow.mount`, `allow.raw_sockets`, `allow.sysvipc` — so the safe \
         rule is to reserve the whole prefix rather than chase additions.\n\n\
         ## What to do instead\n\n\
         Use the first-class fields of the jail definition (addresses, hostname, root, \
         resource limits) and let blackship translate them. Pass extra parameters only for \
         things outside that set.\n",
    );

    page
}

pub fn mount(router: McpResourceRouter<McpState>) -> McpResourceRouter<McpState> {
    router.with_resource(
        McpState::reference_jail_params_resource_info(),
        McpState::reference_jail_params_handler,
        None,
    )
}
