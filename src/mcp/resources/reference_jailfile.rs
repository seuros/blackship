//! What the Jailfile line format supports — and, more usefully, what it does not.
//!
//! The supported keyword list is derived from [`Instruction::name`] through an
//! exhaustive `match`, so adding an `Instruction` variant fails to compile
//! until it is listed here. The *unsupported* list is hand-written because
//! absences cannot be derived from code that does not contain them; it is
//! checked against the parser dispatch in `src/blueprint/parser.rs`.

use std::fmt::Write as _;

use mcp_host::prelude::*;
use mcp_host::registry::router::McpResourceRouter;

use super::super::McpState;
use crate::blueprint::instructions::{BuildArg, CopySpec, ExposePort, Instruction};

const URI: &str = "blackship:///reference/jailfile";

/// Dockerfile habits the line parser rejects, from the parser dispatch.
const UNSUPPORTED: &[(&str, &str)] = &[
    ("ADD", "use COPY"),
    ("SHELL", "RUN's shell is fixed"),
    ("HEALTHCHECK", "health checks live in blackship.toml"),
    ("STOPSIGNAL", "use STOP <command>"),
    (
        "JSON exec form",
        "`CMD [\"a\"]` is taken verbatim as a shell string, brackets included",
    ),
    ("--from=", "no build stages"),
    (
        "--chown=",
        "no COPY flags: line format chowns in a later RUN; TOML uses `owner`/`mode`",
    ),
    (
        "backslash line continuation",
        "a trailing `\\` is ignored; the next line parses as its own instruction",
    ),
];

impl McpState {
    /// The Jailfile keyword reference.
    #[mcp_resource(
        uri = "blackship:///reference/jailfile",
        name = "reference/jailfile",
        mime_type = "text/markdown",
        description = "Jailfile keywords, rejected Dockerfile constructs, TOML step order."
    )]
    async fn reference_jailfile(&self, _ctx: Ctx<'_>) -> ResourceResult {
        Ok(vec![text_resource_with_mime(
            URI,
            render(),
            "text/markdown",
        )])
    }
}

/// The TOML format has no instruction order of its own: `parse_toml_format`
/// emits its tables in one fixed sequence.
const TOML_ORDER: &str = "\n## TOML step order\n\n\
     Fixed, whatever the table order: `from`, `workdir`, `args`, `env`, all `run`, all \
     `copy`, `expose`. So `workdir` precedes every step (relative `copy` destinations \
     resolve against it), and no `run` sees a copied file: set `owner`/`mode` on the \
     copy, or use the line format, which keeps written order.\n";

/// Build the reference page.
fn render() -> String {
    let mut page = String::from(
        "# Jailfile reference\n\n\
         Two formats: line (Dockerfile-like) and TOML. Sniffed by a leading `[` or a \
         `[metadata]`/`[build]` anywhere, so a comment mentioning `[build]` misreads a line \
         Jailfile; pass `format` to `jailfile_validate`/`jailfile_inspect`. Only TOML has \
         `[metadata]`; the line format uses `LABEL`. TOML rejects unknown keys.\n\n\
         ## Line keywords\n\n",
    );

    for keyword in supported_keywords() {
        let _ = writeln!(page, "- `{keyword}`"); // fmt::Write into a String is infallible
    }
    page.push_str(
        "- `#` comment (kept as an instruction)\n\n\
         Case-insensitive; one instruction per line.\n\n\
         ## Rejected\n\n",
    );

    for (name, why) in UNSUPPORTED {
        let _ = writeln!(page, "- `{name}` — {why}"); // fmt::Write into a String is infallible
    }

    page.push_str(TOML_ORDER);
    page
}

/// Every line-format keyword, excluding the comment pseudo-instruction.
fn supported_keywords() -> Vec<&'static str> {
    [
        Instruction::From(String::new()),
        Instruction::Arg(BuildArg {
            name: String::new(),
            default: None,
        }),
        Instruction::Env(String::new(), String::new()),
        Instruction::Run(String::new()),
        Instruction::Copy(CopySpec::new("", "")),
        Instruction::Workdir(String::new()),
        Instruction::Expose(ExposePort {
            port: 0,
            protocol: String::new(),
        }),
        Instruction::Cmd(String::new()),
        Instruction::Entrypoint(String::new()),
        Instruction::Stop(String::new()),
        Instruction::User(String::new()),
        Instruction::Label(String::new(), String::new()),
        Instruction::Volume(String::new()),
    ]
    .iter()
    .map(keyword)
    .collect()
}

/// The keyword for an instruction.
///
/// The `match` is exhaustive on purpose: a new [`Instruction`] variant will
/// not compile until it is added here and to [`supported_keywords`].
const fn keyword(instruction: &Instruction) -> &'static str {
    match instruction {
        Instruction::From(_)
        | Instruction::Arg(_)
        | Instruction::Env(_, _)
        | Instruction::Run(_)
        | Instruction::Copy(_)
        | Instruction::Workdir(_)
        | Instruction::Expose(_)
        | Instruction::Cmd(_)
        | Instruction::Entrypoint(_)
        | Instruction::Stop(_)
        | Instruction::User(_)
        | Instruction::Label(_, _)
        | Instruction::Volume(_)
        | Instruction::Comment(_) => instruction.name(),
    }
}

pub fn mount(
    router: McpResourceRouter<McpState>,
) -> Result<McpResourceRouter<McpState>, AppsError> {
    Ok(router.with_resource(
        McpState::reference_jailfile_resource_info()?,
        McpState::reference_jailfile_handler,
        None,
    ))
}
