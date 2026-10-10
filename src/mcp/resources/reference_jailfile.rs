//! What the Jailfile line format supports — and, more usefully, what it does not.
//!
//! The supported keyword list is derived from [`Instruction::name`] through an
//! exhaustive `match`, so adding an `Instruction` variant fails to compile
//! until it is listed here. The *unsupported* list is hand-written because
//! absences cannot be derived from code that does not contain them; it is
//! checked against the parser dispatch in `src/blueprint/parser.rs`.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpResourceRouter;

use super::super::McpState;
use crate::blueprint::instructions::{BuildArg, CopySpec, ExposePort, Instruction};

const URI: &str = "blackship:///reference/jailfile";

/// Dockerfile habits the line parser rejects, from the parser dispatch.
const UNSUPPORTED: &[(&str, &str)] = &[
    ("ADD", "no remote-fetch or auto-extract instruction exists; use COPY"),
    ("SHELL", "the shell used by RUN is not configurable"),
    ("HEALTHCHECK", "health checks live in blackship.toml, not the Jailfile"),
    ("STOPSIGNAL", "use STOP <command>, which runs a command before shutdown"),
    (
        "JSON exec form",
        "`CMD [\"a\", \"b\"]` is not parsed; the rest of the line is taken verbatim as a \
         shell command string, brackets and all",
    ),
    ("--from=", "COPY takes exactly <src> <dest>; there are no build stages"),
    ("--chown=", "COPY flags are not parsed; set ownership in a RUN step"),
    (
        "backslash line continuation",
        "a trailing `\\` is recognised and then ignored, so the next line is parsed as a \
         separate instruction and almost certainly fails. Keep every instruction on one line.",
    ),
];

impl McpState {
    /// The Jailfile keyword reference.
    #[mcp_resource(
        uri = "blackship:///reference/jailfile",
        name = "reference/jailfile",
        mime_type = "text/markdown",
        description = "The Jailfile line-format keywords blackship actually supports, and an \
                       explicit list of the Dockerfile constructs it does not (ADD, SHELL, \
                       HEALTHCHECK, STOPSIGNAL, JSON exec forms, COPY flags, line \
                       continuations). Read this before writing a Jailfile."
    )]
    async fn reference_jailfile(&self, _ctx: Ctx<'_>) -> ResourceResult {
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
        "# Jailfile reference\n\n\
         Two formats are accepted. The line-based format looks like a Dockerfile; the TOML \
         format is a table. `parse_jailfile` sniffs which one it is by looking for a leading \
         `[` or for the text `[metadata]` or `[build]` anywhere in the body, so a line-format \
         Jailfile that merely mentions `[build]` in a comment is misread as TOML. The \
         `jailfile_inspect` and `jailfile_validate` tools take an explicit `format` to \
         override that, and `jailfile_validate` reports which parser actually ran.\n\n\
         Only the TOML format can express a `[metadata]` table (name, version, description, \
         author, labels). The line format carries metadata through `LABEL` only.\n\n\
         ## Supported keywords (line format)\n\n",
    );

    for keyword in supported_keywords() {
        page.push_str(&format!("- `{keyword}`\n"));
    }
    page.push_str(
        "- `#` at the start of a line is a comment, and is preserved as an instruction.\n\n\
         Keywords are matched case-insensitively. Every instruction must fit on one line.\n\n\
         ## Not supported\n\n\
         A model reaching for Dockerfile habits will hit these. They are absences, not \
         aliases: the parser rejects the line outright.\n\n",
    );

    for (name, why) in UNSUPPORTED {
        page.push_str(&format!("- `{name}` — {why}\n"));
    }

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
fn keyword(instruction: &Instruction) -> &'static str {
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

pub fn mount(router: McpResourceRouter<McpState>) -> McpResourceRouter<McpState> {
    router.with_resource(
        McpState::reference_jailfile_resource_info(),
        McpState::reference_jailfile_handler,
        None,
    )
}
