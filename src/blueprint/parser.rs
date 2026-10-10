//! Jailfile parsing
//!
//! Supports two formats:
//! 1. Line-based format (similar to Dockerfile)
//! 2. TOML format

use crate::blueprint::instructions::{
    BuildArg, CopySpec, ExposePort, Instruction, Jailfile, JailfileMetadata,
};
use crate::error::{Error, Result};
use nom::{
    Parser,
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_till, take_while1},
    character::complete::{char, space0, space1},
    combinator::{map, opt, rest},
    sequence::{delimited, pair, preceded},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Which parser to use for a Jailfile
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum JailfileFormat {
    /// Sniff the content and pick a parser
    #[default]
    Auto,
    /// Always use the line-based (Dockerfile-like) parser
    Line,
    /// Always use the TOML parser
    Toml,
}

/// A single parse problem, with 1-based position
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Diagnostic {
    /// 1-based line number
    pub line: usize,
    /// 1-based column of the first non-whitespace character
    pub column: usize,
    /// Human-readable description of the problem
    pub message: String,
}

/// Parse a Jailfile (auto-detects format)
pub fn parse_jailfile(content: &str) -> Result<Jailfile> {
    parse_jailfile_as(content, JailfileFormat::Auto)
}

/// Parse a Jailfile with an explicit format, bypassing the sniffer
pub(crate) fn parse_jailfile_as(content: &str, format: JailfileFormat) -> Result<Jailfile> {
    match resolve_format(content, format) {
        JailfileFormat::Toml => parse_toml_format(content),
        _ => parse_line_format(content),
    }
}

/// Resolve `Auto` to a concrete format by sniffing the content
///
/// The sniff is textual, so a line-format Jailfile whose body merely mentions
/// `[build]` or `[metadata]` is misrouted to the TOML parser. Callers that
/// report which parser ran need this to be visible.
pub(crate) fn resolve_format(content: &str, format: JailfileFormat) -> JailfileFormat {
    match format {
        JailfileFormat::Auto => {
            let trimmed = content.trim();
            if trimmed.starts_with('[')
                || trimmed.contains("[metadata]")
                || trimmed.contains("[build]")
            {
                JailfileFormat::Toml
            } else {
                JailfileFormat::Line
            }
        }
        explicit => explicit,
    }
}

/// Collect every parse problem in `content` in a single pass
///
/// Returns an empty vector when `content` parses cleanly. The line format
/// reports one diagnostic per bad line; TOML can only report its first error.
#[cfg_attr(
    all(not(test), not(feature = "mcp")),
    expect(
        dead_code,
        reason = "the MCP jailfile_validate tool is this function's only caller"
    )
)]
pub(crate) fn diagnose(content: &str, format: JailfileFormat) -> Vec<Diagnostic> {
    match resolve_format(content, format) {
        JailfileFormat::Toml => diagnose_toml(content),
        _ => diagnose_line_format(content),
    }
}

fn diagnose_line_format(content: &str) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    for (index, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Err(e) = parse_line(line) {
            diagnostics.push(Diagnostic {
                line: index + 1,
                column: raw.chars().take_while(|c| c.is_whitespace()).count() + 1,
                message: e.to_string(),
            });
        }
    }

    diagnostics
}

fn diagnose_toml(content: &str) -> Vec<Diagnostic> {
    match toml::from_str::<TomlJailfile>(content) {
        Ok(_) => Vec::new(),
        Err(e) => {
            let (line, column) = e
                .span()
                .map_or((1, 1), |span| byte_offset_to_position(content, span.start));
            vec![Diagnostic {
                line,
                column,
                message: e.message().to_string(),
            }]
        }
    }
}

/// Convert a byte offset into a 1-based (line, column) pair
fn byte_offset_to_position(content: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut column = 1;

    for (index, ch) in content.char_indices() {
        if index >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }

    (line, column)
}

/// Parse line-based format (Dockerfile-like)
pub fn parse_line_format(content: &str) -> Result<Jailfile> {
    let mut jailfile = Jailfile::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines
        if line.is_empty() {
            continue;
        }

        // Handle comments
        if let Some(comment) = line.strip_prefix('#') {
            jailfile
                .instructions
                .push(Instruction::Comment(comment.trim().to_string()));
            continue;
        }

        // Handle line continuation (not fully implemented, but recognized)
        if line.ends_with('\\') {
            // For now, just strip the backslash and continue
            // A full implementation would concatenate with next line
        }

        // Parse instruction
        if let Some(instruction) = parse_line(line)? {
            // Update Jailfile state based on instruction
            match &instruction {
                Instruction::From(release) => {
                    jailfile.from = Some(release.clone());
                }
                Instruction::Arg(arg) => {
                    jailfile.args.push(arg.clone());
                }
                Instruction::Env(name, value) => {
                    jailfile.env.insert(name.clone(), value.clone());
                }
                Instruction::Workdir(path) => {
                    jailfile.workdir = Some(path.clone());
                }
                Instruction::Expose(port) => {
                    jailfile.expose.push(port.clone());
                }
                Instruction::Cmd(cmd) => {
                    jailfile.cmd = Some(cmd.clone());
                }
                Instruction::Entrypoint(cmd) => {
                    jailfile.entrypoint = Some(cmd.clone());
                }
                Instruction::Stop(cmd) => {
                    jailfile.stop = Some(cmd.clone());
                }
                Instruction::User(user) => {
                    jailfile.user = Some(user.clone());
                }
                Instruction::Volume(path) => {
                    jailfile.volumes.push(path.clone());
                }
                _ => {}
            }

            jailfile.instructions.push(instruction);
        }
    }

    Ok(jailfile)
}

/// Parse a single line instruction
fn parse_line(line: &str) -> Result<Option<Instruction>> {
    if line.is_empty() {
        return Ok(None);
    }

    if let Some(text) = line.strip_prefix('#') {
        return Ok(Some(Instruction::Comment(text.trim().to_string())));
    }

    let result = alt((
        map(parse_from, |r| Some(Instruction::From(r.to_string()))),
        map(parse_arg, Some),
        map(parse_env, |(k, v)| {
            Some(Instruction::Env(k.to_string(), v.to_string()))
        }),
        map(parse_run, |c| Some(Instruction::Run(c.to_string()))),
        map(parse_copy, Some),
        map(parse_workdir, |p| Some(Instruction::Workdir(p.to_string()))),
        map(parse_expose, Some),
        map(parse_cmd, |c| Some(Instruction::Cmd(c.to_string()))),
        map(parse_entrypoint, |c| {
            Some(Instruction::Entrypoint(c.to_string()))
        }),
        map(parse_stop, |c| Some(Instruction::Stop(c.to_string()))),
        map(parse_user, |u| Some(Instruction::User(u.to_string()))),
        map(parse_label, |(k, v)| {
            Some(Instruction::Label(k.to_string(), v.to_string()))
        }),
        map(parse_volume, |p| Some(Instruction::Volume(p.to_string()))),
    ))
    .parse(line);

    match result {
        Ok((_, instruction)) => Ok(instruction),
        Err(_) => Err(Error::TemplateParseFailed(format!(
            "Unknown instruction: {line}"
        ))),
    }
}

// Nom parsers for each instruction type

fn parse_from(input: &str) -> nom::IResult<&str, &str> {
    preceded(
        pair(tag_no_case("FROM"), space1),
        take_while1(|c: char| !c.is_whitespace()),
    )
    .parse(input)
}

fn parse_arg(input: &str) -> nom::IResult<&str, Instruction> {
    let (input, _) = tag_no_case("ARG").parse(input)?;
    let (input, _) = space1.parse(input)?;
    let (input, name) = take_while1(|c: char| c.is_alphanumeric() || c == '_').parse(input)?;
    let (input, default) = opt(preceded(char('='), rest)).parse(input)?;

    Ok((
        input,
        Instruction::Arg(BuildArg {
            name: name.to_string(),
            default: default.map(|s: &str| s.trim().to_string()),
        }),
    ))
}

fn parse_env(input: &str) -> nom::IResult<&str, (&str, &str)> {
    let (input, _) = tag_no_case("ENV").parse(input)?;
    let (input, _) = space1.parse(input)?;
    let (input, name) = take_while1(|c: char| c.is_alphanumeric() || c == '_').parse(input)?;
    let (input, _) = alt((tag("="), preceded(space0, tag(" ")))).parse(input)?;
    let (input, value) = rest.parse(input)?;

    Ok((input, (name, value.trim())))
}

/// Parse a line starting with `keyword` followed by whitespace, returning the rest
fn parse_keyword_rest<'a>(keyword: &str, input: &'a str) -> nom::IResult<&'a str, &'a str> {
    preceded(pair(tag_no_case(keyword), space1), rest).parse(input)
}

fn parse_run(input: &str) -> nom::IResult<&str, &str> {
    parse_keyword_rest("RUN", input)
}

fn parse_copy(input: &str) -> nom::IResult<&str, Instruction> {
    let (input, _) = tag_no_case("COPY").parse(input)?;
    let (input, _) = space1.parse(input)?;

    // Parse source and destination
    let (input, src) = take_while1(|c: char| !c.is_whitespace()).parse(input)?;
    let (input, _) = space1.parse(input)?;
    let (input, dest) = rest.parse(input)?;

    Ok((input, Instruction::Copy(CopySpec::new(src, dest.trim()))))
}

fn parse_workdir(input: &str) -> nom::IResult<&str, &str> {
    parse_keyword_rest("WORKDIR", input)
}

fn parse_expose(input: &str) -> nom::IResult<&str, Instruction> {
    let (input, _) = tag_no_case("EXPOSE").parse(input)?;
    let (input, _) = space1.parse(input)?;
    let (input, port_str) = rest.parse(input)?;

    let port = ExposePort::parse(port_str.trim()).ok_or_else(|| {
        nom::Err::Failure(nom::error::Error::new(
            port_str,
            nom::error::ErrorKind::Verify,
        ))
    })?;
    Ok((input, Instruction::Expose(port)))
}

fn parse_cmd(input: &str) -> nom::IResult<&str, &str> {
    parse_keyword_rest("CMD", input)
}

fn parse_entrypoint(input: &str) -> nom::IResult<&str, &str> {
    parse_keyword_rest("ENTRYPOINT", input)
}

fn parse_stop(input: &str) -> nom::IResult<&str, &str> {
    parse_keyword_rest("STOP", input)
}

fn parse_user(input: &str) -> nom::IResult<&str, &str> {
    parse_keyword_rest("USER", input)
}

fn parse_label(input: &str) -> nom::IResult<&str, (&str, &str)> {
    let (input, _) = tag_no_case("LABEL").parse(input)?;
    let (input, _) = space1.parse(input)?;
    let (input, key) =
        take_while1(|c: char| c.is_alphanumeric() || c == '_' || c == '.' || c == '-')
            .parse(input)?;
    let (input, _) = tag("=").parse(input)?;

    // Handle quoted values
    let (input, value) = alt((
        delimited(char('"'), take_till(|c| c == '"'), char('"')),
        rest,
    ))
    .parse(input)?;

    Ok((input, (key, value)))
}

fn parse_volume(input: &str) -> nom::IResult<&str, &str> {
    preceded(pair(tag_no_case("VOLUME"), space1), rest).parse(input)
}

#[derive(Debug, Deserialize)]
struct TomlJailfile {
    #[serde(default)]
    metadata: Option<JailfileMetadata>,
    #[serde(default)]
    build: Option<TomlBuild>,
    #[serde(default)]
    start: Option<TomlStart>,
    #[serde(default)]
    stop: Option<TomlStop>,
}

#[derive(Debug, Deserialize)]
struct TomlBuild {
    from: Option<String>,
    workdir: Option<String>,
    #[serde(default)]
    args: Vec<TomlArg>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    run: Vec<TomlRun>,
    #[serde(default)]
    copy: Vec<TomlCopy>,
    #[serde(default)]
    expose: Vec<TomlExpose>,
}

#[derive(Debug, Deserialize)]
struct TomlArg {
    name: String,
    #[serde(default)]
    default: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TomlRun {
    command: String,
}

#[derive(Debug, Deserialize)]
struct TomlCopy {
    src: String,
    dest: String,
    #[serde(default)]
    mode: Option<u32>,
    #[serde(default)]
    owner: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TomlExpose {
    port: u16,
    #[serde(default = "default_protocol")]
    protocol: String,
}

fn default_protocol() -> String {
    "tcp".to_string()
}

#[derive(Debug, Deserialize)]
struct TomlStart {
    cmd: Option<String>,
    entrypoint: Option<String>,
    user: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TomlStop {
    cmd: Option<String>,
}

/// Parse TOML format Jailfile
pub(crate) fn parse_toml_format(content: &str) -> Result<Jailfile> {
    let parsed: TomlJailfile = toml::from_str(content)?;

    let mut jailfile = Jailfile::new();

    // Set metadata
    if let Some(meta) = parsed.metadata {
        jailfile.metadata = meta;
    }

    // Process build section
    if let Some(build) = parsed.build {
        // FROM
        if let Some(from) = build.from {
            jailfile.from = Some(from.clone());
            jailfile.instructions.push(Instruction::From(from));
        }

        // WORKDIR
        if let Some(workdir) = build.workdir {
            jailfile.workdir = Some(workdir.clone());
            jailfile.instructions.push(Instruction::Workdir(workdir));
        }

        // ARGs
        for arg in build.args {
            let build_arg = BuildArg {
                name: arg.name,
                default: arg.default,
            };
            jailfile.args.push(build_arg.clone());
            jailfile.instructions.push(Instruction::Arg(build_arg));
        }

        // ENV
        for (name, value) in build.env {
            jailfile.env.insert(name.clone(), value.clone());
            jailfile.instructions.push(Instruction::Env(name, value));
        }

        // RUN commands
        for run in build.run {
            jailfile.instructions.push(Instruction::Run(run.command));
        }

        // COPY
        for copy in build.copy {
            let spec = CopySpec {
                src: copy.src,
                dest: copy.dest,
                mode: copy.mode,
                owner: copy.owner,
            };
            jailfile.instructions.push(Instruction::Copy(spec));
        }

        // EXPOSE
        for expose in build.expose {
            let port = ExposePort {
                port: expose.port,
                protocol: expose.protocol,
            };
            jailfile.expose.push(port.clone());
            jailfile.instructions.push(Instruction::Expose(port));
        }
    }

    // Process start section
    if let Some(start) = parsed.start {
        if let Some(cmd) = start.cmd {
            jailfile.cmd = Some(cmd.clone());
            jailfile.instructions.push(Instruction::Cmd(cmd));
        }
        if let Some(ep) = start.entrypoint {
            jailfile.entrypoint = Some(ep.clone());
            jailfile.instructions.push(Instruction::Entrypoint(ep));
        }
        if let Some(user) = start.user {
            jailfile.user = Some(user.clone());
            jailfile.instructions.push(Instruction::User(user));
        }
    }

    if let Some(stop) = parsed.stop
        && let Some(cmd) = stop.cmd
    {
        jailfile.stop = Some(cmd.clone());
        jailfile.instructions.push(Instruction::Stop(cmd));
    }

    Ok(jailfile)
}

#[cfg(test)]
mod tests;
