//! Jailfile parsing
//!
//! Supports two formats:
//! 1. Line-based format (similar to Dockerfile)
//! 2. TOML format

use crate::error::{Error, Result};
use crate::blueprint::instructions::{
    BuildArg, CopySpec, ExposePort, Instruction, Jailfile, JailfileMetadata,
};
use nom::{
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_till, take_while1},
    character::complete::{char, space0, space1},
    combinator::{map, opt, rest},
    sequence::{delimited, pair, preceded},
    Parser,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Parse a Jailfile (auto-detects format)
pub fn parse_jailfile(content: &str) -> Result<Jailfile> {
    // Try to detect format
    let trimmed = content.trim();

    // If it starts with [ or contains [metadata], it's TOML
    if trimmed.starts_with('[') || trimmed.contains("[metadata]") || trimmed.contains("[build]") {
        parse_toml_format(content)
    } else {
        parse_line_format(content)
    }
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
    // Skip empty or comment lines
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
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
            "Unknown instruction: {}",
            line
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

fn parse_run(input: &str) -> nom::IResult<&str, &str> {
    preceded(pair(tag_no_case("RUN"), space1), rest).parse(input)
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
    preceded(pair(tag_no_case("WORKDIR"), space1), rest).parse(input)
}

fn parse_expose(input: &str) -> nom::IResult<&str, Instruction> {
    let (input, _) = tag_no_case("EXPOSE").parse(input)?;
    let (input, _) = space1.parse(input)?;
    let (input, port_str) = rest.parse(input)?;

    let port = ExposePort::parse(port_str.trim()).unwrap_or(ExposePort::tcp(0));
    Ok((input, Instruction::Expose(port)))
}

fn parse_cmd(input: &str) -> nom::IResult<&str, &str> {
    preceded(pair(tag_no_case("CMD"), space1), rest).parse(input)
}

fn parse_entrypoint(input: &str) -> nom::IResult<&str, &str> {
    preceded(pair(tag_no_case("ENTRYPOINT"), space1), rest).parse(input)
}

fn parse_user(input: &str) -> nom::IResult<&str, &str> {
    preceded(pair(tag_no_case("USER"), space1), rest).parse(input)
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

/// Parse TOML format Jailfile
fn parse_toml_format(content: &str) -> Result<Jailfile> {
    // Define TOML structure
    #[derive(Debug, Deserialize)]
    struct TomlJailfile {
        #[serde(default)]
        metadata: Option<JailfileMetadata>,
        #[serde(default)]
        build: Option<TomlBuild>,
        #[serde(default)]
        start: Option<TomlStart>,
        #[serde(default)]
        #[allow(dead_code)]
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
        #[allow(dead_code)]
        cmd: Option<String>,
    }

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

    Ok(jailfile)
}

/// Parse a Jailfile from a file path (_unused: future feature)
#[allow(dead_code)]
pub fn parse_jailfile_path(path: &Path) -> Result<Jailfile> {
    let content = std::fs::read_to_string(path).map_err(|e| Error::ConfigRead {
        path: path.to_path_buf(),
        source: e,
    })?;
    parse_jailfile(&content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_line_from() {
        let result = parse_line("FROM 14.2-RELEASE").unwrap();
        assert!(matches!(result, Some(Instruction::From(r)) if r == "14.2-RELEASE"));
    }

    #[test]
    fn test_parse_line_run() {
        let result = parse_line("RUN pkg install -y nginx").unwrap();
        assert!(matches!(result, Some(Instruction::Run(c)) if c == "pkg install -y nginx"));
    }

    #[test]
    fn test_parse_line_copy() {
        let result = parse_line("COPY nginx.conf /usr/local/etc/nginx/").unwrap();
        if let Some(Instruction::Copy(spec)) = result {
            assert_eq!(spec.src, "nginx.conf");
            assert_eq!(spec.dest, "/usr/local/etc/nginx/");
        } else {
            panic!("Expected Copy instruction");
        }
    }

    #[test]
    fn test_parse_line_arg() {
        let result = parse_line("ARG VERSION=1.25").unwrap();
        if let Some(Instruction::Arg(arg)) = result {
            assert_eq!(arg.name, "VERSION");
            assert_eq!(arg.default, Some("1.25".to_string()));
        } else {
            panic!("Expected Arg instruction");
        }
    }

    #[test]
    fn test_parse_line_expose() {
        let result = parse_line("EXPOSE 80/tcp").unwrap();
        if let Some(Instruction::Expose(port)) = result {
            assert_eq!(port.port, 80);
            assert_eq!(port.protocol, "tcp");
        } else {
            panic!("Expected Expose instruction");
        }
    }

    #[test]
    fn test_parse_full_jailfile() {
        let content = r#"
FROM 14.2-RELEASE
ARG NGINX_VERSION=1.25
RUN pkg install -y nginx
COPY nginx.conf /usr/local/etc/nginx/
EXPOSE 80/tcp
CMD /usr/sbin/service nginx start
"#;

        let jf = parse_line_format(content).unwrap();
        assert_eq!(jf.from, Some("14.2-RELEASE".to_string()));
        assert_eq!(jf.args.len(), 1);
        assert_eq!(jf.run_commands().len(), 1);
        assert_eq!(jf.expose.len(), 1);
        assert_eq!(jf.cmd, Some("/usr/sbin/service nginx start".to_string()));
    }

    #[test]
    fn test_parse_toml_format() {
        let content = r#"
[metadata]
name = "nginx-jail"
version = "1.0"

[build]
from = "14.2-RELEASE"
workdir = "/usr/local"

[[build.args]]
name = "NGINX_VERSION"
default = "1.25"

[[build.run]]
command = "pkg install -y nginx"

[[build.copy]]
src = "nginx.conf"
dest = "/usr/local/etc/nginx/nginx.conf"

[[build.expose]]
port = 80
protocol = "tcp"

[start]
cmd = "/usr/sbin/service nginx start"
"#;

        let jf = parse_toml_format(content).unwrap();
        assert_eq!(jf.metadata.name, Some("nginx-jail".to_string()));
        assert_eq!(jf.from, Some("14.2-RELEASE".to_string()));
        assert_eq!(jf.args.len(), 1);
        assert_eq!(jf.workdir, Some("/usr/local".to_string()));
        assert_eq!(jf.cmd, Some("/usr/sbin/service nginx start".to_string()));
    }
}
