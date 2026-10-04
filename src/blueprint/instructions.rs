//! Jailfile instructions
//!
//! Defines the instructions that can be used in a Jailfile.

use serde::Deserialize;
use std::collections::HashMap;

/// Build argument definition
#[derive(Debug, Clone, Deserialize)]
pub struct BuildArg {
    /// Argument name
    pub name: String,
    /// Default value (optional)
    pub default: Option<String>,
}

#[cfg(test)]
impl BuildArg {
    /// Create a new build arg
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            default: None,
        }
    }

    /// Set default value
    pub fn with_default(mut self, default: &str) -> Self {
        self.default = Some(default.to_string());
        self
    }
}

/// Port exposure definition
#[derive(Debug, Clone, Deserialize)]
pub struct ExposePort {
    /// Port number
    pub port: u16,
    /// Protocol (tcp/udp)
    #[serde(default = "default_protocol")]
    pub protocol: String,
}

fn default_protocol() -> String {
    "tcp".to_string()
}

impl ExposePort {
    /// Parse from string like "80/tcp" or "53/udp"
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('/').collect();
        let port = parts.first()?.parse().ok()?;
        let protocol = parts
            .get(1)
            .map(|s| s.to_string())
            .unwrap_or_else(default_protocol);
        // Only allow known protocols to prevent injection if wired into PF later
        if protocol != "tcp" && protocol != "udp" && protocol != "sctp" {
            return None;
        }
        Some(Self { port, protocol })
    }
}

/// Copy instruction source/destination
#[derive(Debug, Clone, Deserialize)]
pub struct CopySpec {
    /// Source path (relative to build context)
    pub src: String,
    /// Destination path in jail
    pub dest: String,
    /// File mode (optional)
    pub mode: Option<u32>,
    /// Owner (optional)
    pub owner: Option<String>,
}

impl CopySpec {
    /// Create a new copy spec
    pub fn new(src: &str, dest: &str) -> Self {
        Self {
            src: src.to_string(),
            dest: dest.to_string(),
            mode: None,
            owner: None,
        }
    }
}

/// A single build instruction
#[derive(Debug, Clone)]
pub enum Instruction {
    /// FROM <release> - Base release to build from
    From(String),
    /// ARG <name>[=<default>] - Build argument
    Arg(BuildArg),
    /// ENV <name>=<value> - Environment variable
    Env(String, String),
    /// RUN <command> - Execute a command
    Run(String),
    /// COPY <src> <dest> - Copy files into jail
    Copy(CopySpec),
    /// WORKDIR <path> - Set working directory
    Workdir(String),
    /// EXPOSE <port>[/<protocol>] - Expose a port
    Expose(ExposePort),
    /// CMD <command> - Default command to run
    Cmd(String),
    /// ENTRYPOINT <command> - Entry point command
    Entrypoint(String),
    /// STOP <command> - Command to run before the jail is stopped
    Stop(String),
    /// USER <user> - Set default user
    User(String),
    /// LABEL <key>=<value> - Add metadata
    Label(String, String),
    /// VOLUME <path> - Declare a volume
    Volume(String),
    /// COMMENT - A comment line
    Comment(String),
}

impl Instruction {
    /// Get instruction name
    pub fn name(&self) -> &'static str {
        match self {
            Instruction::From(_) => "FROM",
            Instruction::Arg(_) => "ARG",
            Instruction::Env(_, _) => "ENV",
            Instruction::Run(_) => "RUN",
            Instruction::Copy(_) => "COPY",
            Instruction::Workdir(_) => "WORKDIR",
            Instruction::Expose(_) => "EXPOSE",
            Instruction::Cmd(_) => "CMD",
            Instruction::Entrypoint(_) => "ENTRYPOINT",
            Instruction::Stop(_) => "STOP",
            Instruction::User(_) => "USER",
            Instruction::Label(_, _) => "LABEL",
            Instruction::Volume(_) => "VOLUME",
            Instruction::Comment(_) => "#",
        }
    }
}

/// Jailfile metadata
#[derive(Debug, Clone, Default, Deserialize)]
pub struct JailfileMetadata {
    /// Template name
    pub name: Option<String>,
    /// Template version
    pub version: Option<String>,
    /// Description
    pub description: Option<String>,
    /// Author
    pub author: Option<String>,
    /// Labels
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

/// A parsed Jailfile
#[derive(Debug, Clone)]
pub struct Jailfile {
    /// Metadata
    pub metadata: JailfileMetadata,
    /// Base release
    pub from: Option<String>,
    /// Build arguments
    pub args: Vec<BuildArg>,
    /// Instructions to execute
    pub instructions: Vec<Instruction>,
    /// Start command
    pub cmd: Option<String>,
    /// Entry point
    pub entrypoint: Option<String>,
    /// Command to run before the jail is stopped
    pub stop: Option<String>,
    /// Working directory
    pub workdir: Option<String>,
    /// Default user
    pub user: Option<String>,
    /// Exposed ports
    pub expose: Vec<ExposePort>,
    /// Declared volumes
    pub volumes: Vec<String>,
    /// Environment variables
    pub env: HashMap<String, String>,
}

impl Default for Jailfile {
    fn default() -> Self {
        Self::new()
    }
}

impl Jailfile {
    /// Create a new empty Jailfile
    pub fn new() -> Self {
        Self {
            metadata: JailfileMetadata::default(),
            from: None,
            args: Vec::new(),
            instructions: Vec::new(),
            cmd: None,
            entrypoint: None,
            stop: None,
            workdir: None,
            user: None,
            expose: Vec::new(),
            volumes: Vec::new(),
            env: HashMap::new(),
        }
    }
}

#[cfg(test)]
impl Jailfile {
    /// Create a Jailfile with a base release
    pub fn from_release(release: &str) -> Self {
        let mut jf = Self::new();
        jf.from = Some(release.to_string());
        jf.instructions.push(Instruction::From(release.to_string()));
        jf
    }

    /// Add a build argument
    pub fn arg(mut self, name: &str, default: Option<&str>) -> Self {
        let arg = BuildArg {
            name: name.to_string(),
            default: default.map(String::from),
        };
        self.args.push(arg.clone());
        self.instructions.push(Instruction::Arg(arg));
        self
    }

    /// Add an environment variable
    pub fn env(mut self, name: &str, value: &str) -> Self {
        self.env.insert(name.to_string(), value.to_string());
        self.instructions
            .push(Instruction::Env(name.to_string(), value.to_string()));
        self
    }

    /// Add a RUN instruction
    pub fn run(mut self, command: &str) -> Self {
        self.instructions
            .push(Instruction::Run(command.to_string()));
        self
    }

    /// Add a COPY instruction
    pub fn copy(mut self, src: &str, dest: &str) -> Self {
        let spec = CopySpec::new(src, dest);
        self.instructions.push(Instruction::Copy(spec));
        self
    }

    /// Set working directory
    pub fn workdir(mut self, path: &str) -> Self {
        self.workdir = Some(path.to_string());
        self.instructions
            .push(Instruction::Workdir(path.to_string()));
        self
    }

    /// Expose a port
    pub fn expose(mut self, port: u16, protocol: &str) -> Self {
        let exp = ExposePort {
            port,
            protocol: protocol.to_string(),
        };
        self.expose.push(exp.clone());
        self.instructions.push(Instruction::Expose(exp));
        self
    }

    /// Set the CMD
    pub fn cmd(mut self, command: &str) -> Self {
        self.cmd = Some(command.to_string());
        self.instructions
            .push(Instruction::Cmd(command.to_string()));
        self
    }

    /// Get all RUN commands
    pub fn run_commands(&self) -> Vec<&str> {
        self.instructions
            .iter()
            .filter_map(|i| match i {
                Instruction::Run(cmd) => Some(cmd.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Get all COPY specs
    pub fn copy_specs(&self) -> Vec<&CopySpec> {
        self.instructions
            .iter()
            .filter_map(|i| match i {
                Instruction::Copy(spec) => Some(spec),
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
