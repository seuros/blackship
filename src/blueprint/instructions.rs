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

impl BuildArg {
    /// Create a new build arg (_unused: future feature)
    #[allow(dead_code)]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            default: None,
        }
    }

    /// Set default value (_unused: future feature)
    #[allow(dead_code)]
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
    /// Create a TCP port exposure
    pub fn tcp(port: u16) -> Self {
        Self {
            port,
            protocol: "tcp".to_string(),
        }
    }

    /// Create a UDP port exposure (_unused: future feature)
    #[allow(dead_code)]
    pub fn udp(port: u16) -> Self {
        Self {
            port,
            protocol: "udp".to_string(),
        }
    }

    /// Parse from string like "80/tcp" or "53/udp"
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('/').collect();
        let port = parts.first()?.parse().ok()?;
        let protocol = parts
            .get(1)
            .map(|s| s.to_string())
            .unwrap_or_else(default_protocol);
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

    /// Set file mode (_unused: future feature)
    #[allow(dead_code)]
    pub fn with_mode(mut self, mode: u32) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Set owner (_unused: future feature)
    #[allow(dead_code)]
    pub fn with_owner(mut self, owner: &str) -> Self {
        self.owner = Some(owner.to_string());
        self
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
    /// USER <user> - Set default user
    User(String),
    /// LABEL <key>=<value> - Add metadata
    Label(String, String),
    /// VOLUME <path> - Declare a volume
    Volume(String),
    /// COMMENT - A comment line (_unused: future feature)
    #[allow(dead_code)]
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
    /// Author (_unused: future feature)
    #[allow(dead_code)]
    pub author: Option<String>,
    /// Labels (_unused: future feature)
    #[serde(default)]
    #[allow(dead_code)]
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
            workdir: None,
            user: None,
            expose: Vec::new(),
            volumes: Vec::new(),
            env: HashMap::new(),
        }
    }

    /// Create a Jailfile with a base release
    #[allow(dead_code)] // Public API for programmatic Jailfile creation
    pub fn from_release(release: &str) -> Self {
        let mut jf = Self::new();
        jf.from = Some(release.to_string());
        jf.instructions.push(Instruction::From(release.to_string()));
        jf
    }

    /// Add a build argument
    #[allow(dead_code)] // Public API for programmatic Jailfile creation
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
    #[allow(dead_code)] // Public API for programmatic Jailfile creation
    pub fn env(mut self, name: &str, value: &str) -> Self {
        self.env.insert(name.to_string(), value.to_string());
        self.instructions
            .push(Instruction::Env(name.to_string(), value.to_string()));
        self
    }

    /// Add a RUN instruction
    #[allow(dead_code)] // Public API for programmatic Jailfile creation
    pub fn run(mut self, command: &str) -> Self {
        self.instructions
            .push(Instruction::Run(command.to_string()));
        self
    }

    /// Add a COPY instruction
    #[allow(dead_code)] // Public API for programmatic Jailfile creation
    pub fn copy(mut self, src: &str, dest: &str) -> Self {
        let spec = CopySpec::new(src, dest);
        self.instructions.push(Instruction::Copy(spec));
        self
    }

    /// Set working directory
    #[allow(dead_code)] // Public API for programmatic Jailfile creation
    pub fn workdir(mut self, path: &str) -> Self {
        self.workdir = Some(path.to_string());
        self.instructions
            .push(Instruction::Workdir(path.to_string()));
        self
    }

    /// Expose a port
    #[allow(dead_code)] // Public API for programmatic Jailfile creation
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
    #[allow(dead_code)] // Public API for programmatic Jailfile creation
    pub fn cmd(mut self, command: &str) -> Self {
        self.cmd = Some(command.to_string());
        self.instructions
            .push(Instruction::Cmd(command.to_string()));
        self
    }

    /// Set the entrypoint
    #[allow(dead_code)] // Public API for programmatic Jailfile creation
    pub fn entrypoint(mut self, command: &str) -> Self {
        self.entrypoint = Some(command.to_string());
        self.instructions
            .push(Instruction::Entrypoint(command.to_string()));
        self
    }

    /// Set the user
    #[allow(dead_code)] // Public API for programmatic Jailfile creation
    pub fn user(mut self, user: &str) -> Self {
        self.user = Some(user.to_string());
        self.instructions.push(Instruction::User(user.to_string()));
        self
    }

    /// Get the base release
    #[allow(dead_code)] // Public API for Jailfile inspection
    pub fn base_release(&self) -> Option<&str> {
        self.from.as_deref()
    }

    /// Get all RUN commands
    #[allow(dead_code)] // Public API for Jailfile inspection
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
    #[allow(dead_code)] // Public API for Jailfile inspection
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
mod tests {
    use super::*;

    #[test]
    fn test_build_arg() {
        let arg = BuildArg::new("VERSION").with_default("1.0");
        assert_eq!(arg.name, "VERSION");
        assert_eq!(arg.default, Some("1.0".to_string()));
    }

    #[test]
    fn test_expose_port_parse() {
        let tcp = ExposePort::parse("80/tcp").unwrap();
        assert_eq!(tcp.port, 80);
        assert_eq!(tcp.protocol, "tcp");

        let udp = ExposePort::parse("53/udp").unwrap();
        assert_eq!(udp.port, 53);
        assert_eq!(udp.protocol, "udp");

        let default = ExposePort::parse("443").unwrap();
        assert_eq!(default.port, 443);
        assert_eq!(default.protocol, "tcp");
    }

    #[test]
    fn test_jailfile_builder() {
        let jf = Jailfile::from_release("14.2-RELEASE")
            .arg("VERSION", Some("1.0"))
            .env("PATH", "/usr/local/bin:/usr/bin")
            .run("pkg install -y nginx")
            .copy("nginx.conf", "/usr/local/etc/nginx/nginx.conf")
            .workdir("/usr/local")
            .expose(80, "tcp")
            .cmd("/usr/sbin/service nginx start");

        assert_eq!(jf.from, Some("14.2-RELEASE".to_string()));
        assert_eq!(jf.args.len(), 1);
        assert_eq!(jf.run_commands().len(), 1);
        assert_eq!(jf.copy_specs().len(), 1);
        assert_eq!(jf.expose.len(), 1);
    }

    #[test]
    fn test_instruction_names() {
        assert_eq!(Instruction::From("test".to_string()).name(), "FROM");
        assert_eq!(Instruction::Run("test".to_string()).name(), "RUN");
        assert_eq!(Instruction::Copy(CopySpec::new("a", "b")).name(), "COPY");
    }
}
