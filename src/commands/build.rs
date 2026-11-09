//! Build and template commands

use std::path::Path;

use crate::cli::TemplateAction;
use crate::error::Result;
use crate::host::Host;
use crate::image::BuildMode;
use crate::{blueprint, error, manifest};

/// Read a Jailfile/template source, mapping IO errors to `TemplateParseFailed`
fn read_jailfile_source(path: &std::path::Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| {
        error::Error::TemplateParseFailed(format!("Failed to read {}: {}", path.display(), e))
    })
}

pub fn handle_build(
    config_path: &Path,
    verbose: bool,
    file: &Path,
    name: Option<String>,
    build_args: Vec<(String, String)>,
    context: Option<std::path::PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let context_dir = context.unwrap_or_else(|| crate::image::context_of(file));
    let jailfile = crate::image::read_jailfile(file)?;

    let service_name = name
        .or_else(|| jailfile.metadata.name.clone())
        .unwrap_or_else(|| "unnamed".to_string());
    manifest::validate_name("jail", &service_name)?;

    let config = manifest::load(config_path)?;
    let full_name = config.jail_name(&service_name);
    let host = Host::from_config(Some(config));

    if dry_run {
        println!("=== DRY RUN - No changes will be made ===\n");
    }
    println!("Building jail '{}' from {}", full_name, file.display());

    let mode = if dry_run {
        BuildMode::DryRun
    } else {
        BuildMode::Real { verbose }
    };
    let image =
        crate::image::build_root(&host, &jailfile, &context_dir, &full_name, build_args, mode)?;

    if !dry_run {
        println!("\nBuild complete! Jail root: {}", image.root.display());
        println!("Add the jail to blackship.toml to manage it:");
        println!("  [[jails]]");
        println!("  name = \"{full_name}\"");
        println!("  path = \"{}\"", image.root.display());
    }

    Ok(())
}

pub fn handle_init(file: &Path, release: Option<String>, toml: bool, force: bool) -> Result<()> {
    use std::fs;

    if file.exists() && !force {
        eprintln!(
            "Error: {} already exists. Use -y/--force to overwrite.",
            file.display()
        );
        std::process::exit(1);
    }

    let base_release = release.unwrap_or_else(|| "15.1-RELEASE".to_string());

    let content = if toml {
        format!(
            r#"[metadata]
name = "my-jail"
version = "1.0"
# description = "My jail description"

[build]
from = "{base_release}"

# Build arguments
# [[build.args]]
# name = "VERSION"
# default = "1.0"

# Run commands
# [[build.run]]
# command = "pkg install -y <packages>"

# Copy files
# [[build.copy]]
# src = "config.conf"
# dest = "/usr/local/etc/"

# [start]
# cmd = "/usr/sbin/service myapp start"
# user = "root"
"#
        )
    } else {
        format!(
            r"# Jailfile
FROM {base_release}

# Build arguments
# ARG VERSION=1.0

# Install packages
# RUN pkg install -y <packages>

# Copy files from build context
# COPY config.conf /usr/local/etc/

# Set working directory
# WORKDIR /usr/local

# Expose ports
# EXPOSE 80/tcp

# Default command
# CMD /usr/sbin/service myapp start
"
        )
    };

    fs::write(file, content)?;
    println!("Created {}", file.display());
    println!("\nNext steps:");
    println!("  1. Edit {} to customize your jail", file.display());
    println!(
        "  2. Run 'blackship build -f {}' to build the jail",
        file.display()
    );
    Ok(())
}

pub fn handle_template(config_path: &Path, action: TemplateAction) -> Result<()> {
    match action {
        TemplateAction::List => list_templates(config_path),
        TemplateAction::Inspect { template } => inspect_template(&template)?,
        TemplateAction::Validate { file } => validate_template(&file)?,
    }

    Ok(())
}

/// A template file found by `template list`
struct TemplateInfo {
    name: String,
    path: std::path::PathBuf,
    base_release: Option<String>,
}

/// Jailfile, Jailfile.<suffix>, or *.jail
fn is_template_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };

    if file_name == "Jailfile" || file_name.starts_with("Jailfile.") {
        return true;
    }

    path.extension().is_some_and(|ext| ext == "jail")
}

/// The FROM release of a template, if it parses
fn extract_base_release(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let jailfile = blueprint::parse_jailfile(&content).ok()?;
    jailfile.from
}

/// Collect the template files directly inside `dir`
fn scan_directory(dir: &Path, templates: &mut Vec<TemplateInfo>) {
    if !dir.exists() || !dir.is_dir() {
        return;
    }

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && is_template_file(&path) {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                let base_release = extract_base_release(&path);
                templates.push(TemplateInfo {
                    name,
                    path,
                    base_release,
                });
            }
        }
    }
}

/// `template list`: templates in ., ./templates and the data dir
fn list_templates(config_path: &Path) {
    let mut templates: Vec<TemplateInfo> = Vec::new();
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));

    scan_directory(&cwd, &mut templates);

    let templates_subdir = cwd.join("templates");
    scan_directory(&templates_subdir, &mut templates);

    if let Ok(config) = manifest::load(config_path) {
        let data_templates = config.config.data_dir.join("templates");
        scan_directory(&data_templates, &mut templates);
    }

    if templates.is_empty() {
        println!("No templates found.");
        println!("Create a Jailfile or place .jail files in ./templates/");
    } else {
        println!("Available templates:");

        let max_name_width = templates.iter().map(|t| t.name.len()).max().unwrap_or(0);

        for template in &templates {
            let display_path = template.path.strip_prefix(&cwd).map_or_else(
                |_| template.path.display().to_string(),
                |p| format!("./{}", p.display()),
            );

            if let Some(ref release) = template.base_release {
                println!(
                    "  {:<width$}  {}  ({})",
                    template.name,
                    display_path,
                    release,
                    width = max_name_width
                );
            } else {
                println!(
                    "  {:<width$}  {}",
                    template.name,
                    display_path,
                    width = max_name_width
                );
            }
        }

        println!();
        println!("Use 'blackship build --file <path>' to build from a template.");
    }
}

/// `template inspect`: print a Jailfile's metadata and instructions
fn inspect_template(template: &str) -> Result<()> {
    use blueprint::{Instruction, parse_jailfile};

    let path = std::path::Path::new(&template);
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        let jailfile = parse_jailfile(&content)?;

        println!("Jailfile: {template}\n");

        if let Some(name) = &jailfile.metadata.name {
            println!("Name: {name}");
        }
        if let Some(version) = &jailfile.metadata.version {
            println!("Version: {version}");
        }
        if let Some(desc) = &jailfile.metadata.description {
            println!("Description: {desc}");
        }
        if let Some(author) = &jailfile.metadata.author {
            println!("Author: {author}");
        }
        if !jailfile.metadata.labels.is_empty() {
            println!("Labels:");
            let mut labels: Vec<_> = jailfile.metadata.labels.iter().collect();
            labels.sort();
            for (key, value) in labels {
                println!("  {key} = {value}");
            }
        }

        if let Some(from) = &jailfile.from {
            println!("\nBase release: {from}");
        }

        if !jailfile.args.is_empty() {
            println!("\nBuild arguments:");
            for arg in &jailfile.args {
                println!(
                    "  {} = {}",
                    arg.name,
                    arg.default.as_deref().unwrap_or("<required>")
                );
            }
        }

        if !jailfile.expose.is_empty() {
            println!("\nExposed ports:");
            for port in &jailfile.expose {
                println!("  {}/{}", port.port, port.protocol);
            }
        }

        println!("\nInstructions ({}):", jailfile.instructions.len());
        for instr in &jailfile.instructions {
            match instr {
                Instruction::Run(cmd) => println!("  RUN {cmd}"),
                Instruction::Copy(spec) => {
                    println!("  COPY {} -> {}", spec.src, spec.dest);
                }
                Instruction::Env(k, v) => println!("  ENV {k}={v}"),
                Instruction::Workdir(p) => println!("  WORKDIR {p}"),
                Instruction::Comment(text) => println!("  # {text}"),
                Instruction::Label(key, value) => {
                    println!("  LABEL {key}={value}");
                }
                _ => println!("  {}", instr.name()),
            }
        }

        if let Some(cmd) = &jailfile.cmd {
            println!("\nCMD: {cmd}");
        }
        if let Some(ep) = &jailfile.entrypoint {
            println!("ENTRYPOINT: {ep}");
        }
        if let Some(stop) = &jailfile.stop {
            println!("STOP: {stop}");
        }
    } else {
        println!("Template or file '{template}' not found.");
    }

    Ok(())
}

/// `template validate`: parse a Jailfile, exiting 1 on failure
fn validate_template(file: &Path) -> Result<()> {
    let content = read_jailfile_source(file)?;

    match blueprint::parse_jailfile(&content) {
        Ok(jailfile) => {
            println!("[OK] Jailfile is valid");
            println!("  Instructions: {}", jailfile.instructions.len());
            println!("  Build args: {}", jailfile.args.len());
            if let Some(from) = &jailfile.from {
                println!("  Base release: {from}");
            }
        }
        Err(e) => {
            println!("[FAIL] Jailfile validation failed: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}
