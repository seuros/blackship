//! Build and template commands

use std::path::Path;

use crate::cli::TemplateAction;
use crate::error::Result;
use crate::{blueprint, error, manifest, provision};

pub fn handle_build(
    config_path: &Path,
    verbose: bool,
    file: std::path::PathBuf,
    name: Option<String>,
    build_args: Vec<(String, String)>,
    context: Option<std::path::PathBuf>,
    dry_run: bool,
) -> Result<()> {
    use blueprint::{BuildContext, TemplateExecutor, parse_jailfile};

    let context_dir = context.unwrap_or_else(|| {
        file.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::env::current_dir().unwrap())
    });

    let content = std::fs::read_to_string(&file).map_err(|e| {
        error::Error::TemplateParseFailed(format!("Failed to read {}: {}", file.display(), e))
    })?;
    let jailfile = parse_jailfile(&content)?;

    let service_name = name
        .or_else(|| jailfile.metadata.name.clone())
        .unwrap_or_else(|| "unnamed".to_string());

    let config = manifest::load(config_path)?;
    let full_name = config.jail_name(&service_name);
    let target_path = config.config.data_dir.join("jails").join(&full_name);

    if let Some(release) = &jailfile.from {
        let bs = provision::Provisioner::from_config(&config.config)?;
        let release_path = config.config.releases_dir.join(release);

        if !release_path.exists() {
            println!("Base release '{}' not found. Bootstrapping...", release);
            bs.bootstrap(release, false)?;
        }

        if !dry_run && !target_path.exists() {
            println!("Creating jail root from {}...", release);
            std::fs::create_dir_all(&target_path)?;
            let status = std::process::Command::new("cp")
                .arg("-a")
                .arg(format!("{}/.", release_path.display()))
                .arg(&target_path)
                .status()
                .map_err(|e| error::Error::BuildFailed {
                    step: "FROM".to_string(),
                    message: format!("Failed to copy base release: {}", e),
                })?;
            if !status.success() {
                return Err(error::Error::BuildFailed {
                    step: "FROM".to_string(),
                    message: "cp command failed".to_string(),
                });
            }
        }
    }

    let mut ctx = BuildContext::new(&context_dir, &target_path, &full_name).verbose(verbose);

    for (key, value) in build_args {
        ctx.set_arg(&key, &value);
    }

    let mut executor = TemplateExecutor::new(ctx).dry_run(dry_run);

    if dry_run {
        println!("=== DRY RUN - No changes will be made ===\n");
    }

    println!("Building jail '{}' from {}", full_name, file.display());
    executor.execute(&jailfile)?;

    if !dry_run {
        println!("\nBuild complete! Jail root: {}", target_path.display());
        println!("Add the jail to blackship.toml to manage it:");
        println!("  [[jails]]");
        println!("  name = \"{}\"", full_name);
        println!("  path = \"{}\"", target_path.display());
    }

    Ok(())
}

pub fn handle_init(
    file: std::path::PathBuf,
    release: Option<String>,
    toml: bool,
    force: bool,
) -> Result<()> {
    use std::fs;

    if file.exists() && !force {
        eprintln!(
            "Error: {} already exists. Use -y/--force to overwrite.",
            file.display()
        );
        std::process::exit(1);
    }

    let base_release = release.unwrap_or_else(|| "15.0-RELEASE".to_string());

    let content = if toml {
        format!(
            r#"[metadata]
name = "my-jail"
version = "1.0"
# description = "My jail description"

[build]
from = "{}"

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
"#,
            base_release
        )
    } else {
        format!(
            r#"# Jailfile
FROM {}

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
"#,
            base_release
        )
    };

    fs::write(&file, content)?;
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
    use blueprint::{Instruction, parse_jailfile};

    match action {
        TemplateAction::List => {
            struct TemplateInfo {
                name: String,
                path: std::path::PathBuf,
                base_release: Option<String>,
            }

            fn is_template_file(path: &Path) -> bool {
                let file_name = match path.file_name().and_then(|n| n.to_str()) {
                    Some(name) => name,
                    None => return false,
                };

                if file_name == "Jailfile" || file_name.starts_with("Jailfile.") {
                    return true;
                }

                if file_name.ends_with(".jail") {
                    return true;
                }

                false
            }

            fn extract_base_release(path: &Path) -> Option<String> {
                let content = std::fs::read_to_string(path).ok()?;
                let jailfile = parse_jailfile(&content).ok()?;
                jailfile.from
            }

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
                    let display_path = template
                        .path
                        .strip_prefix(&cwd)
                        .map(|p| format!("./{}", p.display()))
                        .unwrap_or_else(|_| template.path.display().to_string());

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
        TemplateAction::Inspect { template } => {
            let path = std::path::Path::new(&template);
            if path.exists() {
                let content = std::fs::read_to_string(path)?;
                let jailfile = parse_jailfile(&content)?;

                println!("Jailfile: {}\n", template);

                if let Some(name) = &jailfile.metadata.name {
                    println!("Name: {}", name);
                }
                if let Some(version) = &jailfile.metadata.version {
                    println!("Version: {}", version);
                }
                if let Some(desc) = &jailfile.metadata.description {
                    println!("Description: {}", desc);
                }

                if let Some(from) = &jailfile.from {
                    println!("\nBase release: {}", from);
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
                        Instruction::Run(cmd) => println!("  RUN {}", cmd),
                        Instruction::Copy(spec) => {
                            println!("  COPY {} -> {}", spec.src, spec.dest)
                        }
                        Instruction::Env(k, v) => println!("  ENV {}={}", k, v),
                        Instruction::Workdir(p) => println!("  WORKDIR {}", p),
                        _ => println!("  {}", instr.name()),
                    }
                }

                if let Some(cmd) = &jailfile.cmd {
                    println!("\nCMD: {}", cmd);
                }
                if let Some(ep) = &jailfile.entrypoint {
                    println!("ENTRYPOINT: {}", ep);
                }
            } else {
                println!("Template or file '{}' not found.", template);
            }
        }
        TemplateAction::Validate { file } => {
            let content = std::fs::read_to_string(&file).map_err(|e| {
                error::Error::TemplateParseFailed(format!(
                    "Failed to read {}: {}",
                    file.display(),
                    e
                ))
            })?;

            match parse_jailfile(&content) {
                Ok(jailfile) => {
                    println!("✓ Jailfile is valid");
                    println!("  Instructions: {}", jailfile.instructions.len());
                    println!("  Build args: {}", jailfile.args.len());
                    if let Some(from) = &jailfile.from {
                        println!("  Base release: {}", from);
                    }
                }
                Err(e) => {
                    println!("✗ Jailfile validation failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}
