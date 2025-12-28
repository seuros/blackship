//! Blackship - FreeBSD jail orchestrator
//!
//! A jail manager with TOML configuration, dependency management,
//! and state machine-controlled lifecycle.

mod provision;
mod cli;
mod manifest;
mod console;
mod error;
mod export;
mod supply;
mod bulkhead;
mod sickbay;
mod hooks;
mod jail;
mod network;
mod bridge;
mod blueprint;
mod warden;
mod zfs;

use cli::{Cli, Commands, NetworkAction, ReleasesAction, SnapshotAction, TemplateAction};
use error::Result;

use std::sync::Arc;
use tokio::sync::Mutex;

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse_args();

    // Execute command
    match cli.command {
        // Commands that don't require config
        Commands::Exec {
            jail,
            user,
            command,
        } => {
            let opts = console::ExecOptions {
                user,
                ..Default::default()
            };
            let status = console::exec_in_jail(&jail, &command, &opts)?;
            std::process::exit(status.code().unwrap_or(1));
        }
        Commands::Console { jail, user } => {
            let status = console::console(&jail, &user)?;
            std::process::exit(status.code().unwrap_or(1));
        }
        Commands::Completion { shell } => {
            cli::Cli::generate_completion(shell);
            return Ok(());
        }
        Commands::Logs {
            jail,
            follow,
            lines,
        } => {
            let config = manifest::load(&cli.config)?;

            // Find jail config to get its path
            let jail_def = config
                .get_jail(&jail)
                .ok_or_else(|| error::Error::JailNotFound(jail.clone()))?;

            let jail_path = jail_def.effective_path(&config.config);
            let log_dir = jail_path.join("var/log");

            // Common log files to look for
            let log_files = ["messages", "console.log", "daemon.log", "syslog"];

            // Find the first existing log file
            let log_file = log_files
                .iter()
                .map(|f| log_dir.join(f))
                .find(|p| p.exists());

            let log_path = match log_file {
                Some(p) => p,
                None => {
                    // Default to messages even if it doesn't exist yet
                    log_dir.join("messages")
                }
            };

            // Build tail command
            let mut tail_args = vec![];
            if follow {
                tail_args.push("-f".to_string());
            }
            tail_args.push("-n".to_string());
            tail_args.push(lines.to_string());

            // Get the path relative to jail root for jexec
            let relative_log_path = log_path
                .strip_prefix(&jail_path)
                .unwrap_or(&log_path);
            tail_args.push(format!("/{}", relative_log_path.display()));

            // Execute tail via jexec
            let opts = console::ExecOptions::default();
            let mut cmd = vec!["tail".to_string()];
            cmd.extend(tail_args);

            let status = console::exec_in_jail(&jail, &cmd, &opts)?;
            std::process::exit(status.code().unwrap_or(1));
        }

        Commands::Supervise => {
            // Load config and save it for later use (before moving into async)
            let config = manifest::load(&cli.config)?;
            let jails_for_health = config.jails.clone();
            let rate_limit = config.config.rate_limit.clone();

            let bridge = bridge::Bridge::new(config)?.verbose(cli.verbose);
            let bridge = Arc::new(Mutex::new(bridge));

            let rt = tokio::runtime::Runtime::new().map_err(|e| {
                error::Error::Io(std::io::Error::other(e))
            })?;

            rt.block_on(async {
                let warden = warden::Warden::new(Arc::clone(&bridge));
                let sender = warden.sender();

                // Create a WardenHandle before moving warden into spawn
                let warden_handle_for_orch = warden::WardenHandle::new(&warden);
                let warden_handle_for_health = warden::WardenHandle::new(&warden);

                // Wire WardenHandle to the bridge
                {
                    let mut br = bridge.lock().await;
                    br.set_warden_handle(warden_handle_for_orch);
                }

                // Start all jails
                {
                    let mut br = bridge.lock().await;
                    if let Err(e) = br.up(None) {
                        eprintln!("Warning: Failed to start some jails: {}", e);
                    }
                }

                // Spawn the Warden event loop
                let mut warden = warden;
                let warden_task = tokio::spawn(async move {
                    warden.run().await;
                });

                // Spawn health monitors for jails with health checks enabled
                // Collect stop signals to cleanly shutdown health checkers
                let mut health_stop_signals = Vec::new();

                for jail_def in &jails_for_health {
                    if jail_def.healthcheck.enabled && !jail_def.healthcheck.checks.is_empty() {
                        let jail_name = jail_def.name.clone();
                        let healthcheck_config = jail_def.healthcheck.clone();
                        let handle = warden_handle_for_health.clone();
                        let health_capacity = rate_limit.health_capacity;
                        let health_refill_rate = rate_limit.health_refill_rate;

                        // Create health checker with warden handle
                        let mut checker = sickbay::HealthChecker::with_rate_limit(
                            &jail_name,
                            healthcheck_config,
                            health_capacity,
                            health_refill_rate,
                        ).with_warden_handle(handle);

                        // Try to get JID for the jail
                        if let Ok(jid) = jail::jail_getid(&jail_name) {
                            checker = checker.with_jid(jid);
                        }

                        // Get stop signal before moving checker into spawned task
                        let stop_signal = checker.stop_signal();
                        health_stop_signals.push(stop_signal);

                        tokio::spawn(async move {
                            // Run health checks in a loop until stopped
                            while !checker.is_stopped() {
                                if let Err(e) = checker.run_checks() {
                                    eprintln!("Health check error for {}: {}", checker.jail_name(), e);
                                }

                                // Check status and log transitions
                                let status = checker.status();
                                if status == sickbay::HealthStatus::Failing {
                                    eprintln!("Health check failing for jail '{}'", checker.jail_name());
                                }

                                tokio::time::sleep(tokio::time::Duration::from_secs(
                                    checker.interval().as_secs()
                                )).await;
                            }
                            println!("Health monitor stopped for jail '{}'", checker.jail_name());
                        });

                        println!("Spawned health monitor for jail '{}'", jail_def.name);
                    }
                }

                println!("Warden supervisor started. Press Ctrl+C to stop.");

                // Wait for Ctrl+C
                tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");

                println!("\nShutting down...");

                // Stop all health checkers
                for stop_signal in &health_stop_signals {
                    stop_signal.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                if !health_stop_signals.is_empty() {
                    println!("Stopped {} health monitor(s)", health_stop_signals.len());
                }

                // Request Warden shutdown
                warden::Warden::request_shutdown(&sender).await;

                // Wait for Warden to finish
                let _ = warden_task.await;
            });

            return Ok(());
        }

        // Bootstrap commands - require config but not bridge
        Commands::Bootstrap {
            release,
            force,
            archives,
        } => {
            let config = manifest::load(&cli.config)?;
            let mut bs = provision::Provisioner::from_config(&config.config)?;

            // Override archives if specified on command line
            if let Some(archives) = archives {
                bs = provision::Provisioner::new(
                    config.config.mirror_url.clone(),
                    config.config.releases_dir.clone(),
                    config.config.cache_dir.clone(),
                    archives,
                    config.config.retry.clone(),
                )?;
            }

            bs.bootstrap(&release, force)?;
        }

        Commands::Releases { action, json } => {
            let config = manifest::load(&cli.config)?;
            let bs = provision::Provisioner::from_config(&config.config)?;

            match action.unwrap_or(ReleasesAction::List) {
                ReleasesAction::List => {
                    let releases = bs.list_releases()?;
                    if json {
                        let json_data: Vec<_> = releases
                            .iter()
                            .map(|r| {
                                serde_json::json!({
                                    "name": r.name,
                                    "arch": r.arch.freebsd_name(),
                                    "path": r.path.display().to_string()
                                })
                            })
                            .collect();
                        println!("{}", serde_json::to_string_pretty(&json_data).unwrap());
                    } else if releases.is_empty() {
                        println!("No releases bootstrapped.");
                        println!("Use 'blackship bootstrap <release>' to bootstrap a release.");
                    } else {
                        println!("Bootstrapped releases:");
                        for release in releases {
                            println!("  {} ({}) - {}", release.name, release.arch.freebsd_name(), release.path.display());
                        }
                    }
                }
                ReleasesAction::Delete { release } => {
                    bs.delete(&release)?;
                }
                ReleasesAction::Verify { release } => {
                    if bs.verify(&release)? {
                        println!("Release '{}' is valid.", release);
                    } else {
                        println!("Release '{}' is corrupted or incomplete.", release);
                        std::process::exit(1);
                    }
                }
            }
        }

        Commands::Network { action } => {
            use ipnet::IpNet;
            use network::bridge::{destroy_bridge, list_bridges, Bridge};

            match action {
                NetworkAction::Create {
                    name,
                    subnet,
                    gateway,
                    bridge,
                } => {
                    let subnet: IpNet = subnet.parse().map_err(|e| {
                        error::Error::Network(format!("Invalid subnet: {}", e))
                    })?;

                    let gateway_ip: Option<std::net::IpAddr> = if let Some(gw) = gateway {
                        Some(gw.parse().map_err(|e| {
                            error::Error::Network(format!("Invalid gateway: {}", e))
                        })?)
                    } else {
                        None
                    };

                    // Create bridge
                    let br = Bridge::create_or_open(&bridge)?;

                    // Set gateway IP on bridge if provided
                    if let Some(gw) = &gateway_ip {
                        let prefix = subnet.prefix_len();
                        br.set_address(&format!("{}/{}", gw, prefix))?;
                    }

                    println!("Created network '{}' on bridge '{}'", name, bridge);
                    println!("  Subnet: {}", subnet);
                    if let Some(gw) = gateway_ip {
                        println!("  Gateway: {}", gw);
                    }
                }
                NetworkAction::Destroy { name, force } => {
                    destroy_bridge(&name, force)?;
                    println!("Destroyed bridge '{}'", name);
                }
                NetworkAction::List => {
                    let bridges = list_bridges()?;
                    if bridges.is_empty() {
                        println!("No bridge interfaces found.");
                    } else {
                        println!("Bridge interfaces:");
                        for bridge in bridges {
                            let br = Bridge::open(&bridge)?;
                            let members = br.members()?;
                            if members.is_empty() {
                                println!("  {} (no members)", bridge);
                            } else {
                                println!("  {} (members: {})", bridge, members.join(", "));
                            }
                        }
                    }
                }
                NetworkAction::Attach { jail, network, ip } => {
                    println!(
                        "Attaching jail '{}' to network '{}' (ip: {:?})",
                        jail, network, ip
                    );
                    println!("Note: Attach is done automatically during 'up' with network config.");
                }
                NetworkAction::Detach { jail, network } => {
                    println!("Detaching jail '{}' from network '{}'", jail, network);
                    println!("Note: Detach is done automatically during 'down'.");
                }
            }
        }

        Commands::Health {
            jail,
            watch,
            interval,
            json,
        } => {
            use sickbay::{HealthChecker, HealthStatus};

            let config = manifest::load(&cli.config)?;

            // Filter jails based on input
            let jails: Vec<_> = if let Some(jail_name) = &jail {
                config
                    .jails
                    .iter()
                    .filter(|j| j.name == *jail_name)
                    .collect()
            } else {
                config.jails.iter().collect()
            };

            if jails.is_empty() {
                if json {
                    println!("[]");
                } else if let Some(name) = jail {
                    println!("Jail '{}' not found in configuration.", name);
                } else {
                    println!("No jails defined in configuration.");
                }
                return Ok(());
            }

            // Create health checkers for each jail
            let rate_limit = &config.config.rate_limit;
            let mut checkers: Vec<HealthChecker> = jails
                .iter()
                .filter(|j| j.healthcheck.enabled)
                .map(|j| {
                    let mut checker = HealthChecker::with_rate_limit(
                        &j.name,
                        j.healthcheck.clone(),
                        rate_limit.health_capacity,
                        rate_limit.health_refill_rate,
                    );
                    // Try to get JID for running jails
                    if let Ok(jid) = jail::jail_getid(&j.name) {
                        checker = checker.with_jid(jid);
                    }
                    checker
                })
                .collect();

            if checkers.is_empty() {
                if json {
                    println!("[]");
                } else {
                    println!("No jails have health checks enabled.");
                }
                return Ok(());
            }

            // Display header (non-JSON only)
            if !json {
                println!("{:<20} {:<12} {:<20}", "JAIL", "STATUS", "CHECKS");
                println!("{}", "-".repeat(54));
            }

            loop {
                let mut json_results: Vec<serde_json::Value> = Vec::new();

                for checker in &mut checkers {
                    let status = checker.run_checks()?;
                    let check_results = checker.get_check_results();

                    if json {
                        let status_str = match status {
                            HealthStatus::Healthy => "healthy",
                            HealthStatus::Unhealthy => "unhealthy",
                            HealthStatus::Failing => "failing",
                            HealthStatus::Starting => "starting",
                            HealthStatus::Suspended => "suspended",
                            HealthStatus::Unknown => "unknown",
                        };

                        let checks: Vec<_> = check_results
                            .iter()
                            .map(|(check, result, failures)| {
                                serde_json::json!({
                                    "name": check.name,
                                    "passed": result.as_ref().map(|r| r.passed),
                                    "output": result.as_ref().map(|r| r.output.clone()),
                                    "duration_ms": result.as_ref().map(|r| r.duration.as_millis()),
                                    "age_ms": result.as_ref().map(|r| r.age().as_millis()),
                                    "failures": failures
                                })
                            })
                            .collect();

                        json_results.push(serde_json::json!({
                            "jail": checker.jail_name(),
                            "status": status_str,
                            "checks": checks
                        }));
                    } else {
                        let checks_summary: String = check_results
                            .iter()
                            .map(|(_check, result, failures)| {
                                match result {
                                    Some(r) => {
                                        let summary = r.summary();
                                        if *failures > 0 {
                                            format!("{} ({}x)", summary, failures)
                                        } else {
                                            summary
                                        }
                                    }
                                    None => "?".to_string(),
                                }
                            })
                            .collect::<Vec<_>>()
                            .join(", ");

                        let status_str = match status {
                            HealthStatus::Healthy => "\x1b[32mhealthy\x1b[0m",
                            HealthStatus::Unhealthy => "\x1b[33munhealthy\x1b[0m",
                            HealthStatus::Failing => "\x1b[31mfailing\x1b[0m",
                            HealthStatus::Starting => "\x1b[34mstarting\x1b[0m",
                            HealthStatus::Suspended => "\x1b[35msuspended\x1b[0m",
                            HealthStatus::Unknown => "unknown",
                        };

                        println!(
                            "{:<20} {:<12} {:<20}",
                            checker.jail_name(),
                            status_str,
                            checks_summary
                        );
                    }
                }

                if json {
                    println!("{}", serde_json::to_string_pretty(&json_results).unwrap());
                }

                if !watch {
                    break;
                }

                std::thread::sleep(std::time::Duration::from_secs(interval));
                // Clear previous output for watch mode (move cursor up)
                print!("\x1b[{}A", checkers.len() + 2);
                println!("{:<20} {:<12} {:<20}", "JAIL", "STATUS", "CHECKS");
                println!("{}", "-".repeat(54));
            }
        }

        Commands::Build {
            file,
            name,
            build_args,
            context,
            dry_run,
        } => {
            use blueprint::{parse_jailfile, BuildContext, TemplateExecutor};

            // Determine context directory
            let context_dir = context.unwrap_or_else(|| {
                file.parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| std::env::current_dir().unwrap())
            });

            // Parse the Jailfile
            let content = std::fs::read_to_string(&file).map_err(|e| {
                error::Error::TemplateParseFailed(format!(
                    "Failed to read {}: {}",
                    file.display(),
                    e
                ))
            })?;
            let jailfile = parse_jailfile(&content)?;

            // Determine jail name
            let jail_name = name
                .or_else(|| jailfile.metadata.name.clone())
                .unwrap_or_else(|| "unnamed".to_string());

            // Determine target path
            let config = manifest::load(&cli.config)?;
            let target_path = config.config.data_dir.join("jails").join(&jail_name);

            // Check if base release exists and copy it
            if let Some(release) = &jailfile.from {
                let bs = provision::Provisioner::from_config(&config.config)?;
                let release_path = config.config.releases_dir.join(release);

                if !release_path.exists() {
                    println!("Base release '{}' not found. Bootstrapping...", release);
                    bs.bootstrap(release, false)?;
                }

                // Copy release to target (if not dry run)
                if !dry_run && !target_path.exists() {
                    println!("Creating jail root from {}...", release);
                    std::fs::create_dir_all(&target_path)?;
                    // Use cp -a for full copy preserving permissions
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

            // Create build context
            let mut ctx =
                BuildContext::new(&context_dir, &target_path, &jail_name).verbose(cli.verbose);

            // Set build arguments from command line
            for (key, value) in build_args {
                ctx.set_arg(&key, &value);
            }

            // Create and run executor
            let mut executor = TemplateExecutor::new(ctx).dry_run(dry_run);

            if dry_run {
                println!("=== DRY RUN - No changes will be made ===\n");
            }

            println!("Building jail '{}' from {}", jail_name, file.display());
            executor.execute(&jailfile)?;

            if !dry_run {
                println!("\nBuild complete! Jail root: {}", target_path.display());
                println!("Add the jail to blackship.toml to manage it:");
                println!("  [[jails]]");
                println!("  name = \"{}\"", jail_name);
                println!("  path = \"{}\"", target_path.display());
            }
        }

        Commands::Template { action } => {
            use blueprint::{parse_jailfile, Instruction};

            match action {
                TemplateAction::List => {
                    use std::path::Path;

                    /// Represents a discovered template file
                    struct TemplateInfo {
                        name: String,
                        path: std::path::PathBuf,
                        base_release: Option<String>,
                    }

                    /// Check if a file is a valid template based on its name
                    fn is_template_file(path: &Path) -> bool {
                        let file_name = match path.file_name().and_then(|n| n.to_str()) {
                            Some(name) => name,
                            None => return false,
                        };

                        // Match "Jailfile" or "Jailfile.*"
                        if file_name == "Jailfile" || file_name.starts_with("Jailfile.") {
                            return true;
                        }

                        // Match "*.jail" files
                        if file_name.ends_with(".jail") {
                            return true;
                        }

                        false
                    }

                    /// Try to extract base release from a template file
                    fn extract_base_release(path: &Path) -> Option<String> {
                        let content = std::fs::read_to_string(path).ok()?;
                        let jailfile = parse_jailfile(&content).ok()?;
                        jailfile.from
                    }

                    /// Scan a directory for template files
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

                    // 1. Check current directory for Jailfile
                    scan_directory(&cwd, &mut templates);

                    // 2. Check ./templates subdirectory if it exists
                    let templates_subdir = cwd.join("templates");
                    scan_directory(&templates_subdir, &mut templates);

                    // 3. Try to load config and check data_dir/templates
                    if let Ok(config) = manifest::load(&cli.config) {
                        let data_templates = config.config.data_dir.join("templates");
                        scan_directory(&data_templates, &mut templates);
                    }

                    if templates.is_empty() {
                        println!("No templates found.");
                        println!("Create a Jailfile or place .jail files in ./templates/");
                    } else {
                        println!("Available templates:");

                        // Calculate max name width for alignment
                        let max_name_width = templates.iter().map(|t| t.name.len()).max().unwrap_or(0);

                        for template in &templates {
                            // Format path relative to current directory if possible
                            let display_path = template
                                .path
                                .strip_prefix(&cwd)
                                .map(|p| format!("./{}", p.display()))
                                .unwrap_or_else(|_| template.path.display().to_string());

                            // Format with optional base release
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
        }

        Commands::Expose {
            jail,
            port,
            internal,
            proto,
            bind_ip,
        } => {
            use std::net::IpAddr;

            let config = manifest::load(&cli.config)?;
            let mut bridge = bridge::Bridge::new(config)?.verbose(cli.verbose);

            // Parse bind IP if provided
            let bind_addr: Option<IpAddr> = if let Some(ip_str) = bind_ip {
                Some(ip_str.parse().map_err(|e| {
                    error::Error::Network(format!("Invalid bind IP '{}': {}", ip_str, e))
                })?)
            } else {
                None
            };

            // Expose the port through the bridge (uses BulkheadManager)
            let forward = bridge.expose_port(&jail, port, internal, &proto, bind_addr)?;

            println!("Port forwarding configured:");
            println!(
                "  {}:{}/{} -> {}:{}",
                bind_addr
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "*".to_string()),
                port,
                proto,
                forward.jail_ip,
                internal.unwrap_or(port)
            );
            println!("\nPF rule applied: {}", forward.to_pf_rule());
            println!("\nNote: Ensure these lines are in /etc/pf.conf:");
            println!("  rdr-anchor \"blackship\"");
            println!("  anchor \"blackship\"");
        }

        Commands::Ports { jail } => {
            let config = manifest::load(&cli.config)?;
            let bridge = bridge::Bridge::new(config)?;

            println!("Port forwarding status:");
            println!(
                "{:<20} {:<12} {:<18} {:<18}",
                "JAIL", "PROTO", "EXTERNAL", "INTERNAL"
            );
            println!("{}", "-".repeat(70));

            // Get port forwards from bridge's bulkhead manager
            let forwards = if let Some(jail_name) = &jail {
                bridge.get_jail_port_forwards(jail_name)
            } else {
                bridge.list_port_forwards().iter().collect()
            };

            if forwards.is_empty() {
                println!("No port forwards configured.");
            } else {
                for forward in forwards {
                    let bind_str = forward
                        .bind_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "*".to_string());
                    println!(
                        "{:<20} {:<12} {:<18} {:<18}",
                        forward.jail_name,
                        forward.protocol,
                        format!("{}:{}", bind_str, forward.external_port),
                        format!("{}:{}", forward.jail_ip, forward.internal_port)
                    );
                }
            }

            println!("\nTo expose a port:");
            println!("  blackship expose <jail> -p <port> [--bind-ip <ip>]");
        }

        Commands::Unexpose { jail } => {
            let config = manifest::load(&cli.config)?;
            let mut bridge = bridge::Bridge::new(config)?.verbose(cli.verbose);
            bridge.remove_port_forwards(&jail)?;
            println!("Removed all port forwards for jail '{}'", jail);
        }

        Commands::Cleanup { jail, force } => {
            let config = manifest::load(&cli.config)?;
            let mut bridge = bridge::Bridge::new(config)?;
            bridge.cleanup(&jail, force)?;
        }

        Commands::Export {
            jail,
            output,
            zfs_send,
        } => {
            let config = manifest::load(&cli.config)?;

            // Find jail config
            let jail_def = config
                .get_jail(&jail)
                .ok_or_else(|| error::Error::JailNotFound(jail.clone()))?;

            let jail_path = jail_def.effective_path(&config.config);

            // Determine output path
            let output_path =
                output.unwrap_or_else(|| std::path::PathBuf::from(format!("{}.tar.zst", jail)));

            let hostname = jail_def.hostname.as_deref();
            let ip = jail_def
                .network
                .as_ref()
                .and_then(|n| n.ip)
                .map(|ip| ip.to_string());

            if zfs_send {
                // Check if ZFS is enabled
                if !config.config.zfs_enabled {
                    return Err(error::Error::ZfsNotEnabled);
                }
                let pool = config
                    .config
                    .zpool
                    .as_ref()
                    .ok_or(error::Error::ZfsNotEnabled)?;
                let dataset = format!("{}/{}/jails/{}", pool, config.config.dataset, jail);
                export::export_jail_zfs(&jail, &dataset, &output_path, hostname, ip.as_deref())?;
            } else {
                export::export_jail(&jail, &jail_path, &output_path, hostname, ip.as_deref())?;
            }
        }

        Commands::Import { file, name, force } => {
            let config = manifest::load(&cli.config)?;

            // Determine target path
            let target_name = name.as_deref().unwrap_or("imported");
            let target_path = config.config.data_dir.join("jails").join(target_name);

            // Check if target exists
            if target_path.exists() && !force {
                return Err(error::Error::JailOperation(format!(
                    "Jail path {} already exists. Use --force to overwrite.",
                    target_path.display()
                )));
            }

            let imported_name = export::import_jail(&file, &target_path, name.as_deref())?;

            println!("\nTo add the imported jail to your config:");
            println!("  [[jails]]");
            println!("  name = \"{}\"", imported_name);
            println!("  path = \"{}\"", target_path.display());
        }

        Commands::Snapshot { action } => {
            let config = manifest::load(&cli.config)?;

            // Require ZFS for snapshots
            if !config.config.zfs_enabled {
                return Err(error::Error::ZfsNotEnabled);
            }

            let pool = config
                .config
                .zpool
                .as_ref()
                .ok_or(error::Error::ZfsNotEnabled)?;
            let zfs = zfs::ZfsManager::new(pool, &config.config.dataset);

            match action {
                SnapshotAction::Create { jail, name } => {
                    // Verify jail exists in config
                    if config.get_jail(&jail).is_none() {
                        return Err(error::Error::JailNotFound(jail.clone()));
                    }

                    let snap_name = zfs.create_snapshot(&jail, name.as_deref())?;
                    println!("Created snapshot: {}@{}", jail, snap_name);
                }
                SnapshotAction::List { jail, json } => {
                    // Verify jail exists in config
                    if config.get_jail(&jail).is_none() {
                        return Err(error::Error::JailNotFound(jail.clone()));
                    }

                    let snapshots = zfs.list_snapshots(&jail)?;

                    if json {
                        let json_data: Vec<_> = snapshots
                            .iter()
                            .map(|s| {
                                serde_json::json!({
                                    "name": s.name,
                                    "creation": s.creation,
                                    "used": s.used,
                                    "refer": s.refer
                                })
                            })
                            .collect();
                        println!("{}", serde_json::to_string_pretty(&json_data).unwrap());
                    } else if snapshots.is_empty() {
                        println!("No snapshots for jail '{}'.", jail);
                    } else {
                        println!("Snapshots for jail '{}':", jail);
                        println!(
                            "{:<30} {:<24} {:<10} {:<10}",
                            "NAME", "CREATED", "USED", "REFER"
                        );
                        println!("{}", "-".repeat(76));
                        for snap in snapshots {
                            println!(
                                "{:<30} {:<24} {:<10} {:<10}",
                                snap.name, snap.creation, snap.used, snap.refer
                            );
                        }
                    }
                }
                SnapshotAction::Rollback {
                    jail,
                    snapshot,
                    force,
                } => {
                    // Verify jail exists in config
                    if config.get_jail(&jail).is_none() {
                        return Err(error::Error::JailNotFound(jail.clone()));
                    }

                    // Check if jail is running
                    if jail::jail_getid(&jail).is_ok() {
                        return Err(error::Error::JailOperation(format!(
                            "Jail '{}' is running. Stop it first with 'blackship down {}'",
                            jail, jail
                        )));
                    }

                    zfs.rollback_snapshot(&jail, &snapshot, force)?;
                    println!("Rolled back jail '{}' to snapshot '{}'", jail, snapshot);
                }
                SnapshotAction::Delete { jail, snapshot } => {
                    // Verify jail exists in config
                    if config.get_jail(&jail).is_none() {
                        return Err(error::Error::JailNotFound(jail.clone()));
                    }

                    zfs.delete_snapshot(&jail, &snapshot)?;
                    println!("Deleted snapshot '{}@{}'", jail, snapshot);
                }
            }
        }

        Commands::Clone { source, name } => {
            let config = manifest::load(&cli.config)?;

            // Require ZFS for cloning
            if !config.config.zfs_enabled {
                return Err(error::Error::ZfsNotEnabled);
            }

            // Parse source format: jail@snapshot
            let parts: Vec<&str> = source.split('@').collect();
            if parts.len() != 2 {
                return Err(error::Error::JailOperation(
                    "Source must be in format 'jail@snapshot'".into(),
                ));
            }
            let (source_jail, snapshot) = (parts[0], parts[1]);

            // Verify source jail exists
            if config.get_jail(source_jail).is_none() {
                return Err(error::Error::JailNotFound(source_jail.to_string()));
            }

            // Check new name doesn't already exist
            if config.get_jail(&name).is_some() {
                return Err(error::Error::JailOperation(format!(
                    "Jail '{}' already exists in config",
                    name
                )));
            }

            let pool = config
                .config
                .zpool
                .as_ref()
                .ok_or(error::Error::ZfsNotEnabled)?;
            let zfs = zfs::ZfsManager::new(pool, &config.config.dataset);

            let new_path = zfs.clone_from_snapshot(source_jail, snapshot, &name)?;

            println!(
                "Cloned '{}@{}' to new jail '{}'",
                source_jail, snapshot, name
            );
            println!("Path: {}", new_path.display());
            println!("\nTo use this jail, add it to blackship.toml:");
            println!("  [[jails]]");
            println!("  name = \"{}\"", name);
            println!("  path = \"{}\"", new_path.display());
        }

        // Commands that require config and bridge
        _ => {
            let config = manifest::load(&cli.config)?;
            let mut bridge = bridge::Bridge::new(config)?.verbose(cli.verbose);

            match cli.command {
                Commands::Up { jail, all, dry_run } => {
                    // Require either jail name or --all
                    if jail.is_none() && !all {
                        eprintln!("Error: specify a jail name or use --all to start all jails");
                        std::process::exit(1);
                    }
                    if dry_run {
                        bridge.up_dry_run(jail.as_deref())?;
                    } else {
                        bridge.up(jail.as_deref())?;
                    }
                }
                Commands::Down { jail, all, dry_run } => {
                    // Require either jail name or --all
                    if jail.is_none() && !all {
                        eprintln!("Error: specify a jail name or use --all to stop all jails");
                        std::process::exit(1);
                    }
                    if dry_run {
                        bridge.down_dry_run(jail.as_deref())?;
                    } else {
                        bridge.down(jail.as_deref())?;
                    }
                }
                Commands::Restart { jail, all, dry_run } => {
                    // Require either jail name or --all
                    if jail.is_none() && !all {
                        eprintln!("Error: specify a jail name or use --all to restart all jails");
                        std::process::exit(1);
                    }
                    if dry_run {
                        bridge.down_dry_run(jail.as_deref())?;
                        bridge.up_dry_run(jail.as_deref())?;
                    } else {
                        bridge.restart(jail.as_deref())?;
                    }
                }
                Commands::Ps { json } => {
                    bridge.ps(json)?;
                }
                Commands::Check => {
                    bridge.check()?;
                }
                Commands::Init => {
                    // Initialize PF firewall anchor for port forwarding
                    bridge.init_bulkhead()?;
                    println!("Initialization complete.");
                    println!("PF anchor 'blackship' initialized for port forwarding.");
                }
                // Already handled above
                Commands::Exec { .. }
                | Commands::Console { .. }
                | Commands::Bootstrap { .. }
                | Commands::Releases { .. }
                | Commands::Network { .. }
                | Commands::Health { .. }
                | Commands::Build { .. }
                | Commands::Template { .. }
                | Commands::Expose { .. }
                | Commands::Ports { .. }
                | Commands::Unexpose { .. }
                | Commands::Cleanup { .. }
                | Commands::Export { .. }
                | Commands::Import { .. }
                | Commands::Snapshot { .. }
                | Commands::Clone { .. }
                | Commands::Completion { .. }
                | Commands::Supervise
                | Commands::Logs { .. } => unreachable!(),
            }
        }
    }

    Ok(())
}
