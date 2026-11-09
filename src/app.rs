//! Application entry point and CLI dispatch.

use crate::bridge::Bridge;
use crate::cli::{Cli, Commands, NetworkAction, OutputFormat};
use crate::error::{Error, Result};
use crate::output::CliError;
use crate::{commands, console, manifest};
use std::ffi::{OsStr, OsString};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};

/// Run the Blackship CLI application.
///
/// # Errors
///
/// Parsing, privilege escalation or the subcommand fails; rendered in the
/// requested output format.
pub fn run() -> std::result::Result<(), CliError> {
    let cli = parse_cli()?;
    let format = cli.format;
    run_cli(cli).map_err(|error| CliError::new(format, error))
}

fn parse_cli() -> std::result::Result<Cli, CliError> {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if requested_json(&args) {
        let args: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
        match Cli::parse_from(&args) {
            Ok(cli) => Ok(cli),
            Err(
                usage_rs::Error::Help { .. }
                | usage_rs::Error::HelpAll { .. }
                | usage_rs::Error::Version { .. },
            ) => Ok(Cli::parse_args()),
            Err(error) => {
                let message = usage_rs::render_failure_plain(Cli::spec(), &args, &error);
                Err(CliError::new(
                    OutputFormat::Json,
                    Error::CliParse(message.trim().to_string()),
                ))
            }
        }
    } else {
        Ok(Cli::parse_args())
    }
}

fn requested_json(args: &[OsString]) -> bool {
    let mut args = args.iter().take_while(|arg| arg.as_os_str() != "--");
    while let Some(arg) = args.next() {
        if arg == "--format=json" {
            return true;
        }
        if arg == "--format" && args.next().is_some_and(|value| value == "json") {
            return true;
        }
    }
    false
}

fn run_cli(cli: Cli) -> Result<()> {
    if cli.format == OutputFormat::Json && !cli.command.supports_machine_output() {
        return Err(Error::UnsupportedOutputFormat);
    }

    maybe_escalate_to_root(&cli.command, cli.no_escalate, cli.non_interactive)?;
    let ctx = AppContext::new(cli.config, cli.verbose, cli.format);
    ctx.init_telemetry();
    let result = ctx.dispatch(cli.command);
    crate::telemetry::shutdown();
    result
}

struct AppContext {
    config_path: PathBuf,
    verbose: bool,
    format: OutputFormat,
}

impl AppContext {
    const fn new(config_path: PathBuf, verbose: bool, format: OutputFormat) -> Self {
        Self {
            config_path,
            verbose,
            format,
        }
    }

    #[allow(clippy::too_many_lines)] // flat one-arm-per-subcommand dispatch table
    fn dispatch(self, command: Commands) -> Result<()> {
        match command {
            Commands::Exec {
                jail,
                user,
                workdir,
                env,
                clear_env,
                command,
            } => {
                let jail = self.resolve_runtime_jail(&jail);
                let opts = console::ExecOptions {
                    user,
                    workdir,
                    env: crate::cli::into_pairs(env),
                    clear_env,
                };
                let status = console::exec_in_jail(&jail, &command, &opts)?;
                crate::telemetry::shutdown();
                std::process::exit(status.code().unwrap_or(1));
            }

            Commands::Run {
                name,
                release,
                detach,
                network,
                command,
            } => {
                let config = self.load_config_if_present()?;
                commands::container::run_ephemeral_jail(
                    &name,
                    &release,
                    detach,
                    network.as_deref(),
                    &command,
                    config,
                )
            }

            Commands::Cp {
                source,
                dest,
                preserve,
            } => {
                let config = self.load_config_if_present()?;
                commands::container::copy_files(&source, &dest, preserve, config.as_ref())
            }

            Commands::Rm {
                jails,
                force,
                volumes,
            } => {
                let config = self.load_config_if_present()?;
                commands::container::remove_jails(&jails, force, volumes, config)
            }

            Commands::Console { jail, user } => {
                let jail = self.resolve_runtime_jail(&jail);
                let status = console::console(&jail, &user)?;
                crate::telemetry::shutdown();
                std::process::exit(status.code().unwrap_or(1));
            }

            Commands::Completion { shell } => {
                crate::cli::Cli::generate_completion(shell);
                Ok(())
            }

            Commands::Capabilities => {
                if self.format == OutputFormat::Json {
                    crate::output::print_success(&commands::capabilities::data()?)
                } else {
                    commands::capabilities::handle()
                }
            }

            Commands::Init {
                file,
                release,
                toml,
                force,
            } => commands::build::handle_init(&file, release, toml, force),

            Commands::Armada { files, action } => {
                commands::armada::handle(&self.config_path, self.verbose, &files, action)
            }

            Commands::Migrate {
                jail,
                target,
                remote_dataset,
                keep,
            } => commands::migrate::handle_migrate(
                &self.config_path,
                &jail,
                &target,
                remote_dataset,
                keep,
            ),

            Commands::Stats { jail, json } => {
                commands::stats::handle(&self.config_path, jail, json)
            }

            Commands::Logs {
                jail,
                follow,
                lines,
            } => commands::logs::handle(&self.config_path, &jail, follow, lines),

            Commands::Supervise => commands::supervise::handle(&self.config_path, self.verbose),

            #[cfg(feature = "mcp")]
            Commands::Mcp => commands::mcp::handle(&self.config_path),

            Commands::Bootstrap {
                release,
                force,
                archives,
                pkgbase,
            } => commands::bootstrap::handle_bootstrap(
                &self.config_path,
                &release,
                force,
                archives,
                pkgbase,
            ),

            Commands::Releases { action, json } => {
                commands::bootstrap::handle_releases(&self.config_path, action, json)
            }

            Commands::Network { action } => {
                let config = self.load_config_if_present()?;
                if self.format == OutputFormat::Json && matches!(&action, NetworkAction::List) {
                    let networks = commands::network::list(config.as_ref())?;
                    crate::output::print_success(&networks)
                } else {
                    commands::network::handle(config.as_ref(), action)
                }
            }

            Commands::Health {
                jail,
                watch,
                interval,
                json,
            } => commands::health::handle(&self.config_path, jail, watch, interval, json),

            Commands::Build {
                file,
                name,
                build_args,
                context,
                dry_run,
            } => commands::build::handle_build(
                &self.config_path,
                self.verbose,
                &file,
                name,
                crate::cli::into_pairs(build_args),
                context,
                dry_run,
            ),

            Commands::Template { action } => {
                commands::build::handle_template(&self.config_path, action)
            }

            Commands::Expose {
                jail,
                port,
                internal,
                proto,
                bind_ip,
            } => commands::ports::handle_expose(
                &self.config_path,
                self.verbose,
                &jail,
                port,
                internal,
                &proto,
                bind_ip,
            ),

            Commands::Ports { jail } => {
                if self.format == OutputFormat::Json {
                    let forwards = commands::ports::list_ports(&self.config_path, jail.as_deref())?;
                    crate::output::print_success(&forwards)
                } else {
                    commands::ports::handle_ports(&self.config_path, jail.as_deref())
                }
            }

            Commands::Unexpose { jail } => {
                commands::ports::handle_unexpose(&self.config_path, self.verbose, &jail)
            }

            Commands::Cleanup { jail, force } => {
                let config = self.load_config()?;
                let mut bridge = Bridge::new(config)?;
                bridge.cleanup(&jail, force)?;
                Ok(())
            }

            Commands::Qos {
                jail,
                steady,
                startup,
                show,
            } => {
                let request = commands::qos::QosRequest::from_flags(steady, startup, show)?;
                commands::qos::handle_qos(&self.config_path, self.verbose, &jail, request)
            }
            Commands::Audit { jail, json } => {
                commands::audit::handle_audit(&self.config_path, &jail, json)
            }
            Commands::Gc {
                jail,
                dry_run,
                force,
                prune_unreferenced,
                json,
            } => commands::gc::handle_gc(
                &self.config_path,
                self.verbose,
                jail.as_deref(),
                &commands::gc::GcOptions {
                    dry_run,
                    force,
                    prune_unreferenced,
                    json,
                },
            ),

            Commands::Export {
                jail,
                output,
                zfs_send,
            } => commands::snapshot::handle_export(&self.config_path, &jail, output, zfs_send),

            Commands::Import {
                file,
                name,
                force,
                from,
            } => match from {
                Some(from) => commands::foreign::handle_foreign_import(
                    &self.config_path,
                    &file,
                    name,
                    Some(&from),
                ),
                None => commands::snapshot::handle_import(
                    &self.config_path,
                    &file,
                    name.as_deref(),
                    force,
                ),
            },

            Commands::Snapshot { action } => {
                commands::snapshot::handle_snapshot(&self.config_path, action)
            }

            Commands::Commit { jail, release } => {
                commands::snapshot::handle_commit(&self.config_path, &jail, &release)
            }

            Commands::Clone { source, name } => {
                commands::snapshot::handle_clone(&self.config_path, &source, &name)
            }

            Commands::Up { jail, all, dry_run } => {
                let mut bridge = self.verbose_bridge()?;
                commands::lifecycle::handle_up(&mut bridge, jail.as_deref(), all, dry_run)
            }

            Commands::Down { jail, all, dry_run } => {
                let mut bridge = self.verbose_bridge()?;
                commands::lifecycle::handle_down(&mut bridge, jail.as_deref(), all, dry_run)
            }

            Commands::Restart { jail, all, dry_run } => {
                let mut bridge = self.verbose_bridge()?;
                commands::lifecycle::handle_restart(&mut bridge, jail.as_deref(), all, dry_run)
            }

            Commands::Eva { jail, all, dry_run } => {
                let bridge = self.verbose_bridge()?;
                commands::lifecycle::handle_eva(&bridge, jail.as_deref(), all, dry_run)
            }

            Commands::Ps { json } => {
                let bridge = self.verbose_bridge()?;
                if self.format == OutputFormat::Json {
                    crate::output::print_success(&bridge.ps_data())
                } else {
                    bridge.ps(json);
                    Ok(())
                }
            }

            Commands::Check => {
                let bridge = self.verbose_bridge()?;
                if self.format == OutputFormat::Json {
                    crate::output::print_success(&bridge.check_data()?)
                } else {
                    bridge.check()
                }
            }

            Commands::Setup { enable_pf } => self.setup(enable_pf),
        }
    }

    /// `blackship setup`: enable PF, recreate persisted networks, prepare the host.
    fn setup(&self, enable_pf: bool) -> Result<()> {
        if enable_pf {
            crate::bulkhead::enable_pf()?;
        }
        let config = manifest::load_or_default(&self.config_path)?;

        // Bridges and eifaces do not survive a reboot; their records do.
        let net_store = crate::network::NetworkStore::from_config(Some(&config));
        for mut record in net_store.list()? {
            let name = record.name.clone();
            match crate::network::ensure::ensure_network(&mut record) {
                Ok(changed) => {
                    if changed {
                        net_store.save(&record)?;
                    }
                    println!("Network '{}' ready on bridge '{}'.", name, record.bridge);
                }
                Err(e) => {
                    eprintln!("Warning: failed to reapply network '{name}': {e}");
                }
            }
        }

        let mut bridge = Bridge::new(config)?.verbose(self.verbose);
        bridge.prepare_host()?;
        Bridge::init_bulkhead()?;
        bridge.sync_bulkhead()?;
        println!("System setup complete.");
        println!("PF anchor 'blackship' initialized for port forwarding.");
        Ok(())
    }

    /// Resolve a runtime jail target through the config when possible, so
    /// short names, prefixes, and full names all work for exec/console/logs.
    fn resolve_runtime_jail(&self, name: &str) -> String {
        if let Ok(Some(config)) = self.load_config_if_present()
            && let Some((_, full_name)) = config.resolve_jail_names(name)
        {
            return full_name;
        }
        name.to_string()
    }

    /// Arm the OTLP exporter when the manifest carries a `[telemetry]` block.
    /// A missing or unreadable manifest simply leaves telemetry disabled —
    /// dispatch reports that failure properly on its own.
    fn init_telemetry(&self) {
        let config = self.load_config_if_present().ok().flatten();
        crate::telemetry::init(config.as_ref().and_then(|c| c.telemetry.as_ref()));
    }

    fn load_config(&self) -> Result<manifest::BlackshipConfig> {
        manifest::load(&self.config_path)
    }

    fn load_config_if_present(&self) -> Result<Option<manifest::BlackshipConfig>> {
        match self.load_config() {
            Ok(config) => Ok(Some(config)),
            Err(Error::ConfigRead { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    fn verbose_bridge(&self) -> Result<Bridge> {
        Ok(Bridge::new(self.load_config()?)?.verbose(self.verbose))
    }
}

fn maybe_escalate_to_root(
    command: &Commands,
    no_escalate: bool,
    non_interactive: bool,
) -> Result<()> {
    let euid = nix::unistd::geteuid();
    if !should_escalate(command.requires_root(), euid.as_raw(), no_escalate)? {
        return Ok(());
    }

    let escalator = find_escalator().ok_or_else(|| {
        Error::User(
            "This command requires root privileges. Blackship could not find 'mdo', 'doas', or 'sudo'. Configure one of them, or run this command as root.".into(),
        )
    })?;

    let executable = std::env::current_exe()
        .map_err(|e| Error::User(format!("Failed to locate current executable: {e}")))?;
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();

    let mut cmd = escalation_command(escalator, &executable, &args, non_interactive);
    let err = cmd.exec();

    Err(Error::User(format!(
        "Failed to re-exec through '{escalator}': {err}"
    )))
}

const MDO: &str = "/usr/bin/mdo";

fn should_escalate(requires_root: bool, euid: u32, no_escalate: bool) -> Result<bool> {
    if !requires_root || euid == 0 {
        Ok(false)
    } else if no_escalate {
        Err(Error::EscalationDisabled { euid })
    } else {
        Ok(true)
    }
}

fn escalation_command(
    escalator: &str,
    executable: &std::path::Path,
    args: &[OsString],
    non_interactive: bool,
) -> ProcessCommand {
    let mut cmd = ProcessCommand::new(escalator);
    if non_interactive && escalator != MDO {
        cmd.arg("-n");
    }
    cmd.arg(executable).args(args);
    if escalator == MDO {
        as_root_env(&mut cmd);
    }
    cmd
}

/// mdo keeps the caller's environment; reset what sudo and doas reset, so
/// default paths resolve under root's home and not the caller's.
fn as_root_env(cmd: &mut ProcessCommand) {
    let home = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(0))
        .ok()
        .flatten()
        .map_or_else(|| PathBuf::from("/root"), |root| root.dir);
    cmd.env("HOME", home)
        .env("USER", "root")
        .env("LOGNAME", "root")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_STATE_HOME");
}

fn find_escalator() -> Option<&'static str> {
    find_escalator_with(|path| {
        if !std::fs::metadata(path)
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        {
            return false;
        }

        path != MDO || mdo_can_elevate(path)
    })
}

fn mdo_can_elevate(path: &str) -> bool {
    // mdo ships in the base system even when the caller has no applicable
    // mac_do rule. Probe its non-interactive authorization so an unusable mdo
    // does not take precedence over a configured doas or sudo.
    ProcessCommand::new(path)
        .arg("/usr/bin/true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn find_escalator_with(mut is_usable: impl FnMut(&str) -> bool) -> Option<&'static str> {
    // Absolute paths: an earlier PATH entry could supply a fake escalator to steal creds.
    // mdo is part of the FreeBSD base system and mac_do recognizes this canonical path.
    const ESCALATORS: [&str; 4] = [
        MDO,
        "/usr/local/bin/doas",
        "/usr/local/bin/sudo",
        "/usr/bin/sudo",
    ];

    ESCALATORS.into_iter().find(|path| is_usable(path))
}

#[cfg(test)]
mod tests;
