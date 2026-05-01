//! Application entry point and CLI dispatch.

use crate::bridge::Bridge;
use crate::cli::{Cli, Commands};
use crate::error::{Error, Result};
use crate::{commands, console, manifest};
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;

/// Run the Blackship CLI application.
pub fn run() -> Result<()> {
    let cli = Cli::parse_args();
    maybe_escalate_to_root(&cli.command)?;
    let ctx = AppContext::new(cli.config, cli.verbose);
    ctx.dispatch(cli.command)
}

struct AppContext {
    config_path: PathBuf,
    verbose: bool,
}

impl AppContext {
    fn new(config_path: PathBuf, verbose: bool) -> Self {
        Self {
            config_path,
            verbose,
        }
    }

    fn dispatch(self, command: Commands) -> Result<()> {
        match command {
            Commands::Exec {
                jail,
                user,
                workdir,
                env,
                command,
            } => {
                let opts = console::ExecOptions {
                    user,
                    workdir,
                    env,
                    ..Default::default()
                };
                let status = console::exec_in_jail(&jail, &command, &opts)?;
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
                    config.as_ref(),
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
                commands::container::remove_jails(&jails, force, volumes, config.as_ref())
            }

            Commands::Console { jail, user } => {
                let status = console::console(&jail, &user)?;
                std::process::exit(status.code().unwrap_or(1));
            }

            Commands::Completion { shell } => {
                crate::cli::Cli::generate_completion(shell);
                Ok(())
            }

            Commands::Init {
                file,
                release,
                toml,
                force,
            } => commands::build::handle_init(file, release, toml, force),

            Commands::Armada { files, action } => {
                commands::armada::handle(&self.config_path, self.verbose, files, action)
            }

            Commands::Logs {
                jail,
                follow,
                lines,
            } => commands::logs::handle(&self.config_path, &jail, follow, lines),

            Commands::Supervise => commands::supervise::handle(&self.config_path, self.verbose),

            Commands::Bootstrap {
                release,
                force,
                archives,
            } => commands::bootstrap::handle_bootstrap(&self.config_path, release, force, archives),

            Commands::Releases { action, json } => {
                commands::bootstrap::handle_releases(&self.config_path, action, json)
            }

            Commands::Network { action } => {
                let config = self.load_config_if_present()?;
                commands::network::handle(config.as_ref(), action)
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
                file,
                name,
                build_args,
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
                jail,
                port,
                internal,
                proto,
                bind_ip,
            ),

            Commands::Ports { jail } => commands::ports::handle_ports(&self.config_path, jail),

            Commands::Unexpose { jail } => {
                commands::ports::handle_unexpose(&self.config_path, self.verbose, jail)
            }

            Commands::Cleanup { jail, force } => {
                let config = self.load_config()?;
                let mut bridge = Bridge::new(config)?;
                bridge.cleanup(&jail, force)?;
                Ok(())
            }

            Commands::Export {
                jail,
                output,
                zfs_send,
            } => commands::snapshot::handle_export(&self.config_path, jail, output, zfs_send),

            Commands::Import { file, name, force } => {
                commands::snapshot::handle_import(&self.config_path, file, name, force)
            }

            Commands::Snapshot { action } => {
                commands::snapshot::handle_snapshot(&self.config_path, action)
            }

            Commands::Clone { source, name } => {
                commands::snapshot::handle_clone(&self.config_path, source, name)
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

            Commands::Ps { json } => {
                let bridge = self.verbose_bridge()?;
                bridge.ps(json)?;
                Ok(())
            }

            Commands::Check => {
                let bridge = self.verbose_bridge()?;
                bridge.check()?;
                Ok(())
            }

            Commands::Setup => {
                let mut bridge = self.verbose_bridge()?;
                bridge.prepare_host()?;
                bridge.init_bulkhead()?;
                bridge.sync_bulkhead()?;
                println!("System setup complete.");
                println!("PF anchor 'blackship' initialized for port forwarding.");
                Ok(())
            }
        }
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

fn maybe_escalate_to_root(command: &Commands) -> Result<()> {
    if !command.requires_root() || unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }

    let escalator = find_escalator().ok_or_else(|| {
        Error::User(
            "This command requires root privileges. Blackship could not find 'sudo' or 'doas' in PATH. Install one of them, or run this command as root.".into(),
        )
    })?;

    let executable = std::env::current_exe()
        .map_err(|e| Error::User(format!("Failed to locate current executable: {}", e)))?;
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();

    let err = ProcessCommand::new(escalator)
        .arg(&executable)
        .args(args)
        .exec();

    Err(Error::User(format!(
        "Failed to re-exec through '{}': {}",
        escalator, err
    )))
}

fn find_escalator() -> Option<&'static str> {
    ["sudo", "doas"]
        .into_iter()
        .find(|name| command_exists(name))
}

fn command_exists(command: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path_var| {
        std::env::split_paths(&path_var).any(|dir| {
            let candidate = dir.join(command);
            std::fs::metadata(&candidate).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
    })
}
