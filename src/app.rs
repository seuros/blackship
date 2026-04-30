//! Application entry point and CLI dispatch.

use crate::bridge::Bridge;
use crate::cli::{Cli, Commands};
use crate::error::Result;
use crate::{commands, console, manifest};
use std::path::PathBuf;

/// Run the Blackship CLI application.
pub fn run() -> Result<()> {
    let cli = Cli::parse_args();
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
            } => commands::container::run_ephemeral_jail(
                &name,
                &release,
                detach,
                network.as_deref(),
                &command,
                self.load_optional_config().as_ref(),
            ),

            Commands::Cp {
                source,
                dest,
                preserve,
            } => commands::container::copy_files(
                &source,
                &dest,
                preserve,
                self.load_optional_config().as_ref(),
            ),

            Commands::Rm {
                jails,
                force,
                volumes,
            } => commands::container::remove_jails(
                &jails,
                force,
                volumes,
                self.load_optional_config().as_ref(),
            ),

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

            Commands::Network { action } => commands::network::handle(action),

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
                println!("System setup complete.");
                println!("PF anchor 'blackship' initialized for port forwarding.");
                Ok(())
            }
        }
    }

    fn load_config(&self) -> Result<manifest::BlackshipConfig> {
        manifest::load(&self.config_path)
    }

    fn load_optional_config(&self) -> Option<manifest::BlackshipConfig> {
        self.load_config().ok()
    }

    fn verbose_bridge(&self) -> Result<Bridge> {
        Ok(Bridge::new(self.load_config()?)?.verbose(self.verbose))
    }
}
