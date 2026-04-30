//! Jail log inspection command.

use std::path::Path;

use crate::console;
use crate::error::Result;
use crate::{error, manifest};

pub fn handle(config_path: &Path, jail: &str, follow: bool, lines: usize) -> Result<()> {
    let config = manifest::load(config_path)?;

    let (service_name, full_name) = config
        .resolve_jail_names(jail)
        .ok_or_else(|| error::Error::JailNotFound(jail.to_string()))?;
    let jail_def = config
        .get_jail(&service_name)
        .ok_or_else(|| error::Error::JailNotFound(jail.to_string()))?;

    let jail_path = jail_def.effective_path(&config.config, &full_name);
    let log_dir = jail_path.join("var/log");
    let log_files = ["messages", "console.log", "daemon.log", "syslog"];

    let log_path = log_files
        .iter()
        .map(|file| log_dir.join(file))
        .find(|path| path.exists())
        .unwrap_or_else(|| log_dir.join("messages"));

    let mut tail_args = Vec::new();
    if follow {
        tail_args.push("-f".to_string());
    }
    tail_args.push("-n".to_string());
    tail_args.push(lines.to_string());

    let relative_log_path = log_path.strip_prefix(&jail_path).unwrap_or(&log_path);
    tail_args.push(format!("/{}", relative_log_path.display()));

    let mut cmd = vec!["tail".to_string()];
    cmd.extend(tail_args);

    let status = console::exec_in_jail(&full_name, &cmd, &console::ExecOptions::default())?;
    std::process::exit(status.code().unwrap_or(1));
}
