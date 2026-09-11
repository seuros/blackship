//! Lifecycle commands: up, down, restart, ps, check, setup

use crate::bridge;
use crate::error::Result;

pub fn handle_up(
    bridge: &mut bridge::Bridge,
    jail: Option<&str>,
    all: bool,
    dry_run: bool,
) -> Result<()> {
    if jail.is_none() && !all {
        eprintln!("Error: specify a jail name or use --all to start all jails");
        std::process::exit(1);
    }
    if dry_run {
        bridge.up_dry_run(jail)?;
    } else {
        bridge.up(jail)?;
    }
    Ok(())
}

pub fn handle_down(
    bridge: &mut bridge::Bridge,
    jail: Option<&str>,
    all: bool,
    dry_run: bool,
) -> Result<()> {
    if jail.is_none() && !all {
        eprintln!("Error: specify a jail name or use --all to stop all jails");
        std::process::exit(1);
    }
    if dry_run {
        bridge.down_dry_run(jail)?;
    } else {
        bridge.down(jail)?;
    }
    Ok(())
}

pub fn handle_eva(
    bridge: &mut bridge::Bridge,
    jail: Option<&str>,
    all: bool,
    dry_run: bool,
) -> Result<()> {
    if jail.is_none() && !all {
        eprintln!("Error: specify a jail name or use --all to update all jails");
        std::process::exit(1);
    }
    if dry_run {
        bridge.eva_dry_run(jail)?;
    } else {
        bridge.eva(jail)?;
    }
    Ok(())
}

pub fn handle_restart(
    bridge: &mut bridge::Bridge,
    jail: Option<&str>,
    all: bool,
    dry_run: bool,
) -> Result<()> {
    if jail.is_none() && !all {
        eprintln!("Error: specify a jail name or use --all to restart all jails");
        std::process::exit(1);
    }
    if dry_run {
        bridge.down_dry_run(jail)?;
        bridge.up_dry_run(jail)?;
    } else {
        bridge.restart(jail)?;
    }
    Ok(())
}
