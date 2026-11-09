//! Lifecycle commands: up, down, restart, ps, check, setup

use crate::bridge;
use crate::error::{Error, Result};

fn validate_selection(jail: Option<&str>, all: bool, operation: &str) -> Result<()> {
    if jail.is_none() && !all {
        return Err(Error::InvalidArgument(format!(
            "specify a jail name or use --all to {operation} all jails"
        )));
    }
    Ok(())
}

fn plan_value(operation: &str, steps: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "operation": operation,
        "dry_run": true,
        "steps": steps,
    })
}

pub fn up_plan(
    bridge: &bridge::Bridge,
    jail: Option<&str>,
    all: bool,
) -> Result<serde_json::Value> {
    validate_selection(jail, all, "start")?;
    Ok(plan_value("up", bridge.up_plan_data(jail)?))
}

pub fn down_plan(
    bridge: &bridge::Bridge,
    jail: Option<&str>,
    all: bool,
) -> Result<serde_json::Value> {
    validate_selection(jail, all, "stop")?;
    Ok(plan_value("down", bridge.down_plan_data(jail)?))
}

pub fn restart_plan(
    bridge: &bridge::Bridge,
    jail: Option<&str>,
    all: bool,
) -> Result<serde_json::Value> {
    validate_selection(jail, all, "restart")?;
    let mut steps = bridge.down_plan_data(jail)?;
    steps.extend(bridge.up_plan_data(jail)?);
    Ok(plan_value("restart", steps))
}

pub fn eva_plan(
    bridge: &bridge::Bridge,
    jail: Option<&str>,
    all: bool,
) -> Result<serde_json::Value> {
    validate_selection(jail, all, "update")?;
    Ok(plan_value("eva", bridge.eva_plan_data(jail)?))
}

pub fn handle_up(
    bridge: &mut bridge::Bridge,
    jail: Option<&str>,
    all: bool,
    dry_run: bool,
) -> Result<()> {
    validate_selection(jail, all, "start")?;
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
    validate_selection(jail, all, "stop")?;
    if dry_run {
        bridge.down_dry_run(jail)?;
    } else {
        bridge.down(jail)?;
    }
    Ok(())
}

pub fn handle_eva(
    bridge: &bridge::Bridge,
    jail: Option<&str>,
    all: bool,
    dry_run: bool,
) -> Result<()> {
    validate_selection(jail, all, "update")?;
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
    validate_selection(jail, all, "restart")?;
    if dry_run {
        bridge.down_dry_run(jail)?;
        bridge.up_dry_run(jail)?;
    } else {
        bridge.restart(jail)?;
    }
    Ok(())
}
