//! Manual `QoS` phase control for jails started outside `supervise`.

use std::path::Path;

use crate::bridge::{Bridge, ShiftOutcome};
use crate::error::{Error, Result};
use crate::manifest;
use crate::scope::QosPhase;

/// What `blackship qos` was asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QosRequest {
    /// Print the jail's current phase.
    Show,
    /// Move the jail to this phase's resource profile.
    Shift(QosPhase),
}

impl QosRequest {
    /// Interpret the phase flags; `--show`, or no flag, wins over a shift.
    ///
    /// # Errors
    ///
    /// [`Error::ConfigValidation`] when both `--steady` and `--startup` are given.
    pub fn from_flags(steady: bool, startup: bool, show: bool) -> Result<Self> {
        if steady && startup {
            return Err(Error::ConfigValidation(
                "--steady and --startup are mutually exclusive".to_string(),
            ));
        }
        Ok(if show || !(steady || startup) {
            Self::Show
        } else if steady {
            Self::Shift(QosPhase::Steady)
        } else {
            Self::Shift(QosPhase::Startup)
        })
    }
}

pub fn handle_qos(
    config_path: &Path,
    verbose: bool,
    jail: &str,
    request: QosRequest,
) -> Result<()> {
    let config = manifest::load(config_path)?;
    let bridge = Bridge::open(config, verbose)?;

    let target = match request {
        QosRequest::Show => {
            let phase = bridge.qos_phase(jail)?;
            println!("{}: {}", jail, phase.as_str());
            return Ok(());
        }
        QosRequest::Shift(target) => target,
    };

    match bridge.shift_qos(jail, target)? {
        ShiftOutcome::Shifted => {
            println!("{}: shifted to {} profile", jail, target.as_str());
        }
        ShiftOutcome::AlreadyInPhase => {
            println!("{}: already in {} profile", jail, target.as_str());
        }
        ShiftOutcome::NotConfigured => {
            println!("{jail}: no [jails.qos] block configured; resource limits are static");
        }
    }

    Ok(())
}
