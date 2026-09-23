//! Manual QoS phase control for jails started outside `supervise`.

use std::path::Path;

use crate::bridge::{Bridge, ShiftOutcome, phase_label};
use crate::error::{Error, Result};
use crate::manifest;
use crate::scope::QosPhase;

pub fn handle_qos(
    config_path: &Path,
    verbose: bool,
    jail: String,
    steady: bool,
    startup: bool,
    show: bool,
) -> Result<()> {
    if steady && startup {
        return Err(Error::ConfigValidation(
            "--steady and --startup are mutually exclusive".to_string(),
        ));
    }

    let config = manifest::load(config_path)?;
    let bridge = Bridge::open(config, verbose)?;

    if show || !(steady || startup) {
        let phase = bridge.qos_phase(&jail)?;
        println!("{}: {}", jail, phase_label(phase));
        return Ok(());
    }

    let target = if steady {
        QosPhase::Steady
    } else {
        QosPhase::Startup
    };

    match bridge.shift_qos(&jail, target)? {
        ShiftOutcome::Shifted => {
            println!("{}: shifted to {} profile", jail, phase_label(target));
        }
        ShiftOutcome::AlreadyInPhase => {
            println!("{}: already in {} profile", jail, phase_label(target));
        }
        ShiftOutcome::NotConfigured => {
            println!(
                "{}: no [jails.qos] block configured; resource limits are static",
                jail
            );
        }
    }

    Ok(())
}
