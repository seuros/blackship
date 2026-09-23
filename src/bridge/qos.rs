//! Multi-phase QoS: shift a running jail between its startup and steady
//! resource profiles without disturbing custom rctl rules.

use crate::audit::{AuditEvent, AuditRecord};
use crate::error::{Error, Result};
use crate::manifest::JailDef;
use crate::rctl::{QosConfig, ResourceConfig};
use crate::scope::QosPhase;

use super::Bridge;

/// Outcome of a requested QoS shift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftOutcome {
    Shifted,
    AlreadyInPhase,
    NotConfigured,
}

impl Bridge {
    /// The QoS phase currently recorded for a jail, if any.
    pub fn qos_phase(&self, name: &str) -> Result<QosPhase> {
        let (_, full_name) = self.resolve_jail_names(name)?;
        Ok(self
            .scope_store
            .get(&full_name)?
            .map(|scope| scope.qos_phase)
            .unwrap_or(QosPhase::None))
    }

    /// Shift a jail to `target`, applying the difference between the two
    /// profiles. Idempotent: a jail already in `target` is left untouched.
    pub fn shift_qos(&self, name: &str, target: QosPhase) -> Result<ShiftOutcome> {
        let (service_name, full_name) = self.resolve_jail_names(name)?;

        let jail_def = self
            .config
            .get_jail(&service_name)
            .ok_or_else(|| Error::JailNotFound(name.to_string()))?;

        let Some(qos) = jail_def.qos.as_ref() else {
            return Ok(ShiftOutcome::NotConfigured);
        };

        let Some(mut scope) = self.scope_store.get(&full_name)? else {
            return Err(Error::State(format!(
                "No scope record for '{}': the jail is not running under blackship",
                full_name
            )));
        };

        if scope.qos_phase == target {
            return Ok(ShiftOutcome::AlreadyInPhase);
        }

        let from = qos.profile(scope.qos_phase);
        let to = qos.profile(target);

        crate::rctl::apply_phase(&full_name, from, to)?;

        let previous = scope.qos_phase;
        scope.qos_phase = target;
        scope.rctl_subject = Some(format!("jail:{}", full_name));
        self.persist_scope(&mut scope);

        self.audit.record(
            &AuditRecord::new(&full_name, AuditEvent::QosShift)
                .with("from", phase_label(previous))
                .with("to", phase_label(target)),
        );

        if let Some(cpu_list) = to.cpuset.as_ref()
            && from.cpuset.as_deref() != Some(cpu_list.as_str())
            && let Some(jid) = scope.jid
            && let Err(e) = crate::rctl::apply_cpuset(jid, cpu_list)
        {
            eprintln!(
                "Warning: failed to re-pin jail '{}' to CPUs {} during QoS shift: {}",
                full_name, cpu_list, e
            );
        }

        Ok(ShiftOutcome::Shifted)
    }

    /// The effective resource profile for a jail given its recorded QoS phase.
    /// Used by reconcilers that must not silently revert a completed shift.
    pub(super) fn effective_resources<'a>(
        &self,
        full_name: &str,
        jail_def: &'a JailDef,
    ) -> &'a ResourceConfig {
        let Some(qos) = jail_def.qos.as_ref() else {
            return &jail_def.resources;
        };

        match self.scope_store.get(full_name) {
            Ok(Some(scope)) => qos.profile(scope.qos_phase),
            _ => &qos.startup,
        }
    }
}

pub fn phase_label(phase: QosPhase) -> &'static str {
    match phase {
        QosPhase::Startup => "startup",
        QosPhase::Steady => "steady",
        QosPhase::None => "none",
    }
}

/// Startup budget after which a jail shifts to steady even without a health
/// signal. `None` means the shift is health- or operator-driven only.
pub fn startup_deadline_secs(qos: &QosConfig) -> Option<u64> {
    match qos.transition {
        crate::rctl::QosTransition::Timer => Some(qos.max_startup_secs.unwrap_or(60)),
        crate::rctl::QosTransition::Healthy => qos.max_startup_secs,
        crate::rctl::QosTransition::Manual => None,
    }
}
