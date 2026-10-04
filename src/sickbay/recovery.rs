//! Recovery actions for health check failures
//!
//! Provides configurable recovery actions when health checks fail.

use serde::{Deserialize, Serialize};

/// Action to take when health checks fail
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum RecoveryAction {
    /// Do nothing
    #[default]
    None,
    /// Restart the jail
    Restart,
    /// Stop the jail
    Stop,
    /// Execute a custom command on the host
    #[serde(rename = "command")]
    Command(String),
}

/// Recovery configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecoveryConfig {
    /// Action to take on failure
    #[serde(default)]
    pub action: RecoveryAction,

    /// Maximum recovery attempts before giving up
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,

    /// Cooldown period between recovery attempts (seconds)
    #[serde(default = "default_cooldown")]
    pub cooldown: u64,
}

impl RecoveryConfig {
    /// Get cooldown as Duration
    pub fn cooldown_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.cooldown)
    }

    /// Check if recovery should be attempted based on cooldown
    pub fn should_attempt(&self, last_attempt: Option<std::time::Instant>) -> bool {
        match last_attempt {
            Some(t) => t.elapsed() >= self.cooldown_duration(),
            None => true,
        }
    }
}

fn default_max_attempts() -> u32 {
    3
}

fn default_cooldown() -> u64 {
    60
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            action: RecoveryAction::None,
            max_attempts: default_max_attempts(),
            cooldown: default_cooldown(),
        }
    }
}

#[cfg(test)]
impl RecoveryConfig {
    /// Create a new recovery config with restart action
    pub fn restart() -> Self {
        Self {
            action: RecoveryAction::Restart,
            ..Default::default()
        }
    }

    /// Create a new recovery config with stop action
    pub fn stop() -> Self {
        Self {
            action: RecoveryAction::Stop,
            ..Default::default()
        }
    }

    /// Create a new recovery config with custom command
    pub fn command(cmd: &str) -> Self {
        Self {
            action: RecoveryAction::Command(cmd.to_string()),
            ..Default::default()
        }
    }

    /// Set max attempts
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts;
        self
    }

    /// Set cooldown period
    pub fn with_cooldown(mut self, cooldown: u64) -> Self {
        self.cooldown = cooldown;
        self
    }
}

#[cfg(test)]
mod tests;
