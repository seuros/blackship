//! Recovery actions for health check failures
//!
//! Provides configurable recovery actions when health checks fail.

use serde::Deserialize;

/// Action to take when health checks fail
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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
    #[allow(dead_code)] // Public API for recovery timing
    pub fn cooldown_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.cooldown)
    }

    /// Check if recovery should be attempted based on cooldown
    #[allow(dead_code)] // Public API for recovery decisions
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

// Builder methods for RecoveryConfig - public API for programmatic use
impl RecoveryConfig {
    /// Create a new recovery config with restart action
    #[allow(dead_code)] // Public API for programmatic config
    pub fn restart() -> Self {
        Self {
            action: RecoveryAction::Restart,
            ..Default::default()
        }
    }

    /// Create a new recovery config with stop action
    #[allow(dead_code)] // Public API for programmatic config
    pub fn stop() -> Self {
        Self {
            action: RecoveryAction::Stop,
            ..Default::default()
        }
    }

    /// Create a new recovery config with custom command
    #[allow(dead_code)] // Public API for programmatic config
    pub fn command(cmd: &str) -> Self {
        Self {
            action: RecoveryAction::Command(cmd.to_string()),
            ..Default::default()
        }
    }

    /// Set max attempts
    #[allow(dead_code)] // Public API for programmatic config
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts;
        self
    }

    /// Set cooldown period
    #[allow(dead_code)] // Public API for programmatic config
    pub fn with_cooldown(mut self, cooldown: u64) -> Self {
        self.cooldown = cooldown;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_action_default() {
        let action = RecoveryAction::default();
        assert_eq!(action, RecoveryAction::None);
    }

    #[test]
    fn test_recovery_config_builders() {
        let restart = RecoveryConfig::restart().with_max_attempts(5);
        assert_eq!(restart.action, RecoveryAction::Restart);
        assert_eq!(restart.max_attempts, 5);

        let stop = RecoveryConfig::stop().with_cooldown(120);
        assert_eq!(stop.action, RecoveryAction::Stop);
        assert_eq!(stop.cooldown, 120);

        let cmd = RecoveryConfig::command("/usr/local/bin/fix.sh");
        assert_eq!(
            cmd.action,
            RecoveryAction::Command("/usr/local/bin/fix.sh".to_string())
        );
    }

    #[test]
    fn test_recovery_config_deserialize() {
        let toml = r#"
action = "restart"
max_attempts = 5
cooldown = 120
"#;

        let config: RecoveryConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.action, RecoveryAction::Restart);
        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.cooldown, 120);
    }

    #[test]
    fn test_recovery_command_deserialize() {
        let toml = r#"
action = { command = "/usr/local/bin/restart-service.sh" }
max_attempts = 2
"#;

        let config: RecoveryConfig = toml::from_str(toml).unwrap();
        assert_eq!(
            config.action,
            RecoveryAction::Command("/usr/local/bin/restart-service.sh".to_string())
        );
    }
}
