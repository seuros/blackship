//! Health check definitions and monitoring
//!
//! Provides health check configuration and status tracking for jails.

use crate::error::{Error, Result};
use crate::sickbay::recovery::{RecoveryAction, RecoveryConfig};
use crate::jail::ffi::{jail_getid, jail_remove};
use crate::warden::WardenHandle;
use breaker_machines::{CircuitBreaker, CircuitBuilder};
use serde::Deserialize;
use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use throttle_machines::token_bucket;

/// Health status of a jail
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Initial state, waiting for start_period to elapse
    Starting,
    /// All health checks passing
    Healthy,
    /// Some checks failing but within retry threshold
    Unhealthy,
    /// Checks consistently failing, recovery may be triggered
    Failing,
    /// Circuit breaker is open, checks suspended
    Suspended,
    /// Unknown status (not yet checked)
    Unknown,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Starting => write!(f, "starting"),
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
            HealthStatus::Failing => write!(f, "failing"),
            HealthStatus::Suspended => write!(f, "suspended"),
            HealthStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Where to execute the health check
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CheckTarget {
    /// Execute on the host system
    Host,
    /// Execute inside the jail
    #[default]
    Jail,
}

/// A single health check definition
#[derive(Debug, Clone, Deserialize)]
pub struct HealthCheck {
    /// Check name for identification
    pub name: String,

    /// Command to execute (exit 0 = healthy)
    pub command: String,

    /// Where to execute the check
    #[serde(default)]
    pub target: CheckTarget,

    /// Interval between checks in seconds
    #[serde(default = "default_interval")]
    pub interval: u64,

    /// Timeout for each check in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Initial grace period before checks start in seconds
    #[serde(default = "default_start_period")]
    pub start_period: u64,

    /// Number of consecutive failures before marking as failing
    #[serde(default = "default_retries")]
    pub retries: u32,

    /// Recovery configuration (optional)
    pub recovery: Option<RecoveryConfig>,
}

fn default_interval() -> u64 {
    30
}

fn default_timeout() -> u64 {
    10
}

fn default_start_period() -> u64 {
    60
}

fn default_retries() -> u32 {
    3
}

#[cfg(test)]
impl HealthCheck {
    /// Create a new health check
    pub fn new(name: &str, command: &str) -> Self {
        Self {
            name: name.to_string(),
            command: command.to_string(),
            target: CheckTarget::Jail,
            interval: default_interval(),
            timeout: default_timeout(),
            start_period: default_start_period(),
            retries: default_retries(),
            recovery: None,
        }
    }

    /// Set check target
    pub fn with_target(mut self, target: CheckTarget) -> Self {
        self.target = target;
        self
    }

    /// Set check interval
    pub fn with_interval(mut self, interval: u64) -> Self {
        self.interval = interval;
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set retries
    pub fn with_retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }
}

/// Result of a single health check execution
#[derive(Debug)]
pub struct CheckResult {
    /// Name of the check
    pub name: String,
    /// Whether the check passed
    pub passed: bool,
    /// Execution duration
    pub duration: Duration,
    /// Output (stdout/stderr combined)
    pub output: String,
    /// Timestamp of check
    pub timestamp: Instant,
}

impl CheckResult {
    /// Get a summary string for this check result
    pub fn summary(&self) -> String {
        let status = if self.passed { "ok" } else { "fail" };
        let duration_ms = self.duration.as_millis();
        if self.output.is_empty() {
            format!("{}:{} ({}ms)", self.name, status, duration_ms)
        } else {
            format!(
                "{}:{} ({}ms) - {}",
                self.name,
                status,
                duration_ms,
                self.output.lines().next().unwrap_or("")
            )
        }
    }

    /// Get elapsed time since this check was run
    pub fn age(&self) -> Duration {
        self.timestamp.elapsed()
    }
}

/// Health check configuration for a jail
#[derive(Debug, Clone, Deserialize, Default)]
pub struct HealthCheckConfig {
    /// Enable health checking for this jail
    #[serde(default)]
    pub enabled: bool,

    /// List of health checks to perform
    #[serde(default)]
    pub checks: Vec<HealthCheck>,
}

#[cfg(test)]
impl HealthCheckConfig {
    /// Create a new enabled health check config
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            checks: Vec::new(),
        }
    }

    /// Add a check
    pub fn with_check(mut self, check: HealthCheck) -> Self {
        self.checks.push(check);
        self
    }
}

/// State tracked for each check
#[derive(Debug)]
struct CheckState {
    /// Consecutive failures
    failures: u32,
    /// Last check result
    last_result: Option<CheckResult>,
    /// Recovery attempts made
    recovery_attempts: u32,
    /// Rate limiter tokens available
    rate_limit_tokens: f64,
    /// Rate limiter last refill time (seconds since UNIX epoch)
    rate_limit_last_refill: f64,
}

impl CheckState {
    fn new(capacity: f64) -> Self {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        Self {
            failures: 0,
            last_result: None,
            recovery_attempts: 0,
            rate_limit_tokens: capacity,
            rate_limit_last_refill: now_secs,
        }
    }
}

impl Default for CheckState {
    fn default() -> Self {
        Self::new(5.0) // Default capacity
    }
}


/// Health checker for a single jail
pub struct HealthChecker {
    /// Jail name
    jail_name: String,
    /// Jail ID (for executing commands inside jail)
    jid: Option<i32>,
    /// Health check configuration
    config: HealthCheckConfig,
    /// Current health status
    status: HealthStatus,
    /// Start time (for start_period tracking)
    started_at: Instant,
    /// State for each check
    check_states: Vec<CheckState>,
    /// Stop signal for background monitoring
    stop_signal: Arc<AtomicBool>,
    /// Interval between check cycles (from first check's interval)
    check_interval: Duration,
    /// Circuit breakers per health check (keyed by check name)
    circuit_breakers: HashMap<String, CircuitBreaker>,
    /// Rate limiter capacity (burst size)
    rate_limit_capacity: f64,
    /// Rate limiter refill rate (tokens per second)
    rate_limit_refill_rate: f64,
    /// Optional Warden handle for notifications
    warden_handle: Option<WardenHandle>,
}

impl HealthChecker {
    /// Create a new health checker with custom rate limit settings
    pub fn with_rate_limit(
        jail_name: &str,
        config: HealthCheckConfig,
        rate_limit_capacity: f64,
        rate_limit_refill_rate: f64,
    ) -> Self {
        let check_count = config.checks.len();
        let interval = config
            .checks
            .first()
            .map(|c| c.interval)
            .unwrap_or(30);

        // Initialize circuit breakers for each health check
        let circuit_breakers = config
            .checks
            .iter()
            .map(|check| {
                let breaker = CircuitBuilder::new(format!("health_{}_{}", jail_name, check.name))
                    .failure_threshold(check.retries as usize)
                    .success_threshold(2)
                    .half_open_timeout_secs(60.0)
                    .build();
                (check.name.clone(), breaker)
            })
            .collect();

        Self {
            jail_name: jail_name.to_string(),
            jid: None,
            config,
            status: HealthStatus::Unknown,
            started_at: Instant::now(),
            check_states: (0..check_count)
                .map(|_| CheckState::new(rate_limit_capacity))
                .collect(),
            stop_signal: Arc::new(AtomicBool::new(false)),
            check_interval: Duration::from_secs(interval),
            circuit_breakers,
            rate_limit_capacity,
            rate_limit_refill_rate,
            warden_handle: None,
        }
    }

    /// Set the Warden handle for health failure notifications
    pub fn with_warden_handle(mut self, handle: WardenHandle) -> Self {
        self.warden_handle = Some(handle);
        self
    }

    /// Set jail ID for executing checks inside jail
    pub fn with_jid(mut self, jid: i32) -> Self {
        self.jid = Some(jid);
        self
    }

    /// Get current health status
    pub fn status(&self) -> HealthStatus {
        self.status
    }

    /// Get jail name
    pub fn jail_name(&self) -> &str {
        &self.jail_name
    }

    /// Get stop signal for external control
    pub fn stop_signal(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_signal)
    }

    /// Check if stop has been signaled
    pub fn is_stopped(&self) -> bool {
        self.stop_signal.load(Ordering::SeqCst)
    }

    /// Get the check interval
    pub fn interval(&self) -> Duration {
        self.check_interval
    }

    /// Check if health checking is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled && !self.config.checks.is_empty()
    }

    /// Run a single iteration of all health checks
    pub fn run_checks(&mut self) -> Result<HealthStatus> {
        if !self.is_enabled() {
            return Ok(HealthStatus::Unknown);
        }

        // Check if still in start period for any check
        let elapsed = self.started_at.elapsed().as_secs();
        let in_start_period = self.config.checks.iter().any(|c| elapsed < c.start_period);

        if in_start_period {
            self.status = HealthStatus::Starting;
            return Ok(self.status);
        }

        let mut any_failing = false;
        let mut all_healthy = true;
        let mut any_suspended = false;

        // Collect results and recovery actions to avoid borrow issues
        let check_count = self.config.checks.len();
        let mut results: Vec<Option<CheckResult>> = Vec::with_capacity(check_count);
        let mut recovery_needed: Vec<(usize, RecoveryConfig)> = Vec::new();
        let mut breaker_updates: Vec<(String, bool, f64)> = Vec::new();

        // Get current time for rate limiting
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        for (idx, check) in self.config.checks.iter().enumerate() {
            // Check if circuit breaker is open for this check
            let breaker_closed = self
                .circuit_breakers
                .get(&check.name)
                .map(|b| b.is_closed())
                .unwrap_or(true);

            if !breaker_closed {
                // Circuit is open, return suspended result without executing
                any_suspended = true;
                all_healthy = false;
                results.push(Some(CheckResult {
                    name: check.name.clone(),
                    passed: false,
                    duration: Duration::ZERO,
                    output: "Circuit breaker open - check suspended".to_string(),
                    timestamp: Instant::now(),
                }));
                continue;
            }

            // Check rate limit before executing
            let state = &self.check_states[idx];
            let rate_result = token_bucket::check(
                state.rate_limit_tokens,
                state.rate_limit_last_refill,
                now_secs,
                self.rate_limit_capacity,
                self.rate_limit_refill_rate,
            );

            if !rate_result.allowed {
                // Rate limited - skip this check and keep previous result
                // Update token state even when rate limited (for refill tracking)
                self.check_states[idx].rate_limit_tokens = rate_result.new_tokens;
                self.check_states[idx].rate_limit_last_refill = now_secs;
                // Keep the previous result by pushing None (handled below)
                results.push(None);
                continue;
            }

            // Update rate limiter state after consuming a token
            self.check_states[idx].rate_limit_tokens = rate_result.new_tokens;
            self.check_states[idx].rate_limit_last_refill = now_secs;

            let result = self.execute_check(check)?;
            let duration_secs = result.duration.as_secs_f64();

            if result.passed {
                // Reset failure count on success
                self.check_states[idx].failures = 0;
                self.check_states[idx].recovery_attempts = 0;
                breaker_updates.push((check.name.clone(), true, duration_secs));
            } else {
                self.check_states[idx].failures += 1;
                all_healthy = false;
                breaker_updates.push((check.name.clone(), false, duration_secs));

                if self.check_states[idx].failures >= check.retries {
                    any_failing = true;

                    // Mark for recovery if configured
                    if let Some(recovery) = &check.recovery {
                        recovery_needed.push((idx, recovery.clone()));
                    }
                }
            }

            results.push(Some(result));
        }

        // Update circuit breakers
        for (name, success, duration) in breaker_updates {
            if let Some(breaker) = self.circuit_breakers.get_mut(&name) {
                if success {
                    breaker.record_success(duration);
                } else {
                    breaker.record_failure(duration);
                }
            }
        }

        // Store results (only update if we have a new result, otherwise keep previous)
        for (idx, result) in results.into_iter().enumerate() {
            if result.is_some() {
                self.check_states[idx].last_result = result;
            }
            // If result is None (rate limited), keep the previous last_result
        }

        // Trigger recoveries after the loop to avoid borrow issues
        for (idx, recovery) in recovery_needed {
            self.trigger_recovery(idx, &recovery)?;
        }

        // Update overall status
        self.status = if any_suspended && !any_failing {
            HealthStatus::Suspended
        } else if any_failing {
            HealthStatus::Failing
        } else if all_healthy {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy
        };

        Ok(self.status)
    }

    /// Execute a single health check
    fn execute_check(&self, check: &HealthCheck) -> Result<CheckResult> {
        let start = Instant::now();

        let (passed, output) = match check.target {
            CheckTarget::Host => self.execute_on_host(&check.command, check.timeout)?,
            CheckTarget::Jail => {
                if let Some(jid) = self.jid {
                    self.execute_in_jail(jid, &check.command, check.timeout)?
                } else {
                    (false, "No jail ID available".to_string())
                }
            }
        };

        Ok(CheckResult {
            name: check.name.clone(),
            passed,
            duration: start.elapsed(),
            output,
            timestamp: Instant::now(),
        })
    }

    /// Execute a check command on the host with timeout enforcement
    fn execute_on_host(&self, command: &str, timeout: u64) -> Result<(bool, String)> {
        let mut child = Command::new("sh")
            .args(["-c", command])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::HealthCheckFailed {
                jail: self.jail_name.clone(),
                check: "host".to_string(),
                message: e.to_string(),
            })?;

        let timeout_duration = Duration::from_secs(timeout);
        let start = Instant::now();

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process completed
                    let stdout = child
                        .stdout
                        .take()
                        .map(|mut s| {
                            let mut buf = String::new();
                            std::io::Read::read_to_string(&mut s, &mut buf).ok();
                            buf
                        })
                        .unwrap_or_default();
                    let stderr = child
                        .stderr
                        .take()
                        .map(|mut s| {
                            let mut buf = String::new();
                            std::io::Read::read_to_string(&mut s, &mut buf).ok();
                            buf
                        })
                        .unwrap_or_default();
                    let combined = format!("{}{}", stdout, stderr);
                    return Ok((status.success(), combined));
                }
                Ok(None) => {
                    // Process still running, check timeout
                    if start.elapsed() > timeout_duration {
                        // Kill the process
                        let _ = child.kill();
                        let _ = child.wait(); // Reap the zombie
                        return Ok((
                            false,
                            format!("Health check timed out after {} seconds", timeout),
                        ));
                    }
                    // Sleep briefly before polling again
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    return Err(Error::HealthCheckFailed {
                        jail: self.jail_name.clone(),
                        check: "host".to_string(),
                        message: format!("Failed to wait for process: {}", e),
                    });
                }
            }
        }
    }

    /// Execute a check command inside the jail with timeout enforcement
    fn execute_in_jail(&self, jid: i32, command: &str, timeout: u64) -> Result<(bool, String)> {
        // Spawn jexec directly with output capture instead of using console::exec_in_jail
        // which is designed for interactive use
        let mut child = Command::new("/usr/sbin/jexec")
            .arg(jid.to_string())
            .args(["sh", "-c", command])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::HealthCheckFailed {
                jail: self.jail_name.clone(),
                check: "jail".to_string(),
                message: format!("Failed to execute jexec: {}", e),
            })?;

        let timeout_duration = Duration::from_secs(timeout);
        let start = Instant::now();

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process completed
                    let stdout = child
                        .stdout
                        .take()
                        .map(|mut s| {
                            let mut buf = String::new();
                            std::io::Read::read_to_string(&mut s, &mut buf).ok();
                            buf
                        })
                        .unwrap_or_default();
                    let stderr = child
                        .stderr
                        .take()
                        .map(|mut s| {
                            let mut buf = String::new();
                            std::io::Read::read_to_string(&mut s, &mut buf).ok();
                            buf
                        })
                        .unwrap_or_default();
                    let combined = format!("{}{}", stdout, stderr);
                    return Ok((status.success(), combined));
                }
                Ok(None) => {
                    // Process still running, check timeout
                    if start.elapsed() > timeout_duration {
                        // Kill the process
                        let _ = child.kill();
                        let _ = child.wait(); // Reap the zombie
                        return Ok((
                            false,
                            format!("Health check timed out after {} seconds", timeout),
                        ));
                    }
                    // Sleep briefly before polling again
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    return Err(Error::HealthCheckFailed {
                        jail: self.jail_name.clone(),
                        check: "jail".to_string(),
                        message: format!("Failed to wait for jexec process: {}", e),
                    });
                }
            }
        }
    }

    /// Trigger recovery action
    fn trigger_recovery(&mut self, check_idx: usize, config: &RecoveryConfig) -> Result<()> {
        let state = &mut self.check_states[check_idx];

        // Check if we've exceeded max attempts
        if state.recovery_attempts >= config.max_attempts {
            eprintln!(
                "Health check '{}' for jail '{}' exceeded max recovery attempts ({})",
                self.config.checks[check_idx].name, self.jail_name, config.max_attempts
            );
            return Ok(());
        }

        state.recovery_attempts += 1;

        println!(
            "Triggering recovery action '{:?}' for jail '{}' (attempt {}/{})",
            config.action, self.jail_name, state.recovery_attempts, config.max_attempts
        );

        // Notify Warden of health failure
        if let Some(handle) = &self.warden_handle {
            if let Err(e) = handle.notify_health_failure_blocking(&self.jail_name) {
                eprintln!("Warning: Failed to notify Warden of health failure: {}", e);
            }
        }

        // Execute recovery action
        match &config.action {
            RecoveryAction::Restart => {
                // Stop the jail first
                match jail_getid(&self.jail_name) {
                    Ok(jid) => {
                        println!("Recovery: Stopping jail '{}' (JID {})...", self.jail_name, jid);
                        if let Err(e) = jail_remove(jid) {
                            eprintln!(
                                "Recovery: Failed to stop jail '{}': {}",
                                self.jail_name, e
                            );
                            return Err(Error::HealthCheckFailed {
                                jail: self.jail_name.clone(),
                                check: "recovery".to_string(),
                                message: format!("Failed to stop jail for restart: {}", e),
                            });
                        }
                        // Clear the stored JID since the jail is now stopped
                        self.jid = None;
                        println!(
                            "Recovery: Jail '{}' stopped. Manual restart required via 'blackship up {}'",
                            self.jail_name, self.jail_name
                        );
                        println!(
                            "Recovery: Note: For automatic restart, use the 'supervise' command with Warden"
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "Recovery: Jail '{}' not found or already stopped: {}",
                            self.jail_name, e
                        );
                    }
                }
            }
            RecoveryAction::Stop => {
                match jail_getid(&self.jail_name) {
                    Ok(jid) => {
                        println!("Recovery: Stopping jail '{}' (JID {})...", self.jail_name, jid);
                        if let Err(e) = jail_remove(jid) {
                            eprintln!(
                                "Recovery: Failed to stop jail '{}': {}",
                                self.jail_name, e
                            );
                            return Err(Error::HealthCheckFailed {
                                jail: self.jail_name.clone(),
                                check: "recovery".to_string(),
                                message: format!("Failed to stop jail: {}", e),
                            });
                        }
                        // Clear the stored JID since the jail is now stopped
                        self.jid = None;
                        println!("Recovery: Jail '{}' stopped successfully", self.jail_name);
                    }
                    Err(e) => {
                        eprintln!(
                            "Recovery: Jail '{}' not found or already stopped: {}",
                            self.jail_name, e
                        );
                    }
                }
            }
            RecoveryAction::Command(cmd) => {
                println!("Recovery: Executing command for jail '{}'...", self.jail_name);
                let output = Command::new("sh").args(["-c", cmd]).output().map_err(|e| {
                    Error::HealthCheckFailed {
                        jail: self.jail_name.clone(),
                        check: "recovery".to_string(),
                        message: e.to_string(),
                    }
                })?;

                if !output.status.success() {
                    eprintln!(
                        "Recovery command failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                } else {
                    println!("Recovery: Command executed successfully for jail '{}'", self.jail_name);
                }
            }
            RecoveryAction::None => {}
        }

        Ok(())
    }

    /// Get check results for display
    pub fn get_check_results(&self) -> Vec<(&HealthCheck, Option<&CheckResult>, u32)> {
        self.config
            .checks
            .iter()
            .enumerate()
            .map(|(idx, check)| {
                (
                    check,
                    self.check_states[idx].last_result.as_ref(),
                    self.check_states[idx].failures,
                )
            })
            .collect()
    }
}

#[cfg(test)]
impl HealthChecker {
    /// Create a new health checker with default rate limit settings
    pub fn new(jail_name: &str, config: HealthCheckConfig) -> Self {
        Self::with_rate_limit(jail_name, config, 5.0, 0.5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_display() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Failing.to_string(), "failing");
        assert_eq!(HealthStatus::Starting.to_string(), "starting");
        assert_eq!(HealthStatus::Suspended.to_string(), "suspended");
    }

    #[test]
    fn test_health_check_builder() {
        let check = HealthCheck::new("http", "curl -sf http://localhost:8080/health")
            .with_target(CheckTarget::Jail)
            .with_interval(15)
            .with_timeout(5)
            .with_retries(5);

        assert_eq!(check.name, "http");
        assert_eq!(check.interval, 15);
        assert_eq!(check.timeout, 5);
        assert_eq!(check.retries, 5);
    }

    #[test]
    fn test_health_config_builder() {
        let config = HealthCheckConfig::enabled()
            .with_check(HealthCheck::new("test", "true"))
            .with_check(HealthCheck::new("test2", "true"));

        assert!(config.enabled);
        assert_eq!(config.checks.len(), 2);
    }

    #[test]
    fn test_health_checker_creation() {
        let config = HealthCheckConfig::enabled().with_check(HealthCheck::new("test", "true"));

        let checker = HealthChecker::new("testjail", config);
        assert_eq!(checker.jail_name(), "testjail");
        assert!(checker.is_enabled());
    }

    #[test]
    fn test_health_check_deserialize() {
        let toml = r#"
name = "http"
command = "curl -sf http://localhost/health"
target = "jail"
interval = 30
timeout = 10
start_period = 60
retries = 3
"#;

        let check: HealthCheck = toml::from_str(toml).unwrap();
        assert_eq!(check.name, "http");
        assert_eq!(check.target, CheckTarget::Jail);
        assert_eq!(check.interval, 30);
    }
}
