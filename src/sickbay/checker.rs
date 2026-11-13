//! Health check definitions and monitoring
//!
//! Provides health check configuration and status tracking for jails.

use crate::error::{Error, Result};
use crate::jail::ffi::{jail_getid, jail_remove};
use crate::jail::jexec::jexec_with_timeout;
use crate::proc::{Outcome, run_supervised};
use crate::sickbay::recovery::{RecoveryAction, RecoveryConfig};
use crate::sickbay::suspicion::{Accrual, SuspicionConfig, Verdict};
use crate::warden::WardenHandle;
use breaker_machines::{CircuitBreaker, CircuitBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use throttle_machines::gate::Gate;
use throttle_machines::token_bucket::{TokenBucket, TokenBucketParams, TokenBucketState};

/// Health status of a jail
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Initial state, waiting for `start_period` to elapse
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
            Self::Starting => write!(f, "starting"),
            Self::Healthy => write!(f, "healthy"),
            Self::Unhealthy => write!(f, "unhealthy"),
            Self::Failing => write!(f, "failing"),
            Self::Suspended => write!(f, "suspended"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Where to execute the health check
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CheckTarget {
    /// Execute on the host system
    Host,
    /// Execute inside the jail
    #[default]
    Jail,
}

/// A single health check definition
#[derive(Debug, Clone, Deserialize, Serialize)]
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

    /// Phi-accrual thresholds replacing consecutive-failure counting (optional)
    pub suspicion: Option<SuspicionConfig>,
}

const fn default_interval() -> u64 {
    30
}

const fn default_timeout() -> u64 {
    10
}

const fn default_start_period() -> u64 {
    60
}

const fn default_retries() -> u32 {
    3
}

/// Try to take a rate-limit token for one check; refills are tracked either way.
fn take_rate_token(state: &mut CheckState, params: TokenBucketParams, now_secs: f64) -> bool {
    let tb_state = TokenBucketState {
        tokens: state.rate_limit_tokens,
        last_refill: state.rate_limit_last_refill,
    };
    let rate_result = TokenBucket::check(tb_state, now_secs, params);
    state.rate_limit_tokens = rate_result.state.tokens;
    state.rate_limit_last_refill = now_secs;
    rate_result.allowed
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
            suspicion: None,
        }
    }

    /// Set suspicion thresholds
    pub fn with_suspicion(mut self, suspicion: SuspicionConfig) -> Self {
        self.suspicion = Some(suspicion);
        self
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
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
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
    /// When recovery was last attempted, for cooldown enforcement
    last_recovery_at: Option<Instant>,
    /// Rate limiter tokens available
    rate_limit_tokens: f64,
    /// Rate limiter last refill time (seconds since UNIX epoch)
    rate_limit_last_refill: f64,
    /// Suspicion detector, when the check configures one
    accrual: Option<Accrual>,
}

impl CheckState {
    fn new(capacity: f64) -> Self {
        let now_secs = jiff::Timestamp::now().as_duration().as_secs_f64();
        Self {
            failures: 0,
            last_result: None,
            recovery_attempts: 0,
            last_recovery_at: None,
            rate_limit_tokens: capacity,
            rate_limit_last_refill: now_secs,
            accrual: None,
        }
    }
}

impl CheckState {
    /// Clear the failure streak and feed the detector a heartbeat.
    fn record_pass(&mut self, name: &str, since_start: Duration) {
        self.failures = 0;
        self.recovery_attempts = 0;
        if let Some(accrual) = self.accrual.as_mut()
            && let Err(e) = accrual.beat(since_start)
        {
            eprintln!("Warning: suspicion beat refused for '{name}': {e:?}");
        }
    }

    /// `(unhealthy, failing)` for a failed check: suspicion when warmed up, retry counting otherwise.
    fn failure_reading(&self, retries: u32, since_start: Duration) -> (bool, bool) {
        match self.accrual.as_ref().map(|a| a.verdict(since_start)) {
            Some(Verdict::Steady) => (false, false),
            Some(Verdict::Unhealthy) => (true, false),
            Some(Verdict::Failing) => (true, true),
            Some(Verdict::Warming) | None => (true, self.failures >= retries),
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
    /// Start time (for `start_period` tracking)
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
        let check_states: Vec<CheckState> = config
            .checks
            .iter()
            .map(|check| {
                let mut state = CheckState::new(rate_limit_capacity);
                // Manifest validation already rejected unusable thresholds.
                state.accrual = check
                    .suspicion
                    .as_ref()
                    .and_then(|cfg| cfg.build(check.interval).ok());
                state
            })
            .collect();

        let interval = config.checks.first().map_or(30, |c| c.interval);

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
            check_states,
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
    pub const fn with_jid(mut self, jid: i32) -> Self {
        self.jid = Some(jid);
        self
    }

    /// Count the start period from when the jail started `secs` ago, not from
    /// when this checker was built. A one-shot `health` builds its checker long
    /// after the jail came up.
    pub fn with_uptime(mut self, secs: u64) -> Self {
        if let Some(started) = Instant::now().checked_sub(Duration::from_secs(secs)) {
            self.started_at = started;
        }
        self
    }

    /// Get current health status
    pub const fn status(&self) -> HealthStatus {
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

    /// The shortest check timeout, the budget a run is judged against
    pub fn timeout(&self) -> Duration {
        let secs = self.config.checks.iter().map(|c| c.timeout).min();
        Duration::from_secs(secs.unwrap_or_else(default_timeout))
    }

    /// Get the check interval
    pub const fn interval(&self) -> Duration {
        self.check_interval
    }

    /// Check if health checking is enabled
    pub const fn is_enabled(&self) -> bool {
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

        self.refresh_jid(|name| jail_getid(name).ok());

        let previous_status = self.status;
        let mut any_failing = false;
        let mut all_healthy = true;
        let mut any_suspended = false;

        // Collect results and recovery actions to avoid borrow issues
        let check_count = self.config.checks.len();
        let mut results: Vec<Option<CheckResult>> = Vec::with_capacity(check_count);
        let mut recovery_needed: Vec<(usize, RecoveryConfig)> = Vec::new();
        let mut breaker_updates: Vec<(usize, bool, f64)> = Vec::new();

        // Get current time for rate limiting
        let now_secs = jiff::Timestamp::now().as_duration().as_secs_f64();
        let since_start = self.started_at.elapsed();

        for (idx, check) in self.config.checks.iter().enumerate() {
            // Check if circuit breaker is open for this check
            let breaker_closed = self
                .circuit_breakers
                .get(&check.name)
                .is_none_or(breaker_machines::CircuitBreaker::is_closed);

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
            let tb_params = TokenBucketParams {
                capacity: self.rate_limit_capacity,
                refill_rate: self.rate_limit_refill_rate,
            };
            if !take_rate_token(&mut self.check_states[idx], tb_params, now_secs) {
                // Rate limited - keep the previous result by pushing None (handled below)
                results.push(None);
                continue;
            }

            let result = self.execute_check(check)?;
            let duration_secs = result.duration.as_secs_f64();

            let state = &mut self.check_states[idx];
            if result.passed {
                state.record_pass(&check.name, since_start);
                breaker_updates.push((idx, true, duration_secs));
            } else {
                state.failures += 1;
                breaker_updates.push((idx, false, duration_secs));

                let (unhealthy, failing) = state.failure_reading(check.retries, since_start);
                if unhealthy {
                    all_healthy = false;
                }
                if failing {
                    any_failing = true;

                    // Mark for recovery if configured
                    if let Some(recovery) = &check.recovery {
                        recovery_needed.push((idx, recovery.clone()));
                    }
                }
            }

            results.push(Some(result));
        }

        self.record_breaker_outcomes(breaker_updates);

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

        if self.status == HealthStatus::Healthy
            && previous_status != HealthStatus::Healthy
            && let Some(handle) = &self.warden_handle
            && let Err(e) = handle.notify_healthy(&self.jail_name)
        {
            eprintln!("Warning: Failed to notify Warden of health recovery: {e}");
        }

        Ok(self.status)
    }

    /// The JID the next jail-target check will run in; `None` while the jail is down.
    pub const fn jid(&self) -> Option<i32> {
        self.jid
    }

    /// Follow the jail across restarts: a restarted jail has a new JID, and checks run in
    /// the stale one would fail forever. A new JID is re-registered with the Warden.
    fn refresh_jid(&mut self, lookup: impl Fn(&str) -> Option<i32>) {
        if !self
            .config
            .checks
            .iter()
            .any(|c| c.target == CheckTarget::Jail)
        {
            return;
        }
        let current = lookup(&self.jail_name);
        if current == self.jid {
            return;
        }
        self.jid = current;

        if let Some(jid) = current
            && let Some(handle) = &self.warden_handle
            && let Err(e) = handle.register_jail(&self.jail_name, jid, None)
        {
            eprintln!(
                "Warning: Failed to re-register jail '{}' with Warden: {}",
                self.jail_name, e
            );
        }
    }

    /// Feed each executed check's outcome to its circuit breaker.
    fn record_breaker_outcomes(&mut self, outcomes: Vec<(usize, bool, f64)>) {
        for (idx, success, duration) in outcomes {
            if let Some(breaker) = self.circuit_breakers.get_mut(&self.config.checks[idx].name) {
                if success {
                    breaker.record_success(duration);
                } else {
                    breaker.record_failure(duration);
                }
            }
        }
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
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", command]);

        let failed = |message: String| Error::HealthCheckFailed {
            jail: self.jail_name.clone(),
            check: "host".to_string(),
            message,
        };

        match run_supervised(&mut cmd, Duration::from_secs(timeout))
            .map_err(|e| failed(e.to_string()))?
        {
            Outcome::Exited(out) => {
                let mut combined = out.stdout;
                combined.push_str(&out.stderr);
                Ok((out.success, combined))
            }
            // A timed-out check is a failing check, not a broken one.
            Outcome::TimedOut => Ok((
                false,
                format!("Health check timed out after {timeout} seconds"),
            )),
        }
    }

    /// Execute a check command inside the jail with timeout enforcement
    ///
    /// Uses native `jail_attach(2)` syscall instead of spawning jexec process
    fn execute_in_jail(&self, jid: i32, command: &str, timeout: u64) -> Result<(bool, String)> {
        // Use native jexec with timeout - runs sh -c "<command>" inside jail
        match jexec_with_timeout(jid, &["sh", "-c", command], timeout) {
            Ok((exit_code, mut stdout, stderr)) => {
                stdout.push_str(&stderr);
                Ok((exit_code == 0, stdout))
            }
            Err(Error::JailTimeout(secs)) => Ok((
                false,
                format!("Health check timed out after {secs} seconds"),
            )),
            Err(e) => Err(Error::HealthCheckFailed {
                jail: self.jail_name.clone(),
                check: "jail".to_string(),
                message: e.to_string(),
            }),
        }
    }

    /// Trigger recovery action
    /// Remove the jail as a recovery step; false when it was already gone.
    fn stop_for_recovery(&mut self, failure: &str) -> Result<bool> {
        let jid = match jail_getid(&self.jail_name) {
            Ok(jid) => jid,
            Err(e) => {
                eprintln!(
                    "Recovery: Jail '{}' not found or already stopped: {}",
                    self.jail_name, e
                );
                return Ok(false);
            }
        };
        println!(
            "Recovery: Stopping jail '{}' (JID {})...",
            self.jail_name, jid
        );
        if let Err(e) = jail_remove(jid) {
            eprintln!("Recovery: Failed to stop jail '{}': {}", self.jail_name, e);
            return Err(Error::HealthCheckFailed {
                jail: self.jail_name.clone(),
                check: "recovery".to_string(),
                message: format!("{failure}: {e}"),
            });
        }
        self.jid = None;
        Ok(true)
    }

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

        if !config.should_attempt(state.last_recovery_at) {
            let waited = state.last_recovery_at.map_or(0, |t| t.elapsed().as_secs());
            eprintln!(
                "Health check '{}' for jail '{}' is in recovery cooldown ({}s of {}s elapsed)",
                self.config.checks[check_idx].name, self.jail_name, waited, config.cooldown
            );
            return Ok(());
        }

        state.recovery_attempts += 1;
        state.last_recovery_at = Some(Instant::now());

        println!(
            "Triggering recovery action '{:?}' for jail '{}' (attempt {}/{})",
            config.action, self.jail_name, state.recovery_attempts, config.max_attempts
        );

        // Notify Warden of health failure
        if let Some(handle) = &self.warden_handle
            && let Err(e) = handle.notify_health_failure(&self.jail_name)
        {
            eprintln!("Warning: Failed to notify Warden of health failure: {e}");
        }

        // Execute recovery action
        match &config.action {
            RecoveryAction::Restart if self.warden_handle.is_some() => {
                println!("Recovery: Warden is restarting jail '{}'", self.jail_name);
                self.jid = None;
            }
            RecoveryAction::Restart => {
                if self.stop_for_recovery("Failed to stop jail for restart")? {
                    println!(
                        "Recovery: Jail '{}' stopped. Manual restart required via 'blackship up {}'",
                        self.jail_name, self.jail_name
                    );
                    println!(
                        "Recovery: Note: For automatic restart, use the 'supervise' command with Warden"
                    );
                }
            }
            RecoveryAction::Stop => {
                if self.stop_for_recovery("Failed to stop jail")? {
                    println!("Recovery: Jail '{}' stopped successfully", self.jail_name);
                }
            }
            RecoveryAction::Command(cmd) => {
                println!(
                    "Recovery: Executing command for jail '{}'...",
                    self.jail_name
                );
                let output = Command::new("/bin/sh")
                    .args(["-c", cmd])
                    .output()
                    .map_err(|e| Error::HealthCheckFailed {
                        jail: self.jail_name.clone(),
                        check: "recovery".to_string(),
                        message: e.to_string(),
                    })?;

                if output.status.success() {
                    println!(
                        "Recovery: Command executed successfully for jail '{}'",
                        self.jail_name
                    );
                } else {
                    eprintln!(
                        "Recovery command failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
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
mod tests;
