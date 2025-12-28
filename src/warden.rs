//! The Warden - Jail Supervisor
//!
//! Monitors jails and implements one-for-one restart strategy:
//! - Auto-restarts failed jails
//! - Uses exponential backoff between restart attempts
//! - Circuit breaker to stop restart attempts after too many failures

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use breaker_machines::{CircuitBreaker, CircuitBuilder};
use chrono_machines::{BackoffStrategy, ExponentialBackoff};
use rand::rng;
use tokio::sync::{mpsc, Mutex};

use crate::error::Result;
use crate::bridge::Bridge;

/// Events the Warden receives
#[derive(Debug)]
pub enum WardenEvent {
    /// A jail has failed (process crashed or state machine error)
    JailFailed { name: String },
    /// A jail's health check failed
    JailHealthFailed { name: String },
    /// A jail started successfully
    JailStarted { name: String },
    /// A jail was stopped (intentionally)
    JailStopped { name: String },
    /// Shutdown the Warden
    Shutdown,
}

/// Restart state tracking for a single jail
struct RestartState {
    /// Number of restart attempts
    attempts: u8,
    /// Backoff calculator
    backoff: ExponentialBackoff,
    /// Circuit breaker to stop restart attempts
    breaker: CircuitBreaker,
}

impl RestartState {
    fn new(name: &str) -> Self {
        Self {
            attempts: 0,
            backoff: ExponentialBackoff::new()
                .base_delay_ms(1000)       // 1 second base delay
                .max_delay_ms(60000)       // 60 seconds max delay
                .multiplier(2.0)           // Double each time
                .max_attempts(10)          // Max 10 attempts
                .jitter_factor(0.5),       // 50% jitter
            breaker: CircuitBuilder::new(format!("warden_{}", name))
                .failure_threshold(5)
                .success_threshold(2)
                .half_open_timeout_secs(300.0) // 5 minutes in half-open
                .build(),
        }
    }

    fn reset(&mut self) {
        self.attempts = 0;
        self.breaker.record_success(0.0);
    }

    fn record_failure(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
        self.breaker.record_failure(0.0);
    }

    fn next_delay(&self) -> Option<Duration> {
        let mut rng = rng();
        self.backoff.delay(self.attempts, &mut rng)
            .map(Duration::from_millis)
    }

    fn should_retry(&self) -> bool {
        self.breaker.is_closed() && self.backoff.should_retry(self.attempts)
    }
}

/// The Warden supervises all jails with one-for-one restart strategy
pub struct Warden {
    /// Channel to receive events
    rx: mpsc::Receiver<WardenEvent>,
    /// Sender for notifying the Warden (cloneable)
    tx: mpsc::Sender<WardenEvent>,
    /// Restart state per jail
    restart_states: HashMap<String, RestartState>,
    /// Reference to bridge for restart operations
    bridge: Arc<Mutex<Bridge>>,
}

impl Warden {
    /// Create a new Warden for the given bridge
    pub fn new(bridge: Arc<Mutex<Bridge>>) -> Self {
        let (tx, rx) = mpsc::channel(100);
        Self {
            rx,
            tx,
            restart_states: HashMap::new(),
            bridge,
        }
    }

    /// Get a sender to notify the Warden of events
    pub fn sender(&self) -> mpsc::Sender<WardenEvent> {
        self.tx.clone()
    }

    /// Run the Warden event loop
    ///
    /// This should be spawned as a tokio task
    pub async fn run(&mut self) {
        println!("Warden: Starting jail supervisor");

        while let Some(event) = self.rx.recv().await {
            match event {
                WardenEvent::JailFailed { name } => {
                    println!("Warden: Jail '{}' failed, initiating restart", name);
                    self.handle_failure(&name).await;
                }
                WardenEvent::JailHealthFailed { name } => {
                    println!("Warden: Jail '{}' health check failed, initiating restart", name);
                    self.handle_failure(&name).await;
                }
                WardenEvent::JailStarted { name } => {
                    println!("Warden: Jail '{}' started successfully", name);
                    if let Some(state) = self.restart_states.get_mut(&name) {
                        state.reset();
                    }
                }
                WardenEvent::JailStopped { name } => {
                    println!("Warden: Jail '{}' stopped intentionally", name);
                    // Don't restart intentionally stopped jails
                    self.restart_states.remove(&name);
                }
                WardenEvent::Shutdown => {
                    println!("Warden: Shutting down");
                    break;
                }
            }
        }

        println!("Warden: Supervisor stopped");
    }

    /// Handle a jail failure by attempting restart with backoff
    async fn handle_failure(&mut self, name: &str) {
        let state = self
            .restart_states
            .entry(name.to_string())
            .or_insert_with(|| RestartState::new(name));

        // Check if we should retry
        if !state.should_retry() {
            eprintln!(
                "Warden: Not restarting jail '{}' (circuit breaker open or max attempts reached)",
                name
            );
            return;
        }

        // Calculate backoff delay
        let delay = match state.next_delay() {
            Some(d) => d,
            None => {
                eprintln!("Warden: Max retries reached for jail '{}'", name);
                return;
            }
        };

        state.record_failure();

        println!(
            "Warden: Restarting jail '{}' in {:?} (attempt {})",
            name, delay, state.attempts
        );

        // Wait for backoff period
        tokio::time::sleep(delay).await;

        // Attempt restart
        let result = {
            let mut br = self.bridge.lock().await;
            br.restart_jail(name)
        };

        match result {
            Ok(_) => {
                println!("Warden: Jail '{}' restarted successfully", name);
                if let Some(state) = self.restart_states.get_mut(name) {
                    state.reset();
                }
            }
            Err(e) => {
                eprintln!("Warden: Failed to restart jail '{}': {}", name, e);
                // Failure already recorded before restart attempt
            }
        }
    }

    /// Request the Warden to shutdown
    pub async fn request_shutdown(sender: &mpsc::Sender<WardenEvent>) {
        let _ = sender.send(WardenEvent::Shutdown).await;
    }
}

/// Handle for interacting with the Warden from non-async code
#[derive(Clone)]
pub struct WardenHandle {
    sender: mpsc::Sender<WardenEvent>,
}

impl WardenHandle {
    /// Create a handle from a Warden
    pub fn new(warden: &Warden) -> Self {
        Self {
            sender: warden.sender(),
        }
    }

    /// Notify that a jail failed (blocking version for sync code)
    pub fn notify_failure_blocking(&self, name: &str) -> Result<()> {
        self.sender
            .blocking_send(WardenEvent::JailFailed {
                name: name.to_string(),
            })
            .map_err(|_| crate::error::Error::Io(std::io::Error::other("Warden channel closed")))
    }

    /// Notify that a jail's health check failed (blocking version)
    pub fn notify_health_failure_blocking(&self, name: &str) -> Result<()> {
        self.sender
            .blocking_send(WardenEvent::JailHealthFailed {
                name: name.to_string(),
            })
            .map_err(|_| crate::error::Error::Io(std::io::Error::other("Warden channel closed")))
    }

    /// Notify that a jail started (blocking version)
    pub fn notify_started_blocking(&self, name: &str) -> Result<()> {
        self.sender
            .blocking_send(WardenEvent::JailStarted {
                name: name.to_string(),
            })
            .map_err(|_| crate::error::Error::Io(std::io::Error::other("Warden channel closed")))
    }

    /// Notify that a jail stopped intentionally (blocking version)
    pub fn notify_stopped_blocking(&self, name: &str) -> Result<()> {
        self.sender
            .blocking_send(WardenEvent::JailStopped {
                name: name.to_string(),
            })
            .map_err(|_| crate::error::Error::Io(std::io::Error::other("Warden channel closed")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_restart_state_backoff() {
        let state = RestartState::new("test_jail");
        assert!(state.should_retry());
        let delay = state.next_delay();
        assert!(delay.is_some());
    }

    #[test]
    fn test_restart_state_reset() {
        let mut state = RestartState::new("test_jail");
        state.attempts = 5;
        state.reset();
        assert_eq!(state.attempts, 0);
    }
}
