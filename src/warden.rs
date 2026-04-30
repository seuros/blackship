//! The Warden - Jail Supervisor
//!
//! Monitors jails and implements one-for-one restart strategy:
//! - Watches for kernel jail removal events via kqueue (FreeBSD 16+)
//! - Falls back to event-driven mpsc channel on older systems
//! - Auto-restarts failed jails with exponential backoff
//! - Circuit breaker to stop restart attempts after too many failures

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use breaker_machines::{CircuitBreaker, CircuitBuilder};
use chrono_machines::{BackoffStrategy, ExponentialBackoff};
use rand::rng;
use tokio::sync::{Mutex, mpsc};

use crate::bridge::Bridge;
use crate::error::Result;
use crate::jail::kqueue::{JailEvent, JailEventSource};
use crate::sys::OsVersion;

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
    JailStopped { name: String, jid: i32 },
    /// Register a jail for kqueue monitoring (sent via WardenHandle after restart)
    #[allow(dead_code)]
    RegisterJail { name: String, jid: i32 },
    /// Shutdown the Warden
    Shutdown,
}

/// Shared tracking of jails being stopped intentionally.
#[derive(Clone, Default)]
struct IntentionalStops {
    jids: Arc<StdMutex<HashSet<i32>>>,
}

impl IntentionalStops {
    fn mark(&self, jid: i32) {
        let mut jids = self
            .jids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        jids.insert(jid);
    }

    fn clear(&self, jid: i32) {
        let mut jids = self
            .jids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        jids.remove(&jid);
    }

    fn contains(&self, jid: i32) -> bool {
        let jids = self
            .jids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        jids.contains(&jid)
    }
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
                .base_delay_ms(1000)
                .max_delay_ms(60000)
                .multiplier(2.0)
                .max_attempts(10)
                .jitter_factor(0.5),
            breaker: CircuitBuilder::new(format!("warden_{}", name))
                .failure_threshold(5)
                .success_threshold(2)
                .half_open_timeout_secs(300.0)
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
        self.backoff
            .delay(self.attempts, &mut rng)
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
    /// Kqueue event source for kernel jail monitoring (FreeBSD 16+)
    kqueue: Option<JailEventSource>,
    /// Map of JID -> jail name for kqueue event resolution
    jid_names: HashMap<i32, String>,
    /// Shared tracking for intentional stop requests
    intentional_stops: IntentionalStops,
}

impl Warden {
    /// Create a new Warden for the given bridge
    pub fn new(bridge: Arc<Mutex<Bridge>>) -> Self {
        let (tx, rx) = mpsc::channel(100);

        // Try to create kqueue source on FreeBSD 16+
        let kqueue = if OsVersion::detect_kernel()
            .map(|v| v.supports_jail_kqueue())
            .unwrap_or(false)
        {
            match JailEventSource::new() {
                Ok(source) => {
                    println!("Warden: Using kqueue jail event monitoring");
                    Some(source)
                }
                Err(e) => {
                    eprintln!(
                        "Warden: Failed to create kqueue source: {}, falling back to polling",
                        e
                    );
                    None
                }
            }
        } else {
            None
        };

        let intentional_stops = IntentionalStops::default();

        Self {
            rx,
            tx,
            restart_states: HashMap::new(),
            bridge,
            kqueue,
            jid_names: HashMap::new(),
            intentional_stops,
        }
    }

    /// Get a sender to notify the Warden of events
    pub fn sender(&self) -> mpsc::Sender<WardenEvent> {
        self.tx.clone()
    }

    /// Register a jail directly (before the event loop starts)
    pub fn register_jail_direct(&mut self, name: &str, jid: i32) {
        self.register_jail_monitoring(name, jid);
    }

    /// Register a jail for kqueue monitoring
    fn register_jail_monitoring(&mut self, name: &str, jid: i32) {
        self.jid_names.insert(jid, name.to_string());

        if let Some(ref kq) = self.kqueue {
            if let Err(e) = kq.register_jail(jid) {
                eprintln!(
                    "Warden: Failed to register kqueue for jail '{}' (JID {}): {}",
                    name, jid, e
                );
            } else {
                println!(
                    "Warden: Monitoring jail '{}' (JID {}) via kqueue",
                    name, jid
                );
            }
        }
    }

    /// Process kqueue events (non-blocking poll)
    fn process_kqueue_events(&mut self) -> Vec<(String, JailEvent)> {
        let kq = match &self.kqueue {
            Some(kq) => kq,
            None => return Vec::new(),
        };

        let events = match kq.poll(Some(Duration::ZERO)) {
            Ok(events) => events,
            Err(e) => {
                eprintln!("Warden: kqueue poll error: {}", e);
                return Vec::new();
            }
        };

        let mut named_events = Vec::new();
        for event in events {
            let jid = match &event {
                JailEvent::Remove { jid } => *jid,
                JailEvent::Child { jid } => *jid,
                JailEvent::Set { jid } => *jid,
                JailEvent::Attach { jid } => *jid,
            };

            if let Some(name) = self.jid_names.get(&jid) {
                named_events.push((name.clone(), event));
            }
        }

        named_events
    }

    /// Run the Warden event loop
    pub async fn run(&mut self) {
        println!("Warden: Starting jail supervisor");

        if self.kqueue.is_some() {
            self.run_with_kqueue().await;
        } else {
            self.run_polling().await;
        }

        println!("Warden: Supervisor stopped");
    }

    /// Event loop with kqueue integration (FreeBSD 16+)
    async fn run_with_kqueue(&mut self) {
        let kq_fd = self.kqueue.as_ref().unwrap().as_raw_fd();

        // Wrap the kqueue fd for async readiness notification
        let async_fd: tokio::io::unix::AsyncFd<i32> = match tokio::io::unix::AsyncFd::new(kq_fd) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!(
                    "Warden: Failed to create AsyncFd for kqueue: {}, falling back",
                    e
                );
                self.run_polling().await;
                return;
            }
        };

        loop {
            tokio::select! {
                // mpsc channel events (health failures, manual notifications)
                event = self.rx.recv() => {
                    match event {
                        Some(WardenEvent::Shutdown) | None => {
                            println!("Warden: Shutting down");
                            break;
                        }
                        Some(event) => self.handle_event(event).await,
                    }
                }

                // kqueue becomes readable — kernel jail events available
                ready = async_fd.readable() => {
                    if let Ok(mut guard) = ready {
                        let events = self.process_kqueue_events();
                        for (name, event) in events {
                            match event {
                                JailEvent::Remove { jid } => {
                                    self.jid_names.remove(&jid);
                                    if self.intentional_stops.contains(jid) {
                                        println!(
                                            "Warden: Kernel reports jail '{}' (JID {}) removed after requested stop",
                                            name, jid
                                        );
                                    } else {
                                        println!(
                                            "Warden: Kernel reports jail '{}' (JID {}) removed",
                                            name, jid
                                        );
                                        self.handle_failure(&name).await;
                                    }
                                }
                                JailEvent::Child { .. } => {
                                    // Child jail created — informational
                                }
                                JailEvent::Set { .. } => {
                                    // Jail modified — informational
                                }
                                JailEvent::Attach { .. } => {
                                    // Process attached — informational
                                }
                            }
                        }
                        guard.clear_ready();
                    }
                }
            }
        }

        // AsyncFd must not outlive the fd it wraps — drop it explicitly
        // The kqueue fd is owned by self.kqueue, so AsyncFd borrows it.
        // We need to forget the AsyncFd to prevent it from closing the fd.
        std::mem::forget(async_fd);
    }

    /// Polling-based event loop (pre-FreeBSD 16 fallback)
    async fn run_polling(&mut self) {
        while let Some(event) = self.rx.recv().await {
            match event {
                WardenEvent::Shutdown => {
                    println!("Warden: Shutting down");
                    break;
                }
                event => self.handle_event(event).await,
            }
        }
    }

    /// Handle a single warden event
    async fn handle_event(&mut self, event: WardenEvent) {
        match event {
            WardenEvent::JailFailed { name } => {
                println!("Warden: Jail '{}' failed, initiating restart", name);
                self.handle_failure(&name).await;
            }
            WardenEvent::JailHealthFailed { name } => {
                println!(
                    "Warden: Jail '{}' health check failed, initiating restart",
                    name
                );
                self.handle_failure(&name).await;
            }
            WardenEvent::JailStarted { name } => {
                println!("Warden: Jail '{}' started successfully", name);
                if let Some(state) = self.restart_states.get_mut(&name) {
                    state.reset();
                }
            }
            WardenEvent::JailStopped { name, jid } => {
                println!("Warden: Jail '{}' stopped intentionally", name);
                self.restart_states.remove(&name);
                self.jid_names.remove(&jid);
                self.intentional_stops.clear(jid);
            }
            WardenEvent::RegisterJail { name, jid } => {
                self.register_jail_monitoring(&name, jid);
            }
            WardenEvent::Shutdown => {
                // Handled in run loop
            }
        }
    }

    /// Handle a jail failure by attempting restart with backoff
    async fn handle_failure(&mut self, name: &str) {
        let state = self
            .restart_states
            .entry(name.to_string())
            .or_insert_with(|| RestartState::new(name));

        if !state.should_retry() {
            eprintln!(
                "Warden: Not restarting jail '{}' (circuit breaker open or max attempts reached)",
                name
            );
            return;
        }

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

        tokio::time::sleep(delay).await;

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

                // Re-register with kqueue if available
                if self.kqueue.is_some()
                    && let Ok(jid) = crate::jail::jail_getid(name)
                {
                    self.register_jail_monitoring(name, jid);
                }
            }
            Err(e) => {
                eprintln!("Warden: Failed to restart jail '{}': {}", name, e);
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
    intentional_stops: IntentionalStops,
}

impl WardenHandle {
    /// Create a handle from a Warden
    pub fn new(warden: &Warden) -> Self {
        Self {
            sender: warden.sender(),
            intentional_stops: warden.intentional_stops.clone(),
        }
    }

    /// Mark a jail as being stopped intentionally before removal begins.
    pub fn mark_stop_requested(&self, jid: i32) {
        self.intentional_stops.mark(jid);
    }

    /// Clear the intentional stop marker for a jail.
    pub fn clear_stop_requested(&self, jid: i32) {
        self.intentional_stops.clear(jid);
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
    pub fn notify_stopped_blocking(&self, name: &str, jid: i32) -> Result<()> {
        self.sender
            .blocking_send(WardenEvent::JailStopped {
                name: name.to_string(),
                jid,
            })
            .map_err(|_| crate::error::Error::Io(std::io::Error::other("Warden channel closed")))
    }

    /// Register a jail for kqueue monitoring (blocking version)
    #[allow(dead_code)]
    pub fn register_jail_blocking(&self, name: &str, jid: i32) -> Result<()> {
        self.sender
            .blocking_send(WardenEvent::RegisterJail {
                name: name.to_string(),
                jid,
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

    #[test]
    fn test_jid_name_tracking() {
        // Verify the jid_names map works correctly
        let mut map: HashMap<i32, String> = HashMap::new();
        map.insert(42, "test-jail".to_string());
        map.insert(43, "test-jail".to_string());
        assert_eq!(map.get(&42), Some(&"test-jail".to_string()));
        assert_eq!(map.get(&43), Some(&"test-jail".to_string()));

        // Remove only the stopped jail's JID
        map.remove(&42);
        assert!(!map.contains_key(&42));
        assert_eq!(map.get(&43), Some(&"test-jail".to_string()));
    }

    #[test]
    fn test_intentional_stops_track_jids() {
        let stops = IntentionalStops::default();
        stops.mark(42);

        assert!(stops.contains(42));
        assert!(!stops.contains(43));

        stops.clear(42);
        assert!(!stops.contains(42));
    }
}
