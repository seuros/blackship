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
use crate::jail::kqueue::{JailEvent, JailEventSource, JailIdent};
use crate::sys::OsVersion;

/// How often the kqueue is drained while the Warden is idle.
const KQUEUE_DRAIN_INTERVAL: Duration = Duration::from_millis(250);

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
    /// A jail's health check passed for the first time since it last failed
    JailHealthy { name: String },
    /// A jail exhausted its startup QoS budget without a health signal
    QosTimeout { name: String },
    /// Register a jail for kqueue monitoring (sent via WardenHandle after restart)
    RegisterJail {
        name: String,
        jid: i32,
        descriptor_fd: Option<i32>,
    },
    /// Shutdown the Warden
    Shutdown,
}

/// Shared tracking of jails being stopped intentionally.
#[derive(Clone, Default)]
struct IntentionalStops {
    jids: Arc<StdMutex<HashSet<i32>>>,
}

impl IntentionalStops {
    fn lock_jids(&self) -> std::sync::MutexGuard<'_, HashSet<i32>> {
        self.jids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn mark(&self, jid: i32) {
        self.lock_jids().insert(jid);
    }

    fn clear(&self, jid: i32) {
        self.lock_jids().remove(&jid);
    }

    fn contains(&self, jid: i32) -> bool {
        self.lock_jids().contains(&jid)
    }
}

/// Pick the kqueue identity to monitor a jail under.
///
/// A descriptor outlives jid reuse, so it wins whenever one is held.
fn monitor_ident(jid: i32, descriptor_fd: Option<i32>) -> JailIdent {
    match descriptor_fd {
        Some(fd) => JailIdent::Descriptor(fd),
        None => JailIdent::Jid(jid),
    }
}

/// Whether a jail is already monitored under a descriptor identity.
fn has_descriptor_ident(monitored: &HashMap<JailIdent, MonitoredJail>, name: &str) -> bool {
    monitored
        .iter()
        .any(|(ident, jail)| jail.name == name && matches!(ident, JailIdent::Descriptor(_)))
}

/// The identities registered for a jail, optionally narrowed to one jid.
fn idents_for(
    monitored: &HashMap<JailIdent, MonitoredJail>,
    name: &str,
    only_jid: Option<i32>,
) -> Vec<JailIdent> {
    monitored
        .iter()
        .filter(|(_, jail)| jail.name == name && only_jid.is_none_or(|wanted| jail.jid == wanted))
        .map(|(ident, _)| *ident)
        .collect()
}

/// The jail behind a registered kqueue identity
#[derive(Clone)]
struct MonitoredJail {
    name: String,
    jid: i32,
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
    /// Map of registered kqueue identity -> jail, for event resolution
    monitored: HashMap<JailIdent, MonitoredJail>,
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
            monitored: HashMap::new(),
            intentional_stops,
        }
    }

    /// Get a sender to notify the Warden of events
    pub fn sender(&self) -> mpsc::Sender<WardenEvent> {
        self.tx.clone()
    }

    /// Register a jail directly (before the event loop starts)
    pub fn register_jail_direct(&mut self, name: &str, jid: i32, descriptor_fd: Option<i32>) {
        self.register_jail_monitoring(name, jid, descriptor_fd);
    }

    /// Register a jail for kqueue monitoring.
    ///
    /// A descriptor identity is preferred: it stays valid across jid reuse.
    fn register_jail_monitoring(&mut self, name: &str, jid: i32, descriptor_fd: Option<i32>) {
        let ident = monitor_ident(jid, descriptor_fd);

        if descriptor_fd.is_none() && has_descriptor_ident(&self.monitored, name) {
            return;
        }

        self.monitored.insert(
            ident,
            MonitoredJail {
                name: name.to_string(),
                jid,
            },
        );

        if let Some(ref kq) = self.kqueue {
            let registered = match ident {
                JailIdent::Descriptor(fd) => kq.register_jaildesc(fd),
                JailIdent::Jid(jid) => kq.register_jail(jid),
            };

            match registered {
                Ok(()) => println!("Warden: Monitoring jail '{}' ({}) via kqueue", name, ident),
                Err(e) => eprintln!(
                    "Warden: Failed to register kqueue for jail '{}' ({}): {}",
                    name, ident, e
                ),
            }
        }
    }

    /// Stop monitoring every identity registered for a jail
    fn unregister_jail_monitoring(&mut self, name: &str) {
        self.unregister_idents(name, None)
    }

    /// Stop monitoring only the identities that belong to a specific jid.
    fn unregister_jail_jid(&mut self, name: &str, jid: i32) {
        self.unregister_idents(name, Some(jid))
    }

    fn unregister_idents(&mut self, name: &str, only_jid: Option<i32>) {
        for ident in idents_for(&self.monitored, name, only_jid) {
            self.monitored.remove(&ident);
            if let Some(ref kq) = self.kqueue
                && let Err(e) = kq.unregister(ident)
            {
                eprintln!(
                    "Warden: Failed to unregister kqueue for jail '{}' ({}): {}",
                    name, ident, e
                );
            }
        }
    }

    /// Process kqueue events (non-blocking poll)
    fn process_kqueue_events(&mut self) -> Vec<(MonitoredJail, JailEvent)> {
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
            if let Some(jail) = self.monitored.get(&event.ident()) {
                named_events.push((jail.clone(), event));
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
        let mut drain = tokio::time::interval(KQUEUE_DRAIN_INTERVAL);
        drain.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

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

                _ = drain.tick() => {
                    {
                        let events = self.process_kqueue_events();
                        for (jail, event) in events {
                            let MonitoredJail { name, jid } = jail;
                            match event {
                                JailEvent::Remove { ident } => {
                                    self.monitored.remove(&ident);
                                    if self.intentional_stops.contains(jid) {
                                        println!(
                                            "Warden: Kernel reports jail '{}' ({}) removed after requested stop",
                                            name, ident
                                        );
                                    } else {
                                        println!(
                                            "Warden: Kernel reports jail '{}' ({}) removed",
                                            name, ident
                                        );
                                        self.handle_failure(&name).await;
                                    }
                                }
                                JailEvent::Child { ident, coalesced } => {
                                    let detail = if coalesced {
                                        "multiple child jails"
                                    } else {
                                        "a child jail"
                                    };
                                    println!(
                                        "Warden: Jail '{}' ({}) created {}",
                                        name, ident, detail
                                    );
                                }
                                JailEvent::Set { .. } => {
                                }
                                JailEvent::Attach { ident, coalesced } => {
                                    if coalesced {
                                        println!(
                                            "Warden: Jail '{}' ({}) had multiple attaches",
                                            name, ident
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
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
            WardenEvent::JailHealthy { name } => {
                self.shift_to_steady(&name, "healthy").await;
            }
            WardenEvent::QosTimeout { name } => {
                self.shift_to_steady(&name, "timer").await;
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
                self.unregister_jail_jid(&name, jid);
                self.intentional_stops.clear(jid);
            }
            WardenEvent::RegisterJail {
                name,
                jid,
                descriptor_fd,
            } => {
                self.register_jail_monitoring(&name, jid, descriptor_fd);
            }
            WardenEvent::Shutdown => {
                // Handled in run loop
            }
        }
    }

    /// Move a jail from its startup QoS profile to its steady one.
    async fn shift_to_steady(&mut self, name: &str, trigger: &str) {
        let result = {
            let br = self.bridge.lock().await;
            br.shift_qos(name, crate::scope::QosPhase::Steady)
        };

        match result {
            Ok(crate::bridge::ShiftOutcome::Shifted) => {
                println!(
                    "Warden: Jail '{}' shifted to steady QoS profile ({})",
                    name, trigger
                );
            }
            Ok(_) => {}
            Err(e) => eprintln!(
                "Warden: Failed to shift jail '{}' to steady QoS profile: {}",
                name, e
            ),
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

        let (result, descriptor_fd) = {
            let mut br = self.bridge.lock().await;
            let result = br.restart_jail(name);
            (result, br.jail_descriptor_fd(name))
        };

        match result {
            Ok(_) => {
                println!("Warden: Jail '{}' restarted successfully", name);
                if let Some(state) = self.restart_states.get_mut(name) {
                    state.reset();
                }

                self.unregister_jail_monitoring(name);
                if let Ok(jid) = crate::jail::jail_getid(name) {
                    self.register_jail_monitoring(name, jid, descriptor_fd);
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

    fn channel_closed_err() -> crate::error::Error {
        crate::error::Error::Io(std::io::Error::other("Warden channel closed"))
    }

    /// Post an event from synchronous code without blocking.
    fn post(&self, event: WardenEvent) -> Result<()> {
        self.sender.try_send(event).map_err(|e| match e {
            mpsc::error::TrySendError::Closed(_) => Self::channel_closed_err(),
            mpsc::error::TrySendError::Full(_) => {
                crate::error::Error::Io(std::io::Error::other("Warden event queue full"))
            }
        })
    }

    /// Notify that a jail failed
    pub fn notify_failure(&self, name: &str) -> Result<()> {
        self.post(WardenEvent::JailFailed {
            name: name.to_string(),
        })
    }

    /// Notify that a jail's health check failed
    pub fn notify_health_failure(&self, name: &str) -> Result<()> {
        self.post(WardenEvent::JailHealthFailed {
            name: name.to_string(),
        })
    }

    /// Notify that a jail's health check passed
    pub fn notify_healthy(&self, name: &str) -> Result<()> {
        self.post(WardenEvent::JailHealthy {
            name: name.to_string(),
        })
    }

    /// Notify that a jail exhausted its startup QoS budget
    pub async fn notify_qos_timeout(&self, name: &str) -> Result<()> {
        self.sender
            .send(WardenEvent::QosTimeout {
                name: name.to_string(),
            })
            .await
            .map_err(|_| Self::channel_closed_err())
    }

    /// Notify that a jail started
    pub fn notify_started(&self, name: &str) -> Result<()> {
        self.post(WardenEvent::JailStarted {
            name: name.to_string(),
        })
    }

    /// Notify that a jail stopped intentionally
    pub fn notify_stopped(&self, name: &str, jid: i32) -> Result<()> {
        self.post(WardenEvent::JailStopped {
            name: name.to_string(),
            jid,
        })
    }

    /// Register a jail for kqueue monitoring
    pub fn register_jail(&self, name: &str, jid: i32, descriptor_fd: Option<i32>) -> Result<()> {
        self.post(WardenEvent::RegisterJail {
            name: name.to_string(),
            jid,
            descriptor_fd,
        })
    }
}

#[cfg(test)]
mod tests;
