//! The Warden - Jail Supervisor
//!
//! Monitors jails and implements one-for-one restart strategy:
//! - Watches for kernel jail removal events via kqueue (FreeBSD 16+)
//! - Falls back to event-driven mpsc channel on older systems
//! - Auto-restarts failed jails, each restart waiting twice as long as the last
//! - Gives up on a jail that needs more than five restarts in five minutes

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use rand::{RngExt, rng};
use state_machines::runtime::{Clock, Runner};
use supervisor_machines::{Decision, Exit, Intensity, Policy, Strategy, Supervisor};
use tokio::sync::{Mutex, mpsc};

use crate::bridge::Bridge;
use crate::error::Result;
use crate::jail::kqueue::{JailEvent, JailEventSource, JailIdent};
use crate::sys::OsVersion;

mod supervisor;

use supervisor::{DynamicSupervisor, SupervisorCtx, SupervisorEvent, SupervisorState};

/// How often the kqueue is drained and supervision timers are advanced.
const KQUEUE_DRAIN_INTERVAL: Duration = Duration::from_millis(250);

/// Dispatch budget for one supervision drain.
const SUPERVISION_STEPS: usize = 32;

/// Mailbox capacity of a single supervision runner.
const SUPERVISION_MAILBOX: usize = 8;

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
    /// A jail exhausted its startup `QoS` budget without a health signal
    QosTimeout { name: String },
    /// Register a jail for kqueue monitoring (sent via `WardenHandle` after restart)
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
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
const fn monitor_ident(jid: i32, descriptor_fd: Option<i32>) -> JailIdent {
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

/// Restarts tolerated per jail before supervision gives up on it.
const RESTART_INTENSITY: Intensity = Intensity::new(5, 300 * NS_PER_SEC);
/// First restart delay, doubled per recent restart up to the ceiling.
const RESTART_DELAY_BASE_NS: u64 = NS_PER_SEC;
const RESTART_DELAY_CEILING_NS: u64 = 60 * NS_PER_SEC;
const NS_PER_SEC: u64 = 1_000_000_000;

/// One jail is one child under its own one-for-one supervisor.
type RestartPolicy = Supervisor<1, 8>;

/// Monotonic millisecond ticks for the supervision runners.
struct MillisClock {
    origin: Instant,
}

impl MillisClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl MillisClock {
    fn now_ns(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

impl Clock for MillisClock {
    fn now(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Supervision of a single jail: the runtime machine plus the restart policy
/// that decides whether and when it comes back.
struct Supervision {
    runner: Runner<DynamicSupervisor>,
    policy: RestartPolicy,
}

impl Supervision {
    fn new(
        name: &str,
        bridge: Arc<Mutex<Bridge>>,
        tx: mpsc::Sender<WardenEvent>,
        clock: &MillisClock,
    ) -> Self {
        let machine = DynamicSupervisor::new(SupervisorCtx::new(name, bridge, tx));
        let mut runner = Runner::new(machine, SUPERVISION_MAILBOX);

        if let Err(e) = runner.start(clock) {
            eprintln!("Warden: Failed to start supervision of jail '{name}': {e:?}");
        }

        Self {
            runner,
            policy: RestartPolicy::new(Strategy::OneForOne, RESTART_INTENSITY),
        }
    }

    fn state(&self) -> SupervisorState {
        self.runner.machine().current_state()
    }

    /// Arm the retry timer for a `Backoff` visit that has none, or give up.
    fn arm_backoff(&mut self, name: &str, clock: &MillisClock) {
        if self.state() != SupervisorState::Backoff || self.runner.next_deadline().is_some() {
            return;
        }

        let now = clock.now_ns();
        if self
            .policy
            .stopped(0, Policy::Permanent, Exit::Abnormal, now)
            == Decision::Escalate
        {
            eprintln!("Warden: Not restarting jail '{name}' (restart intensity exceeded)");
            self.enqueue(name, SupervisorEvent::Exhausted);
            return;
        }

        let delay_ns =
            self.policy
                .restart_delay_ns(RESTART_DELAY_BASE_NS, RESTART_DELAY_CEILING_NS, now);
        // Up to half off, so jails that failed together do not restart in lockstep.
        let delay = Duration::from_nanos(delay_ns).mul_f64(rng().random_range(0.5..=1.0));
        println!(
            "Warden: Restarting jail '{name}' in {delay:?} (restart {} in window)",
            self.policy.recent_restarts(now)
        );

        let ticks = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
        if let Err(e) = self
            .runner
            .schedule_after(clock, ticks, SupervisorEvent::Retry)
        {
            eprintln!("Warden: Failed to schedule restart of jail '{name}': {e:?}");
        }
    }

    fn enqueue(&self, name: &str, event: SupervisorEvent) {
        if let Err(e) = self.runner.enqueue(event) {
            eprintln!("Warden: Supervision mailbox rejected event for '{name}': {e:?}");
        }
    }
}

/// The Warden supervises all jails with one-for-one restart strategy
pub struct Warden {
    /// Channel to receive events
    rx: mpsc::Receiver<WardenEvent>,
    /// Sender for notifying the Warden (cloneable)
    tx: mpsc::Sender<WardenEvent>,
    /// Supervision runner per jail
    supervisors: HashMap<String, Supervision>,
    /// Logical clock driving the supervision timers
    clock: MillisClock,
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
        let kqueue = if OsVersion::detect_kernel().is_ok_and(|v| v.supports_jail_kqueue()) {
            match JailEventSource::new() {
                Ok(source) => {
                    println!("Warden: Using kqueue jail event monitoring");
                    Some(source)
                }
                Err(e) => {
                    eprintln!(
                        "Warden: Failed to create kqueue source: {e}, falling back to polling"
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
            supervisors: HashMap::new(),
            clock: MillisClock::new(),
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

        for stale in idents_for(&self.monitored, name, None) {
            if stale != ident {
                self.unregister_ident(name, stale);
            }
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
                Ok(()) => println!("Warden: Monitoring jail '{name}' ({ident}) via kqueue"),
                Err(e) => {
                    eprintln!("Warden: Failed to register kqueue for jail '{name}' ({ident}): {e}");
                }
            }
        }
    }

    /// Stop monitoring only the identities that belong to a specific jid.
    fn unregister_jail_jid(&mut self, name: &str, jid: i32) {
        self.unregister_idents(name, Some(jid));
    }

    fn unregister_idents(&mut self, name: &str, only_jid: Option<i32>) {
        for ident in idents_for(&self.monitored, name, only_jid) {
            self.unregister_ident(name, ident);
        }
    }

    fn unregister_ident(&mut self, name: &str, ident: JailIdent) {
        self.monitored.remove(&ident);
        if let Some(ref kq) = self.kqueue
            && let Err(e) = kq.unregister(ident)
        {
            eprintln!("Warden: Failed to unregister kqueue for jail '{name}' ({ident}): {e}");
        }
    }

    /// Process kqueue events (non-blocking poll)
    fn process_kqueue_events(&self) -> Vec<(MonitoredJail, JailEvent)> {
        let Some(kq) = &self.kqueue else {
            return Vec::new();
        };

        let events = match kq.poll(Some(Duration::ZERO)) {
            Ok(events) => events,
            Err(e) => {
                eprintln!("Warden: kqueue poll error: {e}");
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

        let mut ticker = tokio::time::interval(KQUEUE_DRAIN_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

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

                _ = ticker.tick() => self.drain_kqueue(),
            }

            self.pump().await;
        }

        println!("Warden: Supervisor stopped");
    }

    /// Resolve pending kernel jail events (no-op without kqueue)
    fn drain_kqueue(&mut self) {
        for (jail, event) in self.process_kqueue_events() {
            let MonitoredJail { name, jid } = jail;
            match event {
                JailEvent::Remove { ident } => {
                    self.monitored.remove(&ident);
                    if self.intentional_stops.contains(jid) {
                        println!(
                            "Warden: Kernel reports jail '{name}' ({ident}) removed after requested stop"
                        );
                    } else {
                        println!("Warden: Kernel reports jail '{name}' ({ident}) removed");
                        self.handle_failure(&name);
                    }
                }
                JailEvent::Child { ident, coalesced } => {
                    let detail = if coalesced {
                        "multiple child jails"
                    } else {
                        "a child jail"
                    };
                    println!("Warden: Jail '{name}' ({ident}) created {detail}");
                }
                JailEvent::Set { .. } => {}
                JailEvent::Attach { ident, coalesced } => {
                    if coalesced {
                        println!("Warden: Jail '{name}' ({ident}) had multiple attaches");
                    }
                }
            }
        }
    }

    /// Advance every supervision runner: timers, dispatch, restart activities.
    async fn pump(&mut self) {
        for (name, supervision) in &mut self.supervisors {
            if supervision.runner.tick(&self.clock).is_err() {
                eprintln!("Warden: Monotonic clock went backwards supervising jail '{name}'");
            }

            if let Err(e) = supervision.runner.drain(SUPERVISION_STEPS).await {
                eprintln!("Warden: Supervision of jail '{name}' failed: {e:?}");
            }

            supervision.arm_backoff(name, &self.clock);
        }
    }

    /// Handle a single warden event
    async fn handle_event(&mut self, event: WardenEvent) {
        match event {
            WardenEvent::JailFailed { name } => {
                println!("Warden: Jail '{name}' failed, initiating restart");
                self.handle_failure(&name);
            }
            WardenEvent::JailHealthFailed { name } => {
                println!("Warden: Jail '{name}' health check failed, initiating restart");
                self.handle_failure(&name);
            }
            WardenEvent::JailHealthy { name } => {
                self.shift_to_steady(&name, "healthy").await;
            }
            WardenEvent::QosTimeout { name } => {
                self.shift_to_steady(&name, "timer").await;
            }
            WardenEvent::JailStarted { name } => {
                println!("Warden: Jail '{name}' started successfully");
                if let Some(supervision) = self.supervisors.get_mut(&name)
                    && supervision.state() == SupervisorState::Backoff
                {
                    supervision.enqueue(&name, SupervisorEvent::Recovered);
                }
            }
            WardenEvent::JailStopped { name, jid } => {
                println!("Warden: Jail '{name}' stopped intentionally");
                self.supervisors.remove(&name);
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

    /// Move a jail from its startup `QoS` profile to its steady one.
    #[allow(clippy::needless_pass_by_ref_mut)] // &self makes run()'s future need Warden: Sync, which it is not
    async fn shift_to_steady(&mut self, name: &str, trigger: &str) {
        let result = {
            let br = self.bridge.lock().await;
            br.shift_qos(name, crate::scope::QosPhase::Steady)
        };

        match result {
            Ok(crate::bridge::ShiftOutcome::Shifted) => {
                println!("Warden: Jail '{name}' shifted to steady QoS profile ({trigger})");
            }
            Ok(_) => {}
            Err(e) => eprintln!("Warden: Failed to shift jail '{name}' to steady QoS profile: {e}"),
        }
    }

    /// Hand a jail failure to its supervision machine
    fn handle_failure(&mut self, name: &str) {
        let bridge = Arc::clone(&self.bridge);
        let tx = self.tx.clone();
        let clock = &self.clock;

        let supervision = self
            .supervisors
            .entry(name.to_string())
            .or_insert_with(|| Supervision::new(name, bridge, tx, clock));

        match supervision.state() {
            SupervisorState::Healthy => supervision.enqueue(name, SupervisorEvent::Failed),
            SupervisorState::Dead => {
                eprintln!("Warden: Not restarting jail '{name}' (supervision exhausted)");
            }
            state => println!(
                "Warden: Jail '{}' is already recovering ({})",
                name,
                state.name()
            ),
        }
    }

    /// Request the Warden to shutdown
    pub async fn request_shutdown(sender: &mpsc::Sender<WardenEvent>) {
        // Receiver gone means already shut down.
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

    /// Notify that a jail exhausted its startup `QoS` budget
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
