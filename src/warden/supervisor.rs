//! Per-jail supervision machine driven by the `state-machines` runtime.
//!
//! The Warden owns one runner per supervised jail. Failures enqueue `Failed`,
//! the Warden arms a backoff timer on the `Backoff` visit, and the `Restarting`
//! visit invokes the restart as a runtime activity.

use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};

use crate::bridge::Bridge;
use crate::warden::WardenEvent;

pub use machine::{DynamicSupervisor, SupervisorEvent, SupervisorState};

/// What a supervision activity needs to restart its jail and re-arm monitoring.
pub struct SupervisorCtx {
    name: String,
    bridge: Arc<Mutex<Bridge>>,
    tx: mpsc::Sender<WardenEvent>,
}

impl std::fmt::Debug for SupervisorCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupervisorCtx")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl SupervisorCtx {
    pub fn new(name: &str, bridge: Arc<Mutex<Bridge>>, tx: mpsc::Sender<WardenEvent>) -> Self {
        Self {
            name: name.to_string(),
            bridge,
            tx,
        }
    }
}

mod machine {
    use super::{SupervisorCtx, restart};
    use state_machines::state_machine;

    state_machine! {
        name: Supervisor,
        dynamic: true,
        context: SupervisorCtx,
        initial: Healthy,
        states: [Healthy, Backoff, Restarting, Dead],
        final_states: [Dead],
        runtime: {
            Restarting { invoke: [begin_restart] }
        },
        events {
            failed    { transition: { from: Healthy, to: Backoff } }
            retry     { transition: { from: Backoff, to: Restarting } }
            recovered { transition: { from: Backoff, to: Healthy } }
            restarted { transition: { from: Restarting, to: Healthy } }
            relapsed  { transition: { from: Restarting, to: Backoff } }
            exhausted { transition: { from: [Healthy, Backoff, Restarting], to: Dead } }
        }
    }

    impl Supervisor<Restarting> {
        fn begin_restart(&self) -> impl Future<Output = SupervisorEvent> + Send + 'static {
            restart(&self.ctx)
        }
    }
}

fn restart(ctx: &SupervisorCtx) -> impl Future<Output = SupervisorEvent> + Send + 'static {
    let name = ctx.name.clone();
    let bridge = Arc::clone(&ctx.bridge);
    let tx = ctx.tx.clone();

    async move {
        let (result, descriptor_fd) = {
            let mut br = bridge.lock().await;
            let result = br.restart_jail(&name);
            (result, br.jail_descriptor_fd(&name))
        };

        match result {
            Ok(()) => {
                println!("Warden: Jail '{}' restarted successfully", name);
                match crate::jail::jail_getid(&name) {
                    Ok(jid) => {
                        if let Err(e) = tx.try_send(WardenEvent::RegisterJail {
                            name: name.clone(),
                            jid,
                            descriptor_fd,
                        }) {
                            eprintln!(
                                "Warden: Failed to re-register jail '{}' for monitoring: {}",
                                name, e
                            );
                        }
                    }
                    Err(e) => eprintln!(
                        "Warden: Restarted jail '{}' but could not resolve its jid: {}",
                        name, e
                    ),
                }
                SupervisorEvent::Restarted
            }
            Err(e) => {
                eprintln!("Warden: Failed to restart jail '{}': {}", name, e);
                SupervisorEvent::Relapsed
            }
        }
    }
}

#[cfg(test)]
mod tests;
