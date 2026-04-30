//! Warden supervisor command

use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::error::Result;
use crate::{bridge, error, jail, manifest, sickbay, warden};

pub fn handle(config_path: &Path, verbose: bool) -> Result<()> {
    let config = manifest::load(config_path)?;
    let project_name = config.config.project_name();
    let project_prefix = format!("{}-", project_name);
    let jails_for_health = config.jails.clone();
    let rate_limit = config.config.rate_limit.clone();

    let bridge = bridge::Bridge::new(config)?.verbose(verbose);
    let bridge = Arc::new(Mutex::new(bridge));

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| error::Error::Io(std::io::Error::other(e)))?;

    rt.block_on(async {
        let mut warden = warden::Warden::new(Arc::clone(&bridge));
        let sender = warden.sender();

        let warden_handle_for_orch = warden::WardenHandle::new(&warden);
        let warden_handle_for_health = warden::WardenHandle::new(&warden);

        {
            let mut br = bridge.lock().await;
            br.set_warden_handle(warden_handle_for_orch);
        }

        {
            let mut br = bridge.lock().await;
            if let Err(e) = br.up(None) {
                eprintln!("Warning: Failed to start some jails: {}", e);
            }
        }

        // Register running jails with the Warden for kqueue monitoring
        for jail_def in &jails_for_health {
            let full_name = if jail_def.name.starts_with(&project_prefix) {
                jail_def.name.clone()
            } else {
                format!("{}-{}", project_name, jail_def.name)
            };
            if let Ok(jid) = jail::jail_getid(&full_name) {
                warden.register_jail_direct(&full_name, jid);
            }
        }

        let mut warden = warden;
        let warden_task = tokio::spawn(async move {
            warden.run().await;
        });

        let mut health_stop_signals = Vec::new();

        for jail_def in &jails_for_health {
            if jail_def.healthcheck.enabled && !jail_def.healthcheck.checks.is_empty() {
                let full_name = if jail_def.name.starts_with(&project_prefix) {
                    jail_def.name.clone()
                } else {
                    format!("{}-{}", project_name, jail_def.name)
                };
                let healthcheck_config = jail_def.healthcheck.clone();
                let handle = warden_handle_for_health.clone();
                let health_capacity = rate_limit.health_capacity;
                let health_refill_rate = rate_limit.health_refill_rate;

                let mut checker = sickbay::HealthChecker::with_rate_limit(
                    &full_name,
                    healthcheck_config,
                    health_capacity,
                    health_refill_rate,
                )
                .with_warden_handle(handle);

                if let Ok(jid) = jail::jail_getid(&full_name) {
                    checker = checker.with_jid(jid);
                }

                let stop_signal = checker.stop_signal();
                health_stop_signals.push(stop_signal);

                tokio::spawn(async move {
                    while !checker.is_stopped() {
                        if let Err(e) = checker.run_checks() {
                            eprintln!("Health check error for {}: {}", checker.jail_name(), e);
                        }

                        let status = checker.status();
                        if status == sickbay::HealthStatus::Failing {
                            eprintln!("Health check failing for jail '{}'", checker.jail_name());
                        }

                        tokio::time::sleep(tokio::time::Duration::from_secs(
                            checker.interval().as_secs(),
                        ))
                        .await;
                    }
                    println!("Health monitor stopped for jail '{}'", checker.jail_name());
                });

                println!("Spawned health monitor for jail '{}'", full_name);
            }
        }

        println!("Warden supervisor started. Press Ctrl+C to stop.");

        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");

        println!("\nShutting down...");

        for stop_signal in &health_stop_signals {
            stop_signal.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        if !health_stop_signals.is_empty() {
            println!("Stopped {} health monitor(s)", health_stop_signals.len());
        }

        warden::Warden::request_shutdown(&sender).await;

        let _ = warden_task.await;
    });

    Ok(())
}
