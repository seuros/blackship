//! Warden supervisor command

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::sync::Mutex;

use crate::error::Result;
use crate::{bridge, jail, manifest, sickbay, warden};

pub fn handle(config_path: &Path, verbose: bool) -> Result<()> {
    let config = manifest::load(config_path)?;
    let project_prefix = format!("{}-", config.config.project_name());
    let configured_jails = config.jails.clone();
    let rate_limit = config.config.rate_limit.clone();
    let monitor_ping_url = config.config.monitor_ping_url.clone();
    let usage_sample_secs = config.config.usage_sample_secs.unwrap_or(30);

    let bridge = bridge::Bridge::open(config, verbose)?;
    let autostart = bridge
        .autostart_order()?
        .into_iter()
        .collect::<HashSet<_>>();
    let jails_for_health = configured_jails
        .into_iter()
        .filter(|jail| autostart.contains(&jail.name))
        .collect::<Vec<_>>();
    let bridge = Arc::new(Mutex::new(bridge));

    let rt = tokio::runtime::Runtime::new()?;

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
            if let Err(e) = br.reconcile_autostart() {
                eprintln!("Warning: Failed to reconcile project autostart: {e}");
            }
        }

        let full_jail_name = |name: &str| full_jail_name(&project_prefix, name);

        // Register running jails with the Warden for kqueue monitoring
        for jail_def in &jails_for_health {
            let full_name = full_jail_name(&jail_def.name);
            if let Ok(jid) = jail::jail_getid(&full_name) {
                let descriptor_fd = bridge.lock().await.jail_descriptor_fd(&full_name);
                warden.register_jail_direct(&full_name, jid, descriptor_fd);
            }
        }

        let mut warden = warden;
        let warden_task = tokio::spawn(async move {
            warden.run().await;
        });

        spawn_qos_timers(
            &jails_for_health,
            &project_prefix,
            &warden_handle_for_health,
        );
        let health_stop_signals = spawn_health_monitors(
            &jails_for_health,
            &project_prefix,
            &rate_limit,
            &warden_handle_for_health,
        );

        if usage_sample_secs > 0 {
            let sampled: Vec<String> = jails_for_health
                .iter()
                .map(|jail_def| full_jail_name(&jail_def.name))
                .collect();
            spawn_usage_sampler(Arc::clone(&bridge), sampled, usage_sample_secs);
        }

        // Dead-man ping: prove the supervisor itself is alive.
        if let Some(url) = monitor_ping_url {
            spawn_monitor_ping(url);
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

        if let Err(e) = warden_task.await {
            eprintln!("Warning: Warden task failed: {e}");
        }
    });

    Ok(())
}

/// Prefix a service name with the project, unless it already carries it.
fn full_jail_name(project_prefix: &str, name: &str) -> String {
    if name.starts_with(project_prefix) {
        name.to_string()
    } else {
        format!("{project_prefix}{name}")
    }
}

/// One startup-budget timer per `QoS`-enabled jail. Must run inside tokio.
fn spawn_qos_timers(
    jails: &[manifest::JailDef],
    project_prefix: &str,
    warden_handle: &warden::WardenHandle,
) {
    for jail_def in jails {
        let Some(deadline) = jail_def
            .qos
            .as_ref()
            .and_then(bridge::startup_deadline_secs)
        else {
            continue;
        };

        let full_name = full_jail_name(project_prefix, &jail_def.name);
        let handle = warden_handle.clone();
        println!("QoS startup budget for jail '{full_name}': {deadline}s");
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(deadline)).await;
            if let Err(e) = handle.notify_qos_timeout(&full_name).await {
                eprintln!("Warning: Failed to signal QoS startup timeout for '{full_name}': {e}");
            }
        });
    }
}

/// One health-check loop per jail; returns their stop flags. Must run inside tokio.
fn spawn_health_monitors(
    jails: &[manifest::JailDef],
    project_prefix: &str,
    rate_limit: &manifest::RateLimitConfig,
    warden_handle: &warden::WardenHandle,
) -> Vec<Arc<AtomicBool>> {
    let mut health_stop_signals = Vec::new();

    for jail_def in jails {
        if !jail_def.healthcheck.enabled || jail_def.healthcheck.checks.is_empty() {
            continue;
        }
        let full_name = full_jail_name(project_prefix, &jail_def.name);

        let mut checker = sickbay::HealthChecker::with_rate_limit(
            &full_name,
            jail_def.healthcheck.clone(),
            rate_limit.health_capacity,
            rate_limit.health_refill_rate,
        )
        .with_warden_handle(warden_handle.clone());

        if let Ok(jid) = jail::jail_getid(&full_name) {
            checker = checker.with_jid(jid);
        }

        health_stop_signals.push(checker.stop_signal());

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

        println!("Spawned health monitor for jail '{full_name}'");
    }

    health_stop_signals
}

/// Periodic racct usage sampling for the named jails.
fn spawn_usage_sampler(bridge: Arc<Mutex<bridge::Bridge>>, sampled: Vec<String>, every_secs: u64) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(every_secs)).await;
            let br = bridge.lock().await;
            for name in &sampled {
                br.sample_usage(name);
            }
        }
    });
    println!("Racct usage sampling every {every_secs}s.");
}

/// Dead-man ping thread: GET `url` every 300s.
fn spawn_monitor_ping(url: String) {
    std::thread::spawn(move || {
        loop {
            if let Err(e) = ureq::get(&url).call() {
                eprintln!("Warning: monitor ping to {url} failed: {e}");
            }
            std::thread::sleep(std::time::Duration::from_secs(300));
        }
    });
    println!("Dead-man ping enabled (every 300s).");
}
