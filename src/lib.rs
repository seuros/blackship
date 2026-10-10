//! Blackship - FreeBSD jail orchestrator
//!
//! Library crate for the Blackship CLI application.

#[cfg(not(target_os = "freebsd"))]
compile_error!(
    "blackship only supports FreeBSD. This crate requires jail(2) syscalls \
     which are only available on FreeBSD."
);

mod app;
mod atomic;
mod audit;
mod blueprint;
mod bridge;
mod bulkhead;
mod cli;
mod commands;
mod console;
mod error;
mod export;
mod gc;
mod hooks;
mod jail;
mod manifest;
mod network;
mod proc;
mod provision;
mod rctl;
mod scope;
mod sickbay;
mod strings;
mod supply;
mod sys;
mod telemetry;
mod warden;
mod zfs;

pub use app::run;
