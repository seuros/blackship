//! Blackship: a FreeBSD jail orchestrator, as a CLI and as a library.
//!
//! The library half drives ephemeral jails from another program, such as
//! a CI runner, with no `blackship.toml` and no shelling out to the CLI:
//!
//! ```no_run
//! use blackship::{ContainerSpec, Exec, Host, Limits, Network, Selector};
//! use std::time::Duration;
//!
//! # fn main() -> blackship::Result<()> {
//! let host = Host::new("/var/db/kim/blackship").with_zfs("zroot", "kim/blackship");
//!
//! // Clean up after a previous crash, then make sure the userland is there.
//! host.reap_orphans(&Selector::prefix("kim-"))?;
//! host.ensure_release("16.0-CURRENT")?;
//!
//! let job = host.create(
//!     &ContainerSpec::new("kim-42", "16.0-CURRENT")
//!         .network(Network::Inherit)
//!         .limits(Limits::new().memory("4g")),
//! )?;
//! let run = job.exec(
//!     Exec::shell("make test")
//!         .timeout(Duration::from_secs(900))
//!         .on_output(|_stream, bytes| print!("{}", String::from_utf8_lossy(bytes))),
//! )?;
//! job.copy_out("/work/report.xml", "/tmp/kim-42-report.xml")?;
//! job.destroy()?;
//! # let _ = run;
//! # Ok(())
//! # }
//! ```
//!
//! Privileged calls fail with [`Error::NeedsRoot`] unless already root; the
//! library never re-executes through sudo or doas. Build with
//! `default-features = false` to leave out the CLI and MCP server.

// Without `cli` the orchestration half compiles but goes unused.
#![cfg_attr(not(feature = "cli"), allow(dead_code, unused_imports))]

#[cfg(not(target_os = "freebsd"))]
compile_error!(
    "blackship only supports FreeBSD. This crate requires jail(2) syscalls \
     which are only available on FreeBSD."
);

#[cfg(feature = "cli")]
mod app;
mod atomic;
mod audit;
mod blueprint;
mod bridge;
mod bulkhead;
#[cfg(feature = "cli")]
mod cli;
#[cfg(feature = "cli")]
mod commands;
mod console;
mod container;
mod error;
mod export;
mod fault;
mod gc;
mod hooks;
mod host;
#[cfg(feature = "cli")]
mod host_profile;
mod image;
mod jail;
mod manifest;
#[cfg(feature = "mcp")]
mod mcp;
mod network;
#[cfg(feature = "cli")]
mod output;
mod proc;
mod provision;
mod rctl;
mod release;
mod scope;
mod sickbay;
mod strings;
mod supply;
mod sys;
mod telemetry;
#[cfg(feature = "ui")]
mod ui;
mod warden;
mod zfs;

#[cfg(feature = "cli")]
pub use app::run;
pub use container::{
    Container, ContainerInfo, ContainerSpec, Exec, ExecOutput, Exit, Limits, Mount, Network,
    Selector, Stream,
};
pub use error::{Error, Result};
pub use host::Host;
pub use image::{Build, Image};
#[cfg(feature = "cli")]
pub use output::CliError;
pub use release::{Bootstrap, Release};
