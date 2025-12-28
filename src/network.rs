//! Network management module for VNET jails
//!
//! Provides:
//! - Bridge interface management (if_bridge)
//! - Epair interface creation for VNET jails
//! - IP address allocation and management
//! - VNET jail network configuration

pub mod bridge;
pub mod epair;
pub mod ip;
pub mod vnet;

pub use bridge::Bridge;
pub use epair::EpairInterface;
pub use ip::{IpAllocator, IpPool};
pub use vnet::{VnetConfig, VnetSetup};
