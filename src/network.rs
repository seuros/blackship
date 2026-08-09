//! Network management module for VNET jails
//!
//! Provides:
//! - Bridge interface management (if_bridge)
//! - Epair interface creation for VNET jails
//! - IP address allocation and management
//! - VNET jail network configuration

pub mod bridge;
pub mod ensure;
pub mod epair;
pub mod ioctl;
pub mod ip;
pub mod netgraph;
pub mod store;
pub mod vnet;

pub use bridge::Bridge;
pub use ip::{IpAllocator, IpPool};
pub use store::allocate_and_record;
pub use store::{
    NetworkLeaseStore, NetworkRecord, NetworkStore, ResolvedNetwork, VnetStateStore,
    build_runtime_allocator,
};
pub use vnet::{VnetConfig, VnetSetup};
