//! IP address management for jail networks
//!
//! Provides:
//! - IP pool allocation from subnets
//! - Tracking of allocated addresses
//! - Support for IPv4 and IPv6

use crate::error::{Error, Result};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::collections::HashSet;
use std::net::IpAddr;

/// IP address pool for a network
#[derive(Debug, Clone)]
pub struct IpPool {
    /// Network subnet
    subnet: IpNet,
    /// Gateway address (usually first usable in subnet)
    gateway: IpAddr,
    /// Set of allocated addresses
    allocated: HashSet<IpAddr>,
}

impl IpPool {
    /// Create a new IP pool from a subnet
    ///
    /// The gateway is automatically set to the first usable address.
    pub fn new(subnet: IpNet) -> Result<Self> {
        let gateway = Self::first_usable(&subnet)?;
        let mut allocated = HashSet::new();
        // Reserve gateway
        allocated.insert(gateway);

        Ok(Self {
            subnet,
            gateway,
            allocated,
        })
    }

    /// Create a new IP pool with a specific gateway
    pub fn with_gateway(subnet: IpNet, gateway: IpAddr) -> Result<Self> {
        if !subnet.contains(&gateway) {
            return Err(Error::Network(format!(
                "Gateway {} is not in subnet {}",
                gateway, subnet
            )));
        }

        let mut allocated = HashSet::new();
        allocated.insert(gateway);

        Ok(Self {
            subnet,
            gateway,
            allocated,
        })
    }

    /// Allocate the next available IP address
    pub fn allocate(&mut self) -> Result<IpAddr> {
        match self.subnet {
            IpNet::V4(net) => self.allocate_v4(net),
            IpNet::V6(net) => self.allocate_v6(net),
        }
    }

    /// Allocate a specific IP address
    pub fn allocate_specific(&mut self, addr: IpAddr) -> Result<()> {
        if !self.subnet.contains(&addr) {
            return Err(Error::Network(format!(
                "Address {} is not in subnet {}",
                addr, self.subnet
            )));
        }

        if self.allocated.contains(&addr) {
            return Err(Error::Network(format!(
                "Address {} is already allocated",
                addr
            )));
        }

        self.allocated.insert(addr);
        Ok(())
    }

    /// Release an allocated IP address
    pub fn release(&mut self, addr: &IpAddr) {
        // Don't release the gateway
        if *addr != self.gateway {
            self.allocated.remove(addr);
        }
    }

    fn allocate_v4(&mut self, net: Ipv4Net) -> Result<IpAddr> {
        // Skip network address and broadcast
        let hosts = net.hosts();
        for addr in hosts {
            let ip = IpAddr::V4(addr);
            if !self.allocated.contains(&ip) {
                self.allocated.insert(ip);
                return Ok(ip);
            }
        }

        Err(Error::Network(format!(
            "No available addresses in {}",
            net
        )))
    }

    fn allocate_v6(&mut self, net: Ipv6Net) -> Result<IpAddr> {
        // For IPv6, we iterate through hosts
        // Note: For large subnets, this could be slow
        let hosts = net.hosts();
        for addr in hosts.take(65536) {
            // Limit iteration
            let ip = IpAddr::V6(addr);
            if !self.allocated.contains(&ip) {
                self.allocated.insert(ip);
                return Ok(ip);
            }
        }

        Err(Error::Network(format!(
            "No available addresses in {}",
            net
        )))
    }

    fn first_usable(subnet: &IpNet) -> Result<IpAddr> {
        match subnet {
            IpNet::V4(net) => net
                .hosts()
                .next()
                .map(IpAddr::V4)
                .ok_or_else(|| Error::Network("Network too small for gateway".to_string())),
            IpNet::V6(net) => net
                .hosts()
                .next()
                .map(IpAddr::V6)
                .ok_or_else(|| Error::Network("Network too small for gateway".to_string())),
        }
    }

    // Test-only accessors for verifying internal state
    #[cfg(test)]
    pub fn subnet(&self) -> IpNet {
        self.subnet
    }

    #[cfg(test)]
    pub fn gateway(&self) -> IpAddr {
        self.gateway
    }

    #[cfg(test)]
    pub fn is_available(&self, addr: &IpAddr) -> bool {
        self.subnet.contains(addr) && !self.allocated.contains(addr)
    }

    #[cfg(test)]
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }
}

/// IP allocator that manages multiple networks
#[derive(Debug, Default)]
pub struct IpAllocator {
    /// Map of network name to IP pool
    pools: std::collections::HashMap<String, IpPool>,
}

impl IpAllocator {
    /// Create a new IP allocator
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a network pool
    pub fn add_pool(&mut self, name: String, pool: IpPool) {
        self.pools.insert(name, pool);
    }

    /// Get a mutable pool by name
    pub fn get_pool_mut(&mut self, name: &str) -> Option<&mut IpPool> {
        self.pools.get_mut(name)
    }

    /// Allocate an address from a named pool
    pub fn allocate(&mut self, network: &str) -> Result<IpAddr> {
        let pool = self
            .pools
            .get_mut(network)
            .ok_or_else(|| Error::Network(format!("Network '{}' not found", network)))?;
        pool.allocate()
    }

    /// Release an address back to its pool
    pub fn release(&mut self, network: &str, addr: &IpAddr) {
        if let Some(pool) = self.pools.get_mut(network) {
            pool.release(addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ip_pool_creation() {
        let subnet: IpNet = "10.0.1.0/24".parse().unwrap();
        let pool = IpPool::new(subnet).unwrap();

        assert_eq!(pool.subnet(), subnet);
        assert_eq!(pool.gateway(), IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)));
        assert_eq!(pool.allocated_count(), 1); // Gateway is allocated
    }

    #[test]
    fn test_ip_allocation() {
        let subnet: IpNet = "10.0.1.0/24".parse().unwrap();
        let mut pool = IpPool::new(subnet).unwrap();

        // Gateway is 10.0.1.1, so first allocation should be 10.0.1.2
        let ip = pool.allocate().unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)));

        let ip2 = pool.allocate().unwrap();
        assert_eq!(ip2, IpAddr::V4(Ipv4Addr::new(10, 0, 1, 3)));
    }

    #[test]
    fn test_ip_release() {
        let subnet: IpNet = "10.0.1.0/24".parse().unwrap();
        let mut pool = IpPool::new(subnet).unwrap();

        let ip = pool.allocate().unwrap();
        assert_eq!(pool.allocated_count(), 2);

        pool.release(&ip);
        assert_eq!(pool.allocated_count(), 1);

        // Can allocate same IP again
        let ip2 = pool.allocate().unwrap();
        assert_eq!(ip, ip2);
    }

    #[test]
    fn test_specific_allocation() {
        let subnet: IpNet = "10.0.1.0/24".parse().unwrap();
        let mut pool = IpPool::new(subnet).unwrap();

        let specific = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 100));
        pool.allocate_specific(specific).unwrap();

        assert!(!pool.is_available(&specific));
    }
}
