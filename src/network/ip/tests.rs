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
