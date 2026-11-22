use super::*;

struct TestBridge(String);

impl Drop for TestBridge {
    fn drop(&mut self) {
        let _ = ioctl::destroy_interface(&self.0);
    }
}

#[test]
#[ignore = "needs root and if_bridge"]
fn existing_epair_bridge_recovers_its_gateway() {
    crate::sys::load_modules(&["if_bridge", "bridgestp"]).unwrap();
    let bridge = TestBridge(ioctl::create_interface("bridge", None).unwrap());
    let mut record = NetworkRecord {
        name: "test-network".to_string(),
        bridge: bridge.0.clone(),
        subnet: "192.0.2.0/24".to_string(),
        gateway: "192.0.2.1".to_string(),
        backend: "epair".to_string(),
        host_iface: None,
    };

    assert!(!ioctl::has_ipv4_address(&bridge.0, "192.0.2.1/24").unwrap());
    assert!(!ensure_network(&mut record).unwrap());
    assert!(ioctl::has_ipv4_address(&bridge.0, "192.0.2.1/24").unwrap());
}
