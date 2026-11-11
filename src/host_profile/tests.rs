use super::*;

#[test]
fn usable_hosts_leave_out_network_broadcast_and_gateway() {
    assert_eq!(usable_hosts("10.0.1.0/24".parse().unwrap()), Some(253));
    assert_eq!(usable_hosts("10.0.1.0/30".parse().unwrap()), Some(1));
    assert_eq!(usable_hosts("fd00::/64".parse().unwrap()), None);
}
