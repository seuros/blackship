use super::*;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("blackship-bulkhead-{}", unique))
}

#[test]
fn test_drain_rules_block_syn_only_per_address() {
    let ips: Vec<IpAddr> = vec!["10.0.1.10".parse().unwrap(), "2001:db8::5".parse().unwrap()];

    let rules = drain_rules(&ips);
    let lines: Vec<&str> = rules.lines().collect();

    assert_eq!(lines.len(), 2);
    assert_eq!(
        lines[0],
        "block drop in quick proto tcp to 10.0.1.10 flags S/SA"
    );
    assert_eq!(
        lines[1],
        "block drop in quick proto tcp to 2001:db8::5 flags S/SA"
    );
}

#[test]
fn test_drain_anchor_path_is_sanitized_and_namespaced() {
    assert_eq!(
        drain_anchor_path("myproject-web"),
        "blackship/drain/myproject-web"
    );
    assert_eq!(
        drain_anchor_path("proj/web 1"),
        "blackship/drain/proj_web_1"
    );
}

#[test]
fn test_load_drain_anchor_rejects_empty_address_list() {
    assert!(load_drain_anchor("web", &[]).is_err());
}

#[test]
fn test_port_forward_rule() {
    let forward = PortForward::new(8080, 80, "tcp", "10.0.1.10".parse().unwrap(), "webserver");

    let rule = forward.to_pf_rule().unwrap();
    assert!(rule.contains("rdr"));
    assert!(rule.contains("proto tcp"));
    assert!(rule.contains("port 8080"));
    assert!(rule.contains("-> 10.0.1.10"));
    assert!(rule.contains("port 80"));
    assert!(rule.contains("# jail:webserver"));
}

#[test]
fn test_port_forward_with_bind_ip() {
    let forward = PortForward::new(443, 443, "tcp", "10.0.1.10".parse().unwrap(), "webserver")
        .with_bind_ip("192.168.1.100".parse().unwrap());

    let rule = forward.to_pf_rule().unwrap();
    assert!(rule.contains("on 192.168.1.100"));
}

#[test]
fn test_port_forward_invalid_protocol() {
    let forward = PortForward::new(8080, 80, "icmp", "10.0.1.10".parse().unwrap(), "webserver");
    assert!(forward.to_pf_rule().is_err());

    let injected = PortForward::new(
        8080,
        80,
        "tcp from any to any\npass all",
        "10.0.1.10".parse().unwrap(),
        "webserver",
    );
    assert!(injected.to_pf_rule().is_err());
}

#[test]
fn test_port_forward_udp_protocol() {
    let forward = PortForward::new(53, 53, "udp", "10.0.1.10".parse().unwrap(), "dns");
    let rule = forward.to_pf_rule().unwrap();
    assert!(rule.contains("proto udp"));
}

#[test]
fn test_port_forward_creation() {
    let forward = PortForward::new(3000, 3000, "tcp", "10.0.1.5".parse().unwrap(), "myjail");

    assert_eq!(forward.external_port, 3000);
    assert_eq!(forward.internal_port, 3000);
    assert_eq!(forward.jail_name, "myjail");
    assert_eq!(forward.protocol, "tcp");
}

#[test]
fn test_bulkhead_manager() {
    let manager = BulkheadManager::new();
    assert_eq!(manager.list_forwards().len(), 0);
}

#[test]
fn test_remove_jail_forwards_without_match_does_not_touch_pf() {
    let mut manager = BulkheadManager::new();
    assert!(manager.remove_jail_forwards("absent-web").is_ok());
}

#[test]
fn test_bulkhead_state_round_trip() {
    let root = temp_dir();
    std::fs::create_dir_all(&root).unwrap();

    let state_path = root.join("port-forwards.toml");
    write_forwards(
        &state_path,
        &[PortForward::new(
            8080,
            80,
            "tcp",
            "10.0.1.10".parse().unwrap(),
            "demo-web",
        )],
    )
    .unwrap();

    let manager = BulkheadManager::from_data_dir(&root).unwrap();
    assert_eq!(manager.list_forwards().len(), 1);
    assert_eq!(manager.list_forwards()[0].jail_name, "demo-web");
    assert_eq!(
        manager.list_forwards()[0].jail_ip,
        "10.0.1.10".parse::<IpAddr>().unwrap()
    );

    std::fs::remove_dir_all(root).unwrap();
}
