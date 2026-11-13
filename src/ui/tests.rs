use super::*;

#[test]
fn listen_accepts_loopback_only() {
    assert!(listen_addr("127.0.0.1:7341").is_ok());
    assert!(listen_addr("[::1]:7341").is_ok());
    assert!(listen_addr("0.0.0.0:7341").is_err());
    assert!(listen_addr("192.168.3.73:7341").is_err());
    assert!(listen_addr("127.0.0.1").is_err());
}

#[test]
fn fragment_carries_version_and_counts_under_the_patched_id() {
    let html = fleet_fragment("1.2.3", 2, 5);

    assert!(html.starts_with(r#"<p id="fleet">"#));
    assert!(html.contains("blackship 1.2.3: 2 of 5 jails running"));
}

#[test]
fn no_manifest_means_no_jails() {
    let ui = Ui::new(None, Shutdown::no_signal().guard_weak());

    assert_eq!(ui.names.len(), 0);
    assert_eq!(ui.running(), 0);
}
