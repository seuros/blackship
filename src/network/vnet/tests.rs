use super::*;

#[test]
fn test_vnet_config() {
    let config = VnetConfig::new(
        "blackship0".to_string(),
        "10.0.1.10/24".to_string(),
        "10.0.1.1".parse().unwrap(),
    );

    assert_eq!(config.bridge, "blackship0");
    assert_eq!(config.ip, "10.0.1.10/24");
    assert_eq!(config.backend, NetworkBackend::Epair);
}

#[test]
fn test_vnet_config_netgraph() {
    let config = VnetConfig::new(
        "ngbridge0".to_string(),
        "10.0.1.10/24".to_string(),
        "10.0.1.1".parse().unwrap(),
    )
    .with_backend(NetworkBackend::Netgraph);

    assert_eq!(config.backend, NetworkBackend::Netgraph);
}
