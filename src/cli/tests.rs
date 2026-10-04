use super::*;

#[test]
fn test_network_create_requires_root() {
    let command = Commands::Network {
        action: NetworkAction::Create {
            name: "default".into(),
            subnet: "10.0.1.0/24".into(),
            gateway: None,
            bridge: "blackship0".into(),
            backend: "epair".into(),
        },
    };

    assert!(command.requires_root());
}

#[test]
fn test_network_list_does_not_require_root() {
    let command = Commands::Network {
        action: NetworkAction::List,
    };

    assert!(!command.requires_root());
}

#[test]
fn test_bootstrap_requires_root() {
    let command = Commands::Bootstrap {
        release: "15.0-RELEASE".into(),
        force: false,
        archives: None,
        pkgbase: false,
    };

    assert!(command.requires_root());
}

#[test]
fn test_up_dry_run_does_not_require_root() {
    let command = Commands::Up {
        jail: None,
        all: true,
        dry_run: true,
    };

    assert!(!command.requires_root());
}

#[test]
fn test_armada_up_dry_run_does_not_require_root() {
    let command = Commands::Armada {
        files: vec![PathBuf::from("blackship.toml")],
        action: ArmadaAction::Up {
            detach: false,
            jails: Vec::new(),
            build: false,
            no_build: false,
            dry_run: true,
        },
    };

    assert!(!command.requires_root());
}
