use super::*;
use std::ffi::OsStr;

#[test]
fn test_json_output_format_parses_globally() {
    let argv = [OsStr::new("--format"), OsStr::new("json"), OsStr::new("ps")];
    let cli = Cli::parse_from(&argv).unwrap();

    assert_eq!(cli.format, OutputFormat::Json);
    let Commands::Ps { host, json } = cli.command else {
        panic!("expected ps");
    };
    assert!(!host);
    assert!(!json);
}

#[test]
fn test_ps_host_parses() {
    let argv = [OsStr::new("ps"), OsStr::new("--host")];
    let cli = Cli::parse_from(&argv).unwrap();

    let Commands::Ps { host, json } = cli.command else {
        panic!("expected ps");
    };
    assert!(host);
    assert!(!json);
}

#[test]
fn test_text_output_format_is_default() {
    let argv = [OsStr::new("check")];
    let cli = Cli::parse_from(&argv).unwrap();

    assert_eq!(cli.format, OutputFormat::Text);
}

#[test]
fn test_escalation_controls_parse_globally() {
    let argv = [
        OsStr::new("--no-escalate"),
        OsStr::new("--non-interactive"),
        OsStr::new("up"),
        OsStr::new("--all"),
    ];
    let cli = Cli::parse_from(&argv).unwrap();

    assert!(cli.no_escalate);
    assert!(cli.non_interactive);
}

#[test]
fn test_machine_output_support_is_explicit() {
    assert!(Commands::Check.supports_machine_output());
    assert!(Commands::Host.supports_machine_output());
    assert!(Commands::Capabilities.supports_machine_output());
    assert!(
        Commands::Network {
            action: NetworkAction::List
        }
        .supports_machine_output()
    );
    assert!(
        Commands::Up {
            jail: None,
            all: true,
            dry_run: true,
        }
        .supports_machine_output()
    );
    assert!(
        Commands::Releases {
            action: Some(ReleasesAction::List),
            json: false,
        }
        .supports_machine_output()
    );
    assert!(
        Commands::Stats {
            jail: None,
            json: false,
        }
        .supports_machine_output()
    );
    assert!(
        Commands::Audit {
            jail: "web".into(),
            json: false,
        }
        .supports_machine_output()
    );
    assert!(
        Commands::Snapshot {
            action: SnapshotAction::List {
                jail: "web".into(),
                json: false,
            },
        }
        .supports_machine_output()
    );
    assert!(
        Commands::Armada {
            files: vec!["blackship.toml".into()],
            action: ArmadaAction::Ps { json: false },
        }
        .supports_machine_output()
    );
    assert!(
        Commands::Health {
            jail: None,
            watch: false,
            interval: 5,
            json: false,
        }
        .supports_machine_output()
    );
    assert!(
        !Commands::Health {
            jail: None,
            watch: true,
            interval: 5,
            json: false,
        }
        .supports_machine_output()
    );
    assert!(
        !Commands::Releases {
            action: Some(ReleasesAction::Delete {
                release: "15.1-RELEASE".into(),
            }),
            json: false,
        }
        .supports_machine_output()
    );
    assert!(
        !Commands::Snapshot {
            action: SnapshotAction::Delete {
                jail: "web".into(),
                snapshot: "before-upgrade".into(),
            },
        }
        .supports_machine_output()
    );
    assert!(
        !Commands::Up {
            jail: None,
            all: true,
            dry_run: false,
        }
        .supports_machine_output()
    );
}

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
fn test_host_does_not_require_root() {
    assert!(!Commands::Host.requires_root());
}

#[test]
fn test_bootstrap_requires_root() {
    let command = Commands::Bootstrap {
        release: "15.1-RELEASE".into(),
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
