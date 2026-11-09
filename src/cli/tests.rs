use super::*;
use std::ffi::OsStr;

#[test]
fn test_json_output_format_parses_globally() {
    let argv = [OsStr::new("--format"), OsStr::new("json"), OsStr::new("ps")];
    let cli = Cli::parse_from(&argv).unwrap();

    assert_eq!(cli.format, OutputFormat::Json);
    let Commands::Ps { json } = cli.command else {
        panic!("expected ps");
    };
    assert!(!json);
}

#[test]
fn test_text_output_format_is_default() {
    let argv = [OsStr::new("check")];
    let cli = Cli::parse_from(&argv).unwrap();

    assert_eq!(cli.format, OutputFormat::Text);
}

#[test]
fn test_machine_output_support_is_explicit() {
    assert!(Commands::Check.supports_machine_output());
    assert!(
        Commands::Network {
            action: NetworkAction::List
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
