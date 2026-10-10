use super::*;

use crate::blueprint::parser::resolve_format;

/// Params with just a base release and one build step.
fn minimal() -> JailfileCreateParams {
    JailfileCreateParams {
        path: "Jailfile".to_string(),
        metadata: None,
        build: Some(BuildParams {
            from: Some("15.1-RELEASE".to_string()),
            workdir: None,
            args: Vec::new(),
            env: std::collections::BTreeMap::new(),
            run: vec!["pkg install -y nginx".to_string()],
            copy: Vec::new(),
            expose: Vec::new(),
        }),
        start: None,
        stop: None,
    }
}

#[test]
fn a_rendered_jailfile_parses_through_the_toml_parser() {
    let rendered = render(&minimal()).expect("render");

    let jailfile = parse_jailfile_as(&rendered, JailfileFormat::Toml).expect("parse");

    assert_eq!(jailfile.from.as_deref(), Some("15.1-RELEASE"));
    assert!(
        jailfile
            .instructions
            .iter()
            .any(|instruction| format!("{instruction:?}").contains("pkg install -y nginx")),
        "the RUN step did not survive: {:?}",
        jailfile.instructions
    );
}

#[test]
fn the_rendered_text_also_sniffs_as_toml_for_the_build_command() {
    let rendered = render(&minimal()).expect("render");

    assert_eq!(
        resolve_format(&rendered, JailfileFormat::Auto),
        JailfileFormat::Toml,
        "a written Jailfile is re-read with auto detection: {rendered}"
    );
}

#[test]
fn metadata_survives_the_round_trip() {
    let mut params = minimal();
    params.metadata = Some(MetadataParams {
        name: Some("nginx".to_string()),
        version: Some("1.0.0".to_string()),
        description: Some("a web jail".to_string()),
        author: None,
        labels: std::collections::BTreeMap::from([("tier".to_string(), "edge".to_string())]),
    });

    let rendered = render(&params).expect("render");
    let jailfile = parse_jailfile_as(&rendered, JailfileFormat::Toml).expect("parse");

    assert_eq!(jailfile.metadata.name.as_deref(), Some("nginx"));
    assert_eq!(jailfile.metadata.version.as_deref(), Some("1.0.0"));
    assert_eq!(jailfile.metadata.labels["tier"], "edge");
    assert_eq!(jailfile.metadata.author, None);
}

#[test]
fn start_stop_env_args_expose_and_copy_all_reach_the_parsed_jailfile() {
    let mut params = minimal();
    params.build = Some(BuildParams {
        from: Some("15.1-RELEASE".to_string()),
        workdir: Some("/srv".to_string()),
        args: vec![ArgParams {
            name: "VERSION".to_string(),
            default: Some("1.0".to_string()),
        }],
        env: std::collections::BTreeMap::from([("TZ".to_string(), "UTC".to_string())]),
        run: vec!["pkg install -y nginx".to_string()],
        copy: vec![CopyParams {
            src: "nginx.conf".to_string(),
            dest: "/usr/local/etc/nginx/nginx.conf".to_string(),
            mode: Some(420),
            owner: Some("root".to_string()),
        }],
        expose: vec![ExposeParams {
            port: 8080,
            protocol: Some("udp".to_string()),
        }],
    });
    params.start = Some(StartParams {
        cmd: Some("nginx -g 'daemon off;'".to_string()),
        entrypoint: None,
        user: Some("www".to_string()),
    });
    params.stop = Some("service nginx stop".to_string());

    let rendered = render(&params).expect("render");
    let jailfile = parse_jailfile_as(&rendered, JailfileFormat::Toml).expect("parse");

    assert_eq!(jailfile.workdir.as_deref(), Some("/srv"));
    assert_eq!(jailfile.args[0].name, "VERSION");
    assert_eq!(jailfile.args[0].default.as_deref(), Some("1.0"));
    assert_eq!(jailfile.env["TZ"], "UTC");
    assert_eq!(jailfile.expose[0].port, 8080);
    assert_eq!(jailfile.expose[0].protocol, "udp");
    assert_eq!(jailfile.cmd.as_deref(), Some("nginx -g 'daemon off;'"));
    assert_eq!(jailfile.user.as_deref(), Some("www"));
    assert_eq!(jailfile.stop.as_deref(), Some("service nginx stop"));
}

#[test]
fn an_omitted_protocol_defaults_to_tcp_in_the_parser() {
    let mut params = minimal();
    params.build.as_mut().expect("build").expose = vec![ExposeParams {
        port: 80,
        protocol: None,
    }];

    let rendered = render(&params).expect("render");
    let jailfile = parse_jailfile_as(&rendered, JailfileFormat::Toml).expect("parse");

    assert_eq!(jailfile.expose[0].protocol, "tcp");
}

#[test]
fn an_entirely_empty_request_still_renders_parseable_toml() {
    let params = JailfileCreateParams {
        path: "Jailfile".to_string(),
        metadata: None,
        build: None,
        start: None,
        stop: None,
    };

    let rendered = render(&params).expect("render");

    parse_jailfile_as(&rendered, JailfileFormat::Toml).expect("parse");
    assert_eq!(
        resolve_format(&rendered, JailfileFormat::Auto),
        JailfileFormat::Toml,
        "{rendered}"
    );
}

#[test]
fn a_run_command_containing_a_quote_does_not_break_the_document() {
    let mut params = minimal();
    params.build.as_mut().expect("build").run =
        vec!["echo \"hello\" > /tmp/a".to_string()];

    let rendered = render(&params).expect("render");
    let jailfile = parse_jailfile_as(&rendered, JailfileFormat::Toml).expect("parse");

    assert!(
        jailfile
            .instructions
            .iter()
            .any(|instruction| format!("{instruction:?}").contains("echo \\\"hello\\\"")),
        "{:?}",
        jailfile.instructions
    );
}
