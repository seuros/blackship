use super::*;

#[test]
fn test_parse_line_from() {
    let result = parse_line("FROM 15.1-RELEASE").unwrap();
    assert!(matches!(result, Some(Instruction::From(r)) if r == "15.1-RELEASE"));
}

#[test]
fn test_parse_line_run() {
    let result = parse_line("RUN pkg install -y nginx").unwrap();
    assert!(matches!(result, Some(Instruction::Run(c)) if c == "pkg install -y nginx"));
}

#[test]
fn test_parse_line_copy() {
    let result = parse_line("COPY nginx.conf /usr/local/etc/nginx/").unwrap();
    if let Some(Instruction::Copy(spec)) = result {
        assert_eq!(spec.src, "nginx.conf");
        assert_eq!(spec.dest, "/usr/local/etc/nginx/");
    } else {
        panic!("Expected Copy instruction");
    }
}

#[test]
fn test_parse_line_arg() {
    let result = parse_line("ARG VERSION=1.25").unwrap();
    if let Some(Instruction::Arg(arg)) = result {
        assert_eq!(arg.name, "VERSION");
        assert_eq!(arg.default, Some("1.25".to_string()));
    } else {
        panic!("Expected Arg instruction");
    }
}

#[test]
fn test_parse_line_expose() {
    let result = parse_line("EXPOSE 80/tcp").unwrap();
    if let Some(Instruction::Expose(port)) = result {
        assert_eq!(port.port, 80);
        assert_eq!(port.protocol, "tcp");
    } else {
        panic!("Expected Expose instruction");
    }
}

#[test]
fn test_parse_full_jailfile() {
    let content = r#"
FROM 15.1-RELEASE
ARG NGINX_VERSION=1.25
RUN pkg install -y nginx
COPY nginx.conf /usr/local/etc/nginx/
EXPOSE 80/tcp
CMD /usr/sbin/service nginx start
"#;

    let jf = parse_line_format(content).unwrap();
    assert_eq!(jf.from, Some("15.1-RELEASE".to_string()));
    assert_eq!(jf.args.len(), 1);
    assert_eq!(jf.run_commands().len(), 1);
    assert_eq!(jf.expose.len(), 1);
    assert_eq!(jf.cmd, Some("/usr/sbin/service nginx start".to_string()));
}

#[test]
fn test_parse_toml_format() {
    let content = r#"
[metadata]
name = "nginx-jail"
version = "1.0"

[build]
from = "15.1-RELEASE"
workdir = "/usr/local"

[[build.args]]
name = "NGINX_VERSION"
default = "1.25"

[[build.run]]
command = "pkg install -y nginx"

[[build.copy]]
src = "nginx.conf"
dest = "/usr/local/etc/nginx/nginx.conf"

[[build.expose]]
port = 80
protocol = "tcp"

[start]
cmd = "/usr/sbin/service nginx start"
"#;

    let jf = parse_toml_format(content).unwrap();
    assert_eq!(jf.metadata.name, Some("nginx-jail".to_string()));
    assert_eq!(jf.from, Some("15.1-RELEASE".to_string()));
    assert_eq!(jf.args.len(), 1);
    assert_eq!(jf.workdir, Some("/usr/local".to_string()));
    assert_eq!(jf.cmd, Some("/usr/sbin/service nginx start".to_string()));
}

#[test]
fn test_parse_stop_nom_format() {
    let jf = parse_jailfile("FROM 15.1-RELEASE\nSTOP service nginx stop\n").unwrap();
    assert_eq!(jf.stop, Some("service nginx stop".to_string()));
    assert!(
        jf.instructions
            .iter()
            .any(|i| matches!(i, Instruction::Stop(c) if c == "service nginx stop"))
    );
}

#[test]
fn test_parse_stop_toml_format() {
    let jf = parse_jailfile(
        r#"
[jail]
from = "15.1-RELEASE"

[stop]
cmd = "service nginx stop"
"#,
    )
    .unwrap();
    assert_eq!(jf.stop, Some("service nginx stop".to_string()));
    assert!(
        jf.instructions
            .iter()
            .any(|i| matches!(i, Instruction::Stop(c) if c == "service nginx stop"))
    );
}

#[test]
fn test_diagnose_reports_every_bad_line() {
    let content = "FROM 15.1-RELEASE\nFROBNICATE everything\nRUN true\n    WIBBLE nothing\n";

    let diagnostics = diagnose(content, JailfileFormat::Line);

    assert_eq!(diagnostics.len(), 2);
    assert_eq!(diagnostics[0].line, 2);
    assert_eq!(diagnostics[0].column, 1);
    assert_eq!(diagnostics[1].line, 4);
    assert_eq!(diagnostics[1].column, 5);
}

#[test]
fn test_forced_line_format_tolerates_toml_lookalike_body() {
    let content = "FROM 15.1-RELEASE\nRUN printf '[build]\\n' > /tmp/fake.toml\n";

    let jf = parse_jailfile_as(content, JailfileFormat::Line).unwrap();

    assert_eq!(jf.from, Some("15.1-RELEASE".to_string()));
    assert_eq!(
        jf.run_commands(),
        vec!["printf '[build]\\n' > /tmp/fake.toml"]
    );
    assert!(parse_jailfile(content).is_err());
}

#[test]
fn test_jailfile_json_preserves_instruction_order() {
    let content = "FROM 15.1-RELEASE\nENV TZ=UTC\nRUN pkg install -y nginx\nEXPOSE 80/tcp\nCMD /usr/sbin/service nginx start\n";
    let jf = parse_jailfile_as(content, JailfileFormat::Line).unwrap();

    let value = serde_json::to_value(&jf).unwrap();
    let kinds: Vec<&str> = value["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i.as_object().unwrap().keys().next().unwrap().as_str())
        .collect();

    assert_eq!(kinds, vec!["From", "Env", "Run", "Expose", "Cmd"]);
}

#[test]
fn test_comment_lines_are_retained() {
    let jf = parse_jailfile("# build the web jail\nFROM 15.1-RELEASE\n").unwrap();
    assert!(
        jf.instructions
            .iter()
            .any(|i| matches!(i, Instruction::Comment(t) if t == "build the web jail"))
    );
}
