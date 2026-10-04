use super::*;

#[test]
fn test_parse_line_from() {
    let result = parse_line("FROM 14.2-RELEASE").unwrap();
    assert!(matches!(result, Some(Instruction::From(r)) if r == "14.2-RELEASE"));
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
FROM 14.2-RELEASE
ARG NGINX_VERSION=1.25
RUN pkg install -y nginx
COPY nginx.conf /usr/local/etc/nginx/
EXPOSE 80/tcp
CMD /usr/sbin/service nginx start
"#;

    let jf = parse_line_format(content).unwrap();
    assert_eq!(jf.from, Some("14.2-RELEASE".to_string()));
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
from = "14.2-RELEASE"
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
    assert_eq!(jf.from, Some("14.2-RELEASE".to_string()));
    assert_eq!(jf.args.len(), 1);
    assert_eq!(jf.workdir, Some("/usr/local".to_string()));
    assert_eq!(jf.cmd, Some("/usr/sbin/service nginx start".to_string()));
}

#[test]
fn test_parse_stop_nom_format() {
    let jf = parse_jailfile("FROM 14.2-RELEASE\nSTOP service nginx stop\n").unwrap();
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
from = "14.2-RELEASE"

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
fn test_comment_lines_are_retained() {
    let jf = parse_jailfile("# build the web jail\nFROM 14.2-RELEASE\n").unwrap();
    assert!(
        jf.instructions
            .iter()
            .any(|i| matches!(i, Instruction::Comment(t) if t == "build the web jail"))
    );
}
