use super::*;

#[test]
fn test_build_arg() {
    let arg = BuildArg::new("VERSION").with_default("1.0");
    assert_eq!(arg.name, "VERSION");
    assert_eq!(arg.default, Some("1.0".to_string()));
}

#[test]
fn test_expose_port_parse() {
    let tcp = ExposePort::parse("80/tcp").unwrap();
    assert_eq!(tcp.port, 80);
    assert_eq!(tcp.protocol, "tcp");

    let udp = ExposePort::parse("53/udp").unwrap();
    assert_eq!(udp.port, 53);
    assert_eq!(udp.protocol, "udp");

    let default = ExposePort::parse("443").unwrap();
    assert_eq!(default.port, 443);
    assert_eq!(default.protocol, "tcp");
}

#[test]
fn test_jailfile_builder() {
    let jf = Jailfile::from_release("15.1-RELEASE")
        .arg("VERSION", Some("1.0"))
        .env("PATH", "/usr/local/bin:/usr/bin")
        .run("pkg install -y nginx")
        .copy("nginx.conf", "/usr/local/etc/nginx/nginx.conf")
        .workdir("/usr/local")
        .expose(80, "tcp")
        .cmd("/usr/sbin/service nginx start");

    assert_eq!(jf.from, Some("15.1-RELEASE".to_string()));
    assert_eq!(jf.args.len(), 1);
    assert_eq!(jf.run_commands().len(), 1);
    assert_eq!(jf.copy_specs().len(), 1);
    assert_eq!(jf.expose.len(), 1);
}

#[test]
fn test_instruction_names() {
    assert_eq!(Instruction::From("test".to_string()).name(), "FROM");
    assert_eq!(Instruction::Run("test".to_string()).name(), "RUN");
    assert_eq!(Instruction::Copy(CopySpec::new("a", "b")).name(), "COPY");
}
