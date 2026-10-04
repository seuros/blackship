use super::*;

#[test]
fn test_build_context_creation() {
    let ctx = BuildContext::new(
        Path::new("/build/context"),
        Path::new("/jails/test"),
        "test",
    );

    assert_eq!(ctx.context_dir(), Path::new("/build/context"));
    assert_eq!(ctx.target_path(), Path::new("/jails/test"));
    assert_eq!(ctx.jail_name(), "test");
}

#[test]
fn test_variable_substitution() {
    let mut ctx = BuildContext::new(Path::new("/build"), Path::new("/jails/myapp"), "myapp");
    ctx.set_arg("VERSION", "1.0");
    ctx.set_env("PREFIX", "/usr/local");

    assert_eq!(ctx.substitute("version=${VERSION}"), "version=1.0");
    assert_eq!(ctx.substitute("prefix=$PREFIX"), "prefix=/usr/local");
    assert_eq!(ctx.substitute("jail=${JAIL_NAME}"), "jail=myapp");
}

#[test]
fn test_path_resolution() {
    let ctx = BuildContext::new(
        Path::new("/build/context"),
        Path::new("/jails/test"),
        "test",
    );

    assert_eq!(
        ctx.resolve_source("nginx.conf").unwrap(),
        PathBuf::from("/build/context/nginx.conf")
    );

    assert_eq!(
        ctx.resolve_dest("/etc/nginx/nginx.conf").unwrap(),
        PathBuf::from("/jails/test/etc/nginx/nginx.conf")
    );
}

#[test]
fn test_resolve_source_rejects_absolute_path() {
    let ctx = BuildContext::new(
        Path::new("/build/context"),
        Path::new("/jails/test"),
        "test",
    );

    let result = ctx.resolve_source("/etc/passwd");
    assert!(result.is_err());
}

#[test]
fn test_resolve_source_rejects_parent_dir() {
    let ctx = BuildContext::new(
        Path::new("/build/context"),
        Path::new("/jails/test"),
        "test",
    );

    let result = ctx.resolve_source("../../../etc/passwd");
    assert!(result.is_err());
}

#[test]
fn test_workdir() {
    let mut ctx = BuildContext::new(Path::new("/build"), Path::new("/jails/test"), "test");

    assert_eq!(ctx.workdir(), Path::new("/"));

    ctx.set_workdir("/usr/local");
    assert_eq!(ctx.workdir(), Path::new("/usr/local"));

    // Relative dest should use workdir
    assert_eq!(
        ctx.resolve_dest("bin/app").unwrap(),
        PathBuf::from("/jails/test/usr/local/bin/app")
    );
}
