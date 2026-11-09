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

/// A jail root on disk with the symlinks a real userland carries.
fn jail_root_with_links() -> (tempfile::TempDir, BuildContext) {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("jail");
    std::fs::create_dir_all(root.join("usr/local/www/nginx-dist")).unwrap();
    std::fs::create_dir_all(root.join("usr/share")).unwrap();
    // As the nginx package installs it: absolute, meant for the jail's view.
    symlink(
        "/usr/local/www/nginx-dist",
        root.join("usr/local/www/nginx"),
    )
    .unwrap();
    symlink("../share", root.join("usr/local/share")).unwrap();
    symlink("/../../../../etc", root.join("escape")).unwrap();
    symlink("loop-b", root.join("loop-a")).unwrap();
    symlink("loop-a", root.join("loop-b")).unwrap();

    let ctx = BuildContext::new(tmp.path(), &root, "test");
    (tmp, ctx)
}

#[test]
fn test_resolve_dest_follows_absolute_links_inside_the_jail() {
    let (tmp, ctx) = jail_root_with_links();
    assert_eq!(
        ctx.resolve_dest("/usr/local/www/nginx/index.html").unwrap(),
        tmp.path().join("jail/usr/local/www/nginx-dist/index.html")
    );
}

#[test]
fn test_resolve_dest_follows_relative_links() {
    let (tmp, ctx) = jail_root_with_links();
    assert_eq!(
        ctx.resolve_dest("/usr/local/share/doc/x").unwrap(),
        tmp.path().join("jail/usr/share/doc/x")
    );
}

#[test]
fn test_resolve_dest_clamps_links_at_the_jail_root() {
    let (tmp, ctx) = jail_root_with_links();
    assert_eq!(
        ctx.resolve_dest("/escape/passwd").unwrap(),
        tmp.path().join("jail/etc/passwd")
    );
}

#[test]
fn test_resolve_dest_rejects_symlink_loops() {
    let (_tmp, ctx) = jail_root_with_links();
    assert!(ctx.resolve_dest("/loop-a/file").is_err());
}
