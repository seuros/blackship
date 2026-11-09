use super::*;
use std::fs;

fn scratch(tag: &str) -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix(&format!("blackship-copy-{tag}-"))
        .tempdir()
        .expect("scratch dir");
    fs::create_dir_all(dir.path().join("root/etc")).unwrap();
    fs::create_dir_all(dir.path().join("host")).unwrap();
    dir
}

fn jail(dir: &Path, path: &str) -> Side<'static> {
    Side::Jail(JailSide {
        jid: None,
        root: dir.join("root"),
        path: path.to_string(),
    })
}

#[test]
fn copies_in_and_out_of_a_root() {
    let tmp = scratch("roundtrip");
    let dir = tmp.path().to_path_buf();
    let src = dir.join("host/motd");
    fs::write(&src, "ahoy\n").unwrap();
    transfer(&Side::Host(&src), &jail(&dir, "/etc/motd"), true).unwrap();
    assert_eq!(
        fs::read_to_string(dir.join("root/etc/motd")).unwrap(),
        "ahoy\n"
    );

    let back = dir.join("host/back");
    transfer(&jail(&dir, "/etc/motd"), &Side::Host(&back), true).unwrap();
    assert_eq!(fs::read_to_string(&back).unwrap(), "ahoy\n");
}

#[test]
fn refuses_a_source_symlink_out_of_the_root() {
    let tmp = scratch("escape-src");
    let dir = tmp.path().to_path_buf();
    fs::write(dir.join("host/secret"), "no").unwrap();
    std::os::unix::fs::symlink(dir.join("host/secret"), dir.join("root/etc/leak")).unwrap();
    let out = dir.join("host/out");
    match transfer(&jail(&dir, "/etc/leak"), &Side::Host(&out), false) {
        Err(Error::InvalidArgument(_)) => {}
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}

#[test]
fn refuses_a_destination_symlink() {
    let tmp = scratch("escape-dst");
    let dir = tmp.path().to_path_buf();
    std::os::unix::fs::symlink(dir.join("host"), dir.join("root/etc/trap")).unwrap();
    let src = dir.join("host/file");
    fs::write(&src, "x").unwrap();
    match transfer(&Side::Host(&src), &jail(&dir, "/etc/trap"), false) {
        Err(Error::InvalidArgument(_)) => {}
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}

#[test]
fn refuses_jail_to_jail() {
    let tmp = scratch("j2j");
    let dir = tmp.path().to_path_buf();
    match transfer(&jail(&dir, "/etc"), &jail(&dir, "/tmp"), false) {
        Err(Error::InvalidArgument(_)) => {}
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}
