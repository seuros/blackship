use super::*;

#[test]
fn context_defaults_to_the_jailfile_directory() {
    assert_eq!(
        context_of(Path::new("images/rust/Jailfile")),
        Path::new("images/rust")
    );
    assert_eq!(context_of(Path::new("Jailfile")), Path::new("."));
}

#[test]
fn build_collects_args_in_order() {
    let build = Build::jailfile("Jailfile")
        .name("kim-rust")
        .arg("A", "1")
        .arg("B", "2");
    assert_eq!(build.name.as_deref(), Some("kim-rust"));
    assert_eq!(
        build.args,
        [
            ("A".to_string(), "1".to_string()),
            ("B".to_string(), "2".to_string())
        ]
    );
}

#[test]
fn dry_run_touches_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let host = Host::new(&dir);
    let jailfile = parse_jailfile("FROM 16.0-CURRENT\nRUN echo hi\n").unwrap();
    let image = build_root(&host, &jailfile, &dir, "img", Vec::new(), BuildMode::DryRun).unwrap();
    assert_eq!(image.base.as_deref(), Some("16.0-CURRENT"));
    assert!(!image.root.exists());
}
