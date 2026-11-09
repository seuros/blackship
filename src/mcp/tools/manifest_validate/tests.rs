use super::*;


/// A scratch directory, removed when the guard drops.
fn scratch(tag: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("blackship-manifest-validate-{tag}-"))
        .tempdir()
        .expect("scratch dir")
}

fn validate_content(tag: &str, content: &str) -> Value {
    let tmp = scratch(tag);
    let path = tmp.path().to_path_buf().join("blackship.toml");
    std::fs::write(&path, content).expect("write manifest");
    let result = validate_stages(&path);
    let _ = std::fs::remove_file(&path);
    result
}

#[test]
fn unreadable_path_fails_at_the_read_stage() {
    let tmp = scratch("missing");
    let path = tmp.path().to_path_buf().join("absent.toml");
    let _ = std::fs::remove_file(&path);

    let result = validate_stages(&path);

    assert_eq!(result["valid"], false);
    assert_eq!(result["failed_stage"], "read");
    assert_eq!(result["diagnostics"][0]["line"], Value::Null);
}

#[test]
fn malformed_toml_fails_at_the_parse_stage_with_a_position() {
    let result = validate_content("malformed", "[config]\nproject = \n");

    assert_eq!(result["valid"], false);
    assert_eq!(result["failed_stage"], "parse");
    assert_eq!(result["diagnostics"][0]["line"], 2);
    assert!(result["diagnostics"][0]["column"].is_number());
}

#[test]
fn duplicate_jails_parse_but_fail_at_the_validate_stage() {
    let result = validate_content(
        "duplicate",
        "[config]\nproject = \"demo\"\n\n\
         [[jails]]\nname = \"web\"\nrelease = \"15.1-RELEASE\"\n\n\
         [[jails]]\nname = \"web\"\nrelease = \"15.1-RELEASE\"\n",
    );

    assert_eq!(result["valid"], false);
    assert_eq!(result["failed_stage"], "validate");
    assert!(
        result["diagnostics"][0]["message"]
            .as_str()
            .is_some_and(|m| m.contains("Duplicate jail name")),
        "expected the semantic duplicate-name error, got {:?}",
        result["diagnostics"][0]["message"]
    );
}

#[test]
fn a_good_manifest_passes_every_stage() {
    let result = validate_content(
        "good",
        "[config]\nproject = \"demo\"\n\n\
         [[jails]]\nname = \"web\"\nrelease = \"15.1-RELEASE\"\n",
    );

    assert_eq!(result["valid"], true, "unexpected failure: {result}");
    assert_eq!(result["failed_stage"], Value::Null);
    assert_eq!(result["jails"][0], "web");
}
