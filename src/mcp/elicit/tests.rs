use super::*;

/// A unique scratch directory for one test.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("blackship-elicit-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// An answer carrying the given form fields.
fn answered(action: ElicitationAction, content: Value) -> CreateElicitationResult {
    CreateElicitationResult {
        action,
        content: Some(content),
    }
}

#[test]
fn accept_with_confirm_writes_a_new_file() {
    assert_eq!(
        verdict(
            &answered(ElicitationAction::Accept, json!({"confirm": true})),
            false
        ),
        Verdict::Write { replacing: false }
    );
}

#[test]
fn accept_without_confirm_is_not_an_approval() {
    let result = verdict(
        &answered(ElicitationAction::Accept, json!({"confirm": false})),
        false,
    );

    assert!(matches!(result, Verdict::Refuse(_)), "got {result:?}");
}

#[test]
fn accept_with_no_content_at_all_is_not_an_approval() {
    let bare = CreateElicitationResult {
        action: ElicitationAction::Accept,
        content: None,
    };

    assert!(matches!(verdict(&bare, false), Verdict::Refuse(_)));
}

#[test]
fn confirm_alone_does_not_clobber_an_existing_file() {
    let result = verdict(
        &answered(ElicitationAction::Accept, json!({"confirm": true})),
        true,
    );

    assert!(matches!(result, Verdict::Refuse(_)), "got {result:?}");
}

#[test]
fn confirm_plus_overwrite_replaces_an_existing_file() {
    assert_eq!(
        verdict(
            &answered(
                ElicitationAction::Accept,
                json!({"confirm": true, "overwrite": true})
            ),
            true
        ),
        Verdict::Write { replacing: true }
    );
}

#[test]
fn decline_and_cancel_both_refuse() {
    for action in [ElicitationAction::Decline, ElicitationAction::Cancel] {
        let result = verdict(
            &CreateElicitationResult {
                action,
                content: None,
            },
            false,
        );
        assert!(matches!(result, Verdict::Refuse(_)), "got {result:?}");
    }
}

#[test]
fn a_write_verdict_puts_the_content_on_disk() {
    let target = scratch("write").join("blackship.toml");
    let _ = std::fs::remove_file(&target);

    let report = apply(
        &target,
        "a manifest",
        "[config]\nproject = \"demo\"\n",
        Verdict::Write { replacing: false },
    )
    .expect("apply");

    assert_eq!(report["written"], true);
    assert_eq!(report["replaced"], false);
    assert_eq!(
        std::fs::read_to_string(&target).expect("read back"),
        "[config]\nproject = \"demo\"\n"
    );

    let _ = std::fs::remove_file(&target);
}

#[test]
fn a_refuse_verdict_leaves_no_file_behind() {
    let dir = scratch("refuse");
    let target = dir.join("blackship.toml");
    let _ = std::fs::remove_file(&target);

    let report = apply(
        &target,
        "a manifest",
        "[config]\nproject = \"demo\"\n",
        Verdict::Refuse("the operator declined".to_string()),
    )
    .expect("apply");

    assert_eq!(report["written"], false);
    assert_eq!(report["reason"], "the operator declined");
    assert!(!target.exists(), "{} was created anyway", target.display());
}

#[test]
fn a_file_that_appears_after_approval_is_still_not_clobbered() {
    let target = scratch("race").join("blackship.toml");
    std::fs::write(&target, "pre-existing\n").expect("seed target");

    let report = apply(
        &target,
        "a manifest",
        "overwritten\n",
        Verdict::Write { replacing: false },
    )
    .expect("apply");

    assert_eq!(report["written"], false);
    assert_eq!(
        std::fs::read_to_string(&target).expect("read back"),
        "pre-existing\n"
    );

    let _ = std::fs::remove_file(&target);
}

#[test]
fn the_operator_message_names_the_absolute_path_and_says_the_file_exists() {
    let target = scratch("message").join("blackship.toml");

    let fresh = message(&target, "a manifest", false);
    assert!(fresh.contains(&target.display().to_string()), "{fresh}");
    assert!(fresh.contains("No file exists there yet"), "{fresh}");

    let existing = message(&target, "a manifest", true);
    assert!(
        existing.contains("ALREADY EXISTS"),
        "an existing target must be called out: {existing}"
    );
}

#[test]
fn overwrite_is_only_offered_when_the_target_exists() {
    let fresh = schema("a manifest", false).expect("schema");
    assert!(!fresh.properties.contains_key("overwrite"));
    assert!(fresh.properties.contains_key("confirm"));

    let existing = schema("a manifest", true).expect("schema");
    assert!(existing.properties.contains_key("overwrite"));
}

#[test]
fn a_target_under_a_directory_that_does_not_exist_reports_that_directory() {
    let dir = scratch("absent-parent");
    let absent = dir.join("no-such-dir");
    let _ = std::fs::remove_dir_all(&absent);

    assert_eq!(
        missing_parent(&absent.join("blackship.toml")),
        Some(absent.clone())
    );
    assert_eq!(missing_parent(&dir.join("blackship.toml")), None);
}

#[test]
fn a_parent_that_is_a_regular_file_is_reported_as_unusable() {
    let dir = scratch("file-parent");
    let blocker = dir.join("not-a-dir");
    std::fs::write(&blocker, "i am a file\n").expect("seed blocker");

    assert_eq!(
        missing_parent(&blocker.join("blackship.toml")),
        Some(blocker.clone())
    );

    let reason = no_parent(&blocker);
    assert!(
        reason.contains(&blocker.display().to_string()),
        "the refusal must name the blocking path: {reason}"
    );
    assert!(
        reason.contains("is not a directory"),
        "the refusal must say the path is not a directory: {reason}"
    );
    assert!(
        !reason.contains("does not exist"),
        "a file the model can see must not be called absent: {reason}"
    );

    let _ = std::fs::remove_file(&blocker);
}

#[test]
fn refusing_a_missing_parent_leaves_nothing_at_all_on_disk() {
    let dir = scratch("absent-parent-clean");
    let absent = dir.join("still-no-such-dir");
    let _ = std::fs::remove_dir_all(&absent);
    let target = absent.join("blackship.toml");

    let parent = missing_parent(&target).expect("parent must be reported missing");
    let report = refused(&target, &no_parent(&parent));
    let reason = report["reason"].as_str().expect("reason is a string");

    assert_eq!(report["written"], false);
    assert!(
        reason.contains(&absent.display().to_string()),
        "the refusal must name the absolute missing directory: {reason}"
    );
    assert!(
        reason.contains("Create that directory first"),
        "the refusal must tell the model what to do: {reason}"
    );
    assert!(!absent.exists(), "{} was created", absent.display());
    assert!(!target.exists(), "{} was created", target.display());
    assert_eq!(
        std::fs::read_dir(&dir).expect("read scratch dir").count(),
        0,
        "a stray temp file was left in {}",
        dir.display()
    );
}

#[test]
fn a_relative_path_is_resolved_before_the_operator_sees_it() {
    let resolved = absolute(Path::new("blackship.toml"));

    assert!(resolved.is_absolute(), "{}", resolved.display());
    assert!(resolved.ends_with("blackship.toml"));
}
