use super::*;
use std::io::Write;

#[test]
fn success_envelope_is_versioned() {
    let envelope = SuccessEnvelope {
        schema_version: SCHEMA_VERSION,
        ok: true,
        data: &vec!["jail-a"],
    };
    let value = serde_json::to_value(envelope).unwrap();

    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"][0], "jail-a");
}

#[test]
fn errors_have_stable_codes() {
    let error = CliError::new(OutputFormat::Json, Error::JailNotFound("web".into()));
    let value: serde_json::Value = serde_json::from_str(&error.to_string()).unwrap();

    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "jail_not_found");
    assert_eq!(value["error"]["message"], "Jail 'web' not found");
}

/// fd 1 is process-wide, so tests that capture it run one at a time.
static STDOUT: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    STDOUT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_stdout(bytes: &[u8]) {
    let mut out = std::io::stdout();
    out.write_all(bytes).unwrap();
    out.flush().unwrap();
}

fn stdout_identity() -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata("/dev/stdout").unwrap();
    (meta.dev(), meta.ino())
}

#[test]
fn a_failed_operation_keeps_what_it_printed() {
    let _guard = serial();
    let before = stdout_identity();
    let error = capture_stdout::<()>(|| {
        write_stdout(b"step one\nstep two\n");
        Err(Error::JailNotFound("web".into()))
    })
    .unwrap_err();

    assert_eq!(error.code(), "jail_not_found");
    assert_eq!(error.output(), ["step one", "step two"]);
    assert_eq!(stdout_identity(), before, "stdout must be restored");

    let rendered = CliError::new(OutputFormat::Json, error).to_string();
    let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(value["error"]["code"], "jail_not_found");
    assert_eq!(value["error"]["output"][1], "step two");
}

#[test]
fn a_silent_failure_adds_no_output_field() {
    let _guard = serial();
    let error = capture_stdout::<()>(|| Err(Error::JailNotFound("web".into()))).unwrap_err();
    let rendered = CliError::new(OutputFormat::Json, error).to_string();
    let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert!(value["error"].get("output").is_none());
}

#[test]
fn non_utf8_output_is_decoded_lossily() {
    let _guard = serial();
    let (value, messages) = capture_stdout(|| {
        write_stdout(b"ok \xff\xfe done\n");
        Ok(7)
    })
    .unwrap();

    assert_eq!(value, 7);
    assert_eq!(messages, ["ok \u{fffd}\u{fffd} done"]);
}
