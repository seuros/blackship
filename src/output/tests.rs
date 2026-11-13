use super::*;
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};

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

/// A descriptor of our own to capture. fd 1 belongs to the test harness, which
/// writes results to it, and flushes its half-written lines, whenever a test
/// finishes, so a capture of fd 1 can swallow or be prefixed by foreign text.
struct Private(std::cell::RefCell<OwnedFd>);

impl Private {
    fn new() -> Self {
        Self(std::cell::RefCell::new(OwnedFd::from(
            tempfile::tempfile().unwrap(),
        )))
    }

    fn file(&self) -> std::fs::File {
        std::fs::File::from(self.0.borrow().try_clone().unwrap())
    }

    fn write(&self, bytes: &[u8]) {
        self.file().write_all(bytes).unwrap();
    }

    fn identity(&self) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        let meta = self.file().metadata().unwrap();
        (meta.dev(), meta.ino())
    }
}

impl Captured for Private {
    fn flush(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn save(&self) -> std::io::Result<OwnedFd> {
        self.0.borrow().try_clone()
    }

    fn point_at(&self, to: &impl AsFd) -> std::io::Result<()> {
        nix::unistd::dup2(to, &mut self.0.borrow_mut()).map_err(std::io::Error::from)
    }
}

#[test]
fn a_failed_operation_keeps_what_it_printed() {
    let target = Private::new();
    let before = target.identity();
    let error = capture_fd::<()>(&target, || {
        target.write(b"step one\nstep two\n");
        Err(Error::JailNotFound("web".into()))
    })
    .unwrap_err();

    assert_eq!(error.code(), "jail_not_found");
    assert_eq!(error.output(), ["step one", "step two"]);
    assert_eq!(target.identity(), before, "descriptor must be restored");

    let rendered = CliError::new(OutputFormat::Json, error).to_string();
    let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(value["error"]["code"], "jail_not_found");
    assert_eq!(
        value["error"]["output"],
        serde_json::json!(["step one", "step two"])
    );
}

#[test]
fn a_silent_failure_adds_no_output_field() {
    let target = Private::new();
    let error =
        capture_fd::<()>(&target, || Err(Error::JailNotFound("web".into()))).unwrap_err();
    let rendered = CliError::new(OutputFormat::Json, error).to_string();
    let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert!(value["error"].get("output").is_none());
}

#[test]
fn non_utf8_output_is_decoded_lossily() {
    let target = Private::new();
    let (value, messages) = capture_fd(&target, || {
        target.write(b"ok \xff\xfe done\n");
        Ok(7)
    })
    .unwrap();

    assert_eq!(value, 7);
    assert_eq!(messages, ["ok \u{fffd}\u{fffd} done"]);
}

#[test]
fn capturing_stdout_returns_the_operation_value() {
    let (value, _) = capture_stdout(|| Ok(7)).unwrap();

    assert_eq!(value, 7);
}
