use super::*;

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
