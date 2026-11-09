use super::*;

#[test]
fn report_is_manifestless_and_machine_serializable() {
    let report = data().unwrap();
    let value = serde_json::to_value(report).unwrap();

    assert_eq!(value["output_schema_version"], SCHEMA_VERSION);
    assert_eq!(value["platform"]["os"], "freebsd");
    assert!(value["facilities"].is_array());
    assert!(value["privilege_escalators"].is_array());
}
