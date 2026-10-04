use super::*;

#[test]
fn test_metadata_serialization() {
    let metadata = ExportMetadata {
        name: "test".to_string(),
        version: "0.1.0".to_string(),
        timestamp: "12345".to_string(),
        original_path: "/jails/test".to_string(),
        ip: Some("10.0.1.10".to_string()),
        hostname: Some("test.local".to_string()),
    };

    let json = serde_json::to_string(&metadata).unwrap();
    assert!(json.contains("test"));
    assert!(json.contains("10.0.1.10"));

    let parsed: ExportMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.name, "test");
}
