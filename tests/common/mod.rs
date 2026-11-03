use serde_json::Value;

/// Restore retains the original transaction/receipt identity but rotates signed
/// session generation. Compare every remaining byte after checking that change.
pub fn assert_restored_image(actual: Value, mut expected: Value) {
    fn decode(row: &Value) -> Value {
        let text = row["value"].as_str().unwrap();
        let bytes: Vec<_> = (0..text.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&text[offset..offset + 2], 16).unwrap())
            .collect();
        serde_json::from_slice(&bytes).unwrap()
    }
    let actual_header = decode(&actual["tables"]["local_runtime"][0]);
    let mut expected_header = decode(&expected["tables"]["local_runtime"][0]);
    assert_ne!(
        actual_header["session_generation"],
        expected_header["session_generation"]
    );
    assert!(
        uuid::Uuid::parse_str(actual_header["session_generation"].as_str().unwrap())
            .is_ok_and(|id| !id.is_nil())
    );
    expected_header["session_generation"] = actual_header["session_generation"].clone();
    assert_eq!(
        actual_header, expected_header,
        "restore may change only session generation in its runtime header"
    );
    expected["tables"]["local_runtime"][0]["value"] =
        actual["tables"]["local_runtime"][0]["value"].clone();
    assert_eq!(actual, expected);
}
