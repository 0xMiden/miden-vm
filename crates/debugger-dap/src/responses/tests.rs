use super::*;

#[test]
fn test_responsemessage_is_flattened() {
    let a = Response {
        request_seq: 1,
        success: false,
        message: Some(ResponseMessage::Error("test".to_string())),
        body: None,
        error: None,
    };
    let val = serde_json::to_value(a).unwrap();

    assert!(val.get("message").unwrap().is_string());
    assert!(val.get("message").unwrap().as_str().unwrap() == "test");
    assert!(!val.get("message").unwrap().is_object());

    let a = Response {
        request_seq: 1,
        success: false,
        message: Some(ResponseMessage::Cancelled),
        body: None,
        error: None,
    };
    let val = serde_json::to_value(a).unwrap();
    assert!(val.get("message").unwrap().is_string());
    assert!(val.get("message").unwrap().as_str().unwrap() == "cancelled");

    let a = Response {
        request_seq: 1,
        success: false,
        message: Some(ResponseMessage::NotStopped),
        body: None,
        error: None,
    };
    let val = serde_json::to_value(a).unwrap();
    assert!(val.get("message").unwrap().is_string());
    assert!(val.get("message").unwrap().as_str().unwrap() == "notStopped");
}
