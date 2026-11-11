use serde_json::json;

use super::*;

#[test]
fn acknowledgements_preserve_request_sequence_and_command() {
    for (name, arguments) in [
        ("attach", json!({})),
        ("configurationDone", json!({})),
        ("disconnect", json!({})),
        ("goto", json!({"threadId": 1, "targetId": 2})),
        ("launch", json!({})),
        ("next", json!({"threadId": 1})),
        ("pause", json!({"threadId": 1})),
        ("restart", json!({})),
        ("restartFrame", json!({"frameId": 2})),
        ("reverseContinue", json!({"threadId": 1})),
        ("stepBack", json!({"threadId": 1})),
        ("stepIn", json!({"threadId": 1})),
        ("stepOut", json!({"threadId": 1})),
        ("terminate", json!({})),
        ("terminateThreads", json!({"threadIds": [1]})),
    ] {
        let request = if name == "configurationDone" {
            json!({"command": name})
        } else {
            json!({"command": name, "arguments": arguments})
        };
        let command = serde_json::from_value(request).unwrap();
        let response = Request { seq: 42, command }.ack().unwrap();
        assert!(response.success);
        assert_eq!(response.request_seq, 42);
        assert!(response.message.is_none());
        assert!(response.error.is_none());
        if name == "configurationDone" {
            assert!(matches!(response.body, Some(ResponseBody::ConfigurationDone)));
        }
        let wire = serde_json::to_value(response).unwrap();
        assert_eq!(wire["command"], name);
    }
    assert!(matches!(
        Request {
            seq: 1,
            command: Command::Threads
        }
        .ack(),
        Err(ServerError::ResponseConstructError)
    ));
}

#[test]
fn explicit_responses_distinguish_success_error_and_cancellation() {
    let request = Request {
        seq: 23,
        command: Command::Threads,
    };
    let success = request
        .clone()
        .success(ResponseBody::Threads(crate::responses::ThreadsResponse { threads: vec![] }));
    assert_eq!(success.request_seq, 23);
    assert!(success.success);
    assert!(matches!(success.body, Some(ResponseBody::Threads(_))));
    assert!(success.message.is_none());
    let error = request.clone().error("invalid frame");
    assert_eq!(error.request_seq, 23);
    assert!(!error.success);
    assert!(error.body.is_none());
    assert!(
        matches!(error.message, Some(ResponseMessage::Error(message)) if message == "invalid frame")
    );
    let cancelled = request.cancellation();
    assert_eq!(cancelled.request_seq, 23);
    assert!(!cancelled.success);
    assert!(cancelled.body.is_none());
    assert!(matches!(cancelled.message, Some(ResponseMessage::Cancelled)));
}
