use std::{
    net::{Shutdown, TcpListener},
    time::Duration,
};

use serde_json::{Value, json};

use super::*;

struct Connection {
    client: DapClient,
    peer: TcpStream,
    peer_reader: BufReader<TcpStream>,
}

impl Connection {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = DapClient::connect(&listener.local_addr().unwrap().to_string()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        client.reader.get_ref().set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let peer_reader = BufReader::new(peer.try_clone().unwrap());
        Self {
            client,
            peer,
            peer_reader,
        }
    }

    fn send(&mut self, messages: &[Value]) {
        for message in messages {
            let payload = message.to_string();
            write!(self.peer, "Content-Length: {}\r\n\r\n{payload}\r\n", payload.len()).unwrap();
        }
    }

    fn request(&mut self) -> Value {
        let reader = &mut self.peer_reader;
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        let length: usize =
            header.trim().strip_prefix("Content-Length:").unwrap().trim().parse().unwrap();
        header.clear();
        reader.read_line(&mut header).unwrap();
        assert_eq!(header, "\r\n");
        let mut payload = vec![0; length];
        reader.read_exact(&mut payload).unwrap();
        serde_json::from_slice(&payload).unwrap()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.client.writer.get_ref().shutdown(Shutdown::Both);
    }
}

fn response(command: &str, body: Value) -> Value {
    json!({"type": "response", "seq": 1, "request_seq": 1, "success": true, "command": command, "body": body, "error": null})
}

fn stopped(cycle: usize) -> [Value; 2] {
    [
        json!({"type": "event", "event": "miden/uiState", "body": {"cycle": cycle, "current_stack": [7], "callstack": []}}),
        json!({"type": "event", "event": "stopped", "body": {"reason": "step", "threadId": 1}}),
    ]
}

#[test]
fn configured_stream_times_out_when_peer_does_not_answer_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_peer, _) = listener.accept().unwrap();
    stream.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut client = DapClient::from_stream(stream).unwrap();
    assert!(client.handshake().unwrap_err().contains("read error"));
}

#[test]
fn handshake_preserves_state_events_received_before_responses() {
    let mut connection = Connection::new();
    let [state, event] = stopped(3);
    connection.send(&[
        response("initialize", json!({})),
        response("launch", json!(null)),
        state,
        response("configurationDone", json!(null)),
        event,
    ]);
    let snapshot = connection.client.handshake().unwrap();
    assert_eq!(snapshot.cycle, 3);
    assert_eq!(snapshot.current_stack, [7]);
    assert!(connection.client.pending_events.is_empty());
    assert_eq!(connection.client.seq, 3);
    assert_eq!(connection.request()["command"], "initialize");
}

#[test]
fn stepping_and_restarting_send_expected_commands_and_decode_stop_reasons() {
    for (command, operation) in [
        (
            "stepIn",
            DapClient::step_in as fn(&mut DapClient) -> Result<DapStopReason, String>,
        ),
        ("next", DapClient::step_over),
        ("stepOut", DapClient::step_out),
        ("continue", DapClient::continue_),
        ("restart", DapClient::restart),
    ] {
        let mut connection = Connection::new();
        let [state, event] = stopped(7);
        connection.send(&[response(command, json!(null)), state, event]);
        assert!(
            matches!(operation(&mut connection.client).unwrap(), DapStopReason::Stopped(snapshot) if snapshot.cycle == 7)
        );
        let request = connection.request();
        assert_eq!(request["command"], command);
        assert_eq!(request["seq"], 1);
        if command != "restart" {
            assert_eq!(request["arguments"]["threadId"], 1);
        }
    }
    let mut connection = Connection::new();
    connection.send(&[
        response("restart", json!(null)),
        json!({"type": "event", "event": "terminated", "body": {"restart": true}}),
    ]);
    assert!(matches!(connection.client.restart_phase2().unwrap(), DapStopReason::Restarting));
    assert!(connection.request()["arguments"]["arguments"].is_object());
    connection
        .send(&[response("continue", json!({})), json!({"type": "event", "event": "terminated"})]);
    assert!(matches!(connection.client.continue_().unwrap(), DapStopReason::Terminated));
    assert_eq!(connection.request()["seq"], 2);
}

#[test]
fn queries_and_breakpoints_round_trip_remote_payloads() {
    let mut connection = Connection::new();
    connection.send(&[response("stackTrace", json!({"stackFrames": [{"id": 0, "name": "main", "line": 4, "column": 1}], "totalFrames": 1}))]);
    assert_eq!(connection.client.stack_trace().unwrap()[0].name.as_ref(), "main");
    assert_eq!(connection.request()["command"], "stackTrace");
    connection.send(&[response("scopes", json!({"scopes": [{"name": "Local Variables", "variablesReference": 41, "expensive": false}]}))]);
    assert_eq!(connection.client.scopes(7).unwrap()[0].variables_reference, 41);
    assert_eq!(connection.request()["arguments"]["frameId"], 7);
    connection.send(&[response("evaluate", json!({"result": "9", "variablesReference": 0}))]);
    assert_eq!(connection.client.evaluate_in_frame("x", 7).unwrap(), "9");
    let request = connection.request();
    assert_eq!(request["arguments"]["frameId"], 7);
    assert_eq!(request["arguments"]["expression"], "x");
    connection.send(&[response(
        "variables",
        json!({"variables": [{"name": "input", "value": "5", "variablesReference": 0}]}),
    )]);
    assert_eq!(connection.client.variables(41).unwrap()[0].value, "5");
    assert_eq!(connection.request()["arguments"]["variablesReference"], 41);
    connection.send(&[response("evaluate", json!({"result": "42", "variablesReference": 0}))]);
    assert_eq!(connection.client.read_memory(&"0 -t u32".parse().unwrap()).unwrap(), "42");
    assert!(
        connection.request()["arguments"]["expression"]
            .as_str()
            .unwrap()
            .starts_with("__miden_read_memory ")
    );
    connection.send(&[response("setBreakpoints", json!({"breakpoints": []}))]);
    connection.client.set_breakpoints("main.rs", &[3, 7]).unwrap();
    let request = connection.request();
    assert_eq!(request["arguments"]["source"]["path"], "main.rs");
    assert_eq!(request["arguments"]["breakpoints"], json!([{"line": 3}, {"line": 7}]));
    connection.send(&[response("setFunctionBreakpoints", json!({"breakpoints": []}))]);
    connection.client.set_function_breakpoints(&["main".into()]).unwrap();
    assert_eq!(connection.request()["arguments"]["breakpoints"][0]["name"], "main");
    connection.send(&[response("disconnect", json!(null))]);
    connection.client.disconnect().unwrap();
    assert_eq!(connection.request()["command"], "disconnect");
}

#[test]
fn invalid_responses_and_stop_events_report_actionable_errors() {
    for (message, expected) in [
        (
            json!({"type": "response", "request_seq": 1, "success": false, "message": "bad request", "error": null}),
            "DAP error",
        ),
        (
            json!({"type": "response", "request_seq": 1, "success": false, "error": null}),
            "unknown error",
        ),
        (json!({"type": "request"}), "unexpected message type"),
    ] {
        let mut connection = Connection::new();
        connection.send(&[message]);
        assert!(connection.client.wait_for_response("evaluate").unwrap_err().contains(expected));
    }
    for (message, expected) in [
        (
            json!({"type": "event", "event": "stopped", "body": {"reason": "step"}}),
            "without a preceding",
        ),
        (
            json!({"type": "event", "event": "miden/uiState", "body": {}}),
            "invalid miden/uiState",
        ),
    ] {
        let mut connection = Connection::new();
        connection.send(&[message]);
        assert!(connection.client.wait_for_stopped().unwrap_err().contains(expected));
    }
    let mut connection = Connection::new();
    connection.send(&[response("continue", json!({}))]);
    assert!(connection.client.stack_trace().unwrap_err().contains("unexpected response"));
    connection.send(&[response("continue", json!({}))]);
    assert!(connection.client.variables(1).unwrap_err().contains("unexpected response"));
    connection.send(&[response("continue", json!({}))]);
    assert!(connection.client.evaluate("input").unwrap_err().contains("unexpected response"));
}

#[test]
fn framing_rejects_invalid_lengths_utf8_and_json() {
    for (wire, expected) in [
        (b"Content-Length: nope\r\n\r\n".to_vec(), "invalid Content-Length"),
        (
            format!("Content-Length: {}\r\n\r\n", dap::server::MAX_CONTENT_LENGTH + 1).into_bytes(),
            "exceeds the maximum",
        ),
        (b"Content-Length: 1\r\n\r\n\xff".to_vec(), "invalid utf-8"),
        (b"Content-Length: 1\r\n\r\nx".to_vec(), "JSON parse error"),
    ] {
        let mut connection = Connection::new();
        connection.peer.write_all(&wire).unwrap();
        assert!(connection.client.read_message().unwrap_err().contains(expected));
    }
}

#[test]
fn retry_connects_to_available_listener_and_reports_invalid_address() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client =
        DapClient::connect_with_retry(&listener.local_addr().unwrap().to_string(), Duration::ZERO)
            .unwrap();
    let (_peer, _) = listener.accept().unwrap();
    client.writer.get_ref().shutdown(Shutdown::Both).unwrap();
    assert!(DapClient::connect("invalid address").is_err());
    assert!(
        DapClient::connect_with_retry("invalid address", Duration::ZERO)
            .err()
            .unwrap()
            .contains("failed to reconnect")
    );
}

#[test]
fn bundled_variables_preserve_raw_values_and_requested_frame() {
    let mut connection = Connection::new();
    for show_all in [false, true] {
        let variables = json!([
            {"name": "boolean", "value": "true", "raw": 1},
            {"name": "signed", "value": "-1i32", "raw": 4294967295u64},
            {"name": "array", "value": "[8, 7]", "raw": 8},
            {"name": "missing", "value": "<unavailable>", "raw": null}
        ])
        .to_string();
        connection
            .send(&[response("evaluate", json!({"result": variables, "variablesReference": 0}))]);
        let values = connection.client.frame_variables(42, show_all).unwrap();
        assert_eq!(
            values.iter().map(|value| value.raw).collect::<Vec<_>>(),
            [Some(1), Some(4294967295), Some(8), None]
        );
        assert_eq!(values[1].value, "-1i32");
        let request = connection.request();
        assert_eq!(request["arguments"]["frameId"], 42);
        assert_eq!(
            request["arguments"]["expression"],
            if show_all {
                "__miden_variables all"
            } else {
                "__miden_variables"
            }
        );
    }
    connection.send(&[response(
        "evaluate",
        json!({"result": "not a snapshot", "variablesReference": 0}),
    )]);
    assert!(
        connection
            .client
            .frame_variables(42, false)
            .unwrap_err()
            .contains("invalid DAP variable snapshot")
    );
}
