use std::io::Cursor;

use serde_json::Value;

use super::*;
use crate::requests::{AttachOrLaunchArguments, Command, RestartArguments};

fn simulate_poll_request(input: &str) -> Request {
    let mut server_in = Cursor::new(input.as_bytes().to_vec());
    let server_out = Vec::new();
    let mut server = Server::new(BufReader::new(&mut server_in), BufWriter::new(server_out));

    server.poll_request().unwrap().unwrap()
}

#[test]
fn test_server_init_request() {
    let req = simulate_poll_request(
        "Content-Length: 155\r\n\r\n{\"seq\": 152,\"type\": \"request\",\"command\": \
         \"initialize\",\"arguments\": {\"adapterID\": \"0001e357-72c7-4f03-ae8f-c5b54bd8dabf\", \
         \"clientName\": \"Some Cool Editor\"}}",
    );

    assert_eq!(req.seq, 152);
    assert!(matches!(req.command, Command::Initialize { .. }));
}

#[test]
fn test_server_restart_request() {
    let req = simulate_poll_request(
        "Content-Length: 67\r\n\r\n{\"seq\": 152,\"type\": \"request\",\"command\": \
         \"restart\",\"arguments\": {}}",
    );

    assert!(matches!(
        req.command,
        Command::Restart(None | Some(RestartArguments { arguments: None }))
    ));

    // Restarting a launch request
    let req = simulate_poll_request(
        "Content-Length: 96\r\n\r\n{\"seq\": 152,\"type\": \"request\",\"command\": \
         \"restart\",\"arguments\": {\"arguments\": {\"noDebug\":true}}}",
    );
    assert!(matches!(
        req.command,
        Command::Restart(Some(RestartArguments {
            arguments: Some(AttachOrLaunchArguments { no_debug: Some(_), .. })
        }))
    ));

    // Restarting a launch or attach request
    let req = simulate_poll_request(
        "Content-Length: 98\r\n\r\n{\"seq\": 152,\"type\": \"request\",\"command\": \
         \"restart\",\"arguments\": {\"arguments\": {\"__restart\":true}}}",
    );
    assert!(matches!(
        req.command,
        Command::Restart(Some(RestartArguments {
            arguments: Some(AttachOrLaunchArguments {
                restart_data: Some(Value::Bool(true)),
                ..
            })
        }))
    ));
}

#[test]
fn unsupported_requests_preserve_the_command_and_arguments() {
    for (command, arguments) in [
        ("disassemble", serde_json::json!({"memoryReference": "42"})),
        ("futureCommand", serde_json::json!({})),
    ] {
        let body =
            serde_json::json!({"seq": 42, "command": command, "arguments": arguments}).to_string();
        let request =
            simulate_poll_request(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
        assert_eq!(request.seq, 42);
        assert!(
            matches!(request.command, Command::Unsupported { command: name, arguments: Some(args) }
            if name == command && args == arguments)
        );
    }
}

#[test]
fn empty_arguments_retain_supported_commands() {
    for command in ["launch", "attach", "restart", "configurationDone", "threads"] {
        let body = serde_json::json!({"seq": 1, "command": command, "arguments": {}}).to_string();
        let request =
            simulate_poll_request(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
        assert!(!matches!(request.command, Command::Unsupported { .. }), "{command}");
    }
}
