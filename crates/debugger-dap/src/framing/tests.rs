use std::io::{Cursor, ErrorKind};

use super::*;

#[test]
fn frames_preserve_utf8_bytes_and_message_boundaries() {
    let mut wire = Vec::new();
    let body = "{\"text\":\"☃\"}";
    write_frame(&mut wire, body).unwrap();
    // Accept the trailing CRLF emitted by older servers too.
    wire.extend_from_slice(b"\r\n");
    write_frame(&mut wire, "{}").unwrap();
    let mut input = Cursor::new(wire);
    assert_eq!(read_frame(&mut input).unwrap().unwrap(), body.as_bytes());
    assert_eq!(read_frame(&mut input).unwrap().unwrap(), b"{}");
    assert!(read_frame(&mut input).unwrap().is_none());
}

#[test]
fn rejects_bad_lengths_before_reading_a_body() {
    for header in [
        "Content-Length: invalid\r\n\r\n".to_string(),
        format!("Content-Length: {}\r\n\r\n", MAX_CONTENT_LENGTH + 1),
    ] {
        assert!(read_frame(&mut Cursor::new(header)).is_err());
    }
}

#[test]
fn distinguishes_clean_eof_from_truncated_header_and_body() {
    assert!(read_frame(&mut Cursor::new(b"")).unwrap().is_none());
    for wire in [
        b"Content-Length: 3\r\n".as_slice(),
        b"Content-Length: 3\r\n\r\nx",
        b"Content-Type: application/vscode-jsonrpc; charset=utf-8\r\n",
    ] {
        assert!(matches!(
            read_frame(&mut Cursor::new(wire)),
            Err(ServerError::IoError(error)) if error.kind() == ErrorKind::UnexpectedEof
        ));
    }
}

#[test]
fn rejects_duplicate_lengths_and_missing_length_after_content_type() {
    for length in [1, 2] {
        let wire = format!("Content-Length: 1\r\nContent-Length: {length}\r\n\r\n{{}}");
        assert!(matches!(read_frame(&mut Cursor::new(wire)),
            Err(ServerError::ProtocolError { reason, .. })
                if reason == format!("duplicate Content-Length headers: 1 and {length}")));
    }
    assert!(matches!(
        read_frame(&mut Cursor::new(b"Content-Type: application/vscode-jsonrpc\r\n\r\n")),
        Err(ServerError::ProtocolError { reason, .. }) if reason == "missing Content-Length header"
    ));
}

#[test]
fn accepts_content_type_before_or_after_content_length() {
    for headers in [
        "Content-Type: application/vscode-jsonrpc\r\nContent-Length: 2",
        "Content-Length: 2\r\nContent-Type: application/vscode-jsonrpc",
    ] {
        let wire = format!("{headers}\r\n\r\n{{}}");
        assert_eq!(read_frame(&mut Cursor::new(wire)).unwrap().unwrap(), b"{}");
    }
}
