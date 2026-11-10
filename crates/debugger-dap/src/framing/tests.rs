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
    for wire in [b"Content-Length: 3\r\n".as_slice(), b"Content-Length: 3\r\n\r\nx"] {
        assert!(matches!(
            read_frame(&mut Cursor::new(wire)),
            Err(ServerError::IoError(error)) if error.kind() == ErrorKind::UnexpectedEof
        ));
    }
}
