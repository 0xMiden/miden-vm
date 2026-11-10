//! Content-Length framing shared by the DAP server and client.

use std::io::{BufRead, Write};

use crate::errors::ServerError;

/// The largest DAP message accepted before allocating its body.
pub const MAX_CONTENT_LENGTH: usize = 16 * 1024 * 1024;

/// Read one message body, or `None` when the peer closes between messages.
pub fn read_frame(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>, ServerError> {
    let mut content_length = None;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).map_err(ServerError::IoError)? == 0 {
            return if content_length.is_none() {
                Ok(None)
            } else {
                Err(ServerError::IoError(std::io::ErrorKind::UnexpectedEof.into()))
            };
        }
        let header = line.trim_end();
        if header.is_empty() {
            if content_length.is_some() {
                break;
            }
            // Older adapters append a blank line after each body.
            continue;
        }
        let Some((name, value)) = header.split_once(':') else {
            return Err(ServerError::HeaderParseError { line });
        };
        match name {
            "Content-Length" => {
                let length: usize = value
                    .trim()
                    .parse()
                    .map_err(|_| ServerError::HeaderParseError { line: line.clone() })?;
                if length > MAX_CONTENT_LENGTH {
                    return Err(ServerError::ProtocolError {
                        reason: format!(
                            "content length {length} exceeds the maximum of {MAX_CONTENT_LENGTH}"
                        ),
                        line,
                    });
                }
                content_length = Some(length);
            },
            "Content-Type" => {},
            _ => return Err(ServerError::UnknownHeader { header: name.into() }),
        }
    }
    let mut body = vec![0; content_length.unwrap()];
    reader.read_exact(&mut body).map_err(ServerError::IoError)?;
    Ok(Some(body))
}

/// Write and flush one UTF-8 JSON message with its byte length.
pub fn write_frame(writer: &mut impl Write, body: &str) -> std::io::Result<()> {
    write!(writer, "Content-Length: {}\r\n\r\n{body}", body.len())?;
    writer.flush()
}

#[cfg(test)]
mod tests;
