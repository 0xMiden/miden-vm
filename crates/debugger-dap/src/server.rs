use std::{
    fmt::Debug,
    io::{BufRead, BufReader, BufWriter, Read, Write},
    sync::{Arc, Mutex},
};

use serde_json;

use crate::{
    base_message::{BaseMessage, Sendable},
    errors::{DeserializationError, ServerError},
    events::Event,
    requests::Request,
    responses::Response,
    reverse_requests::ReverseRequest,
};

#[derive(Debug)]
enum ServerState {
    /// Expecting a header
    Header,
    /// Expecting content
    Content,
}

/// Handles message encoding and decoding of messages.
///
/// The `Server` is responsible for reading the incoming bytestream and constructing deserialized
/// requests from it, as well as constructing and serializing outgoing messages.
pub struct Server<R: Read, W: Write> {
    input_buffer: BufReader<R>,

    /// A sharable `ServerOutput` object for sending messages and events from
    /// other threads.
    pub output: Arc<Mutex<ServerOutput<W>>>,
}

/// Handles emission of messages through the connection.
///
/// `ServerOutput` is responsible for sending messages to the connection.
/// It's only accessible through a mutex that can be shared with other
/// threads. This makes it possible to send e.g. events while the server is
/// blocked polling requests.
pub struct ServerOutput<W: Write> {
    output_buffer: BufWriter<W>,
    sequence_number: i64,
}

/// The largest `Content-Length` this server will act on.
///
/// The header is attacker-controlled and feeds two allocations directly, so an unbounded value
/// ends the process rather than the request. DAP payloads carry source text and variable dumps,
/// not bulk data, so this ceiling is far above any legitimate message.
pub const MAX_CONTENT_LENGTH: usize = 16 * 1024 * 1024;

impl<R: Read, W: Write> Server<R, W> {
    /// Construct a new Server using the given input and output streams.
    pub fn new(input: BufReader<R>, output: BufWriter<W>) -> Self {
        let server_output = Arc::new(Mutex::new(ServerOutput {
            output_buffer: output,
            sequence_number: 0,
        }));

        Self {
            input_buffer: input,
            output: server_output,
        }
    }

    /// Wait for a request from the development tool
    ///
    /// This will start reading the `input` buffer that is passed to it and will try to interpret
    /// the incoming bytes according to the DAP protocol.
    pub fn poll_request(&mut self) -> Result<Option<Request>, ServerError> {
        let mut state = ServerState::Header;
        let mut buffer = String::new();
        let mut content_length: usize = 0;

        loop {
            match self.input_buffer.read_line(&mut buffer) {
                Ok(read_size) => {
                    if read_size == 0 {
                        break Ok(None);
                    }
                    match state {
                        ServerState::Header => {
                            let parts: Vec<&str> = buffer.trim_end().split(':').collect();
                            if parts.len() == 2 {
                                match parts[0] {
                                    "Content-Length" => {
                                        content_length = match parts[1].trim().parse() {
                                            Ok(val) if val <= MAX_CONTENT_LENGTH => val,
                                            Ok(val) => {
                                                return Err(ServerError::ProtocolError {
                                                    reason: format!(
                                                        "content length {val} exceeds the maximum \
                                                         of {MAX_CONTENT_LENGTH}"
                                                    ),
                                                    line: buffer,
                                                });
                                            }
                                            Err(_) => {
                                                return Err(ServerError::HeaderParseError {
                                                    line: buffer,
                                                });
                                            }
                                        };
                                        buffer.clear();
                                        buffer.reserve(content_length);
                                        state = ServerState::Content;
                                    }
                                    other => {
                                        return Err(ServerError::UnknownHeader {
                                            header: other.to_string(),
                                        });
                                    }
                                }
                            } else {
                                return Err(ServerError::HeaderParseError { line: buffer });
                            }
                        }
                        ServerState::Content => {
                            buffer.clear();
                            let mut content = vec![0; content_length];
                            self.input_buffer
                                .read_exact(content.as_mut_slice())
                                .map_err(ServerError::IoError)?;

                            let content = std::str::from_utf8(content.as_slice()).map_err(|e| {
                                ServerError::ParseError(DeserializationError::DecodingError(e))
                            })?;
                            eprintln!(
                                "[DAP-RS] Received content ({content_length} bytes): {content}"
                            );
                            // Deserialize seq and command separately to avoid serde
                            // #[serde(flatten)] issues with newer serde versions (>=1.0.171)
                            // where flatten + adjacently-tagged enums can fail.
                            let raw: serde_json::Value =
                                serde_json::from_str(content).map_err(|e| {
                                    eprintln!("[DAP-RS] JSON parse error: {e}");
                                    ServerError::ParseError(DeserializationError::SerdeError(e))
                                })?;
                            let seq = raw.get("seq").and_then(|v| v.as_i64()).ok_or_else(|| {
                                eprintln!("[DAP-RS] Missing seq field");
                                ServerError::ParseError(DeserializationError::SerdeError(
                                    serde_json::from_str::<()>("\"missing seq field\"")
                                        .unwrap_err(),
                                ))
                            })?;
                            // Handle the conflict between unit variants (e.g. ConfigurationDone)
                            // and struct variants with all-optional fields (e.g. Launch):
                            // - Unit variants fail with "arguments": {} ("invalid type: map, expected unit variant")
                            // - Struct variants fail without "arguments" ("missing field `arguments`")
                            // When arguments is an empty object, try without it first (unit variant),
                            // then fall back to keeping it (struct variant with optional fields).
                            let command: crate::requests::Command = if raw
                                .get("arguments")
                                .and_then(|v| v.as_object())
                                .is_some_and(|m| m.is_empty())
                            {
                                let mut without_args = raw.clone();
                                without_args.as_object_mut().unwrap().remove("arguments");
                                match serde_json::from_value::<crate::requests::Command>(
                                    without_args,
                                ) {
                                    Ok(cmd) => cmd,
                                    Err(_) => serde_json::from_value(raw.clone()).map_err(|e| {
                                        eprintln!("[DAP-RS] Command deserialize error: {e}");
                                        ServerError::ParseError(DeserializationError::SerdeError(e))
                                    })?,
                                }
                            } else {
                                serde_json::from_value(raw.clone()).map_err(|e| {
                                    eprintln!("[DAP-RS] Command deserialize error: {e}");
                                    ServerError::ParseError(DeserializationError::SerdeError(e))
                                })?
                            };
                            eprintln!("[DAP-RS] Successfully parsed request seq={seq}");
                            let request = Request { seq, command };
                            return Ok(Some(request));
                        }
                    }
                }
                Err(e) => return Err(ServerError::IoError(e)),
            }
        }
    }

    pub fn send(&mut self, body: Sendable) -> Result<(), ServerError> {
        let mut output = self.output.lock().map_err(|_| ServerError::OutputLockError)?;
        output.send(body)
    }

    pub fn respond(&mut self, response: Response) -> Result<(), ServerError> {
        self.send(Sendable::Response(response))
    }

    pub fn send_event(&mut self, event: Event) -> Result<(), ServerError> {
        self.send(Sendable::Event(event))
    }

    pub fn send_reverse_request(&mut self, request: ReverseRequest) -> Result<(), ServerError> {
        self.send(Sendable::ReverseRequest(request))
    }
}

impl<W: Write> ServerOutput<W> {
    pub fn send(&mut self, body: Sendable) -> Result<(), ServerError> {
        self.sequence_number += 1;

        let message = BaseMessage {
            seq: self.sequence_number,
            message: body,
        };

        let resp_json = serde_json::to_string(&message).map_err(ServerError::SerializationError)?;
        write!(self.output_buffer, "Content-Length: {}\r\n\r\n", resp_json.len())
            .map_err(ServerError::IoError)?;

        write!(self.output_buffer, "{}\r\n", resp_json).map_err(ServerError::IoError)?;
        self.output_buffer.flush().map_err(ServerError::IoError)?;
        Ok(())
    }

    pub fn respond(&mut self, response: Response) -> Result<(), ServerError> {
        self.send(Sendable::Response(response))
    }

    pub fn send_event(&mut self, event: Event) -> Result<(), ServerError> {
        self.send(Sendable::Event(event))
    }

    pub fn send_reverse_request(&mut self, request: ReverseRequest) -> Result<(), ServerError> {
        self.send(Sendable::ReverseRequest(request))
    }
}

#[cfg(test)]
mod tests;
