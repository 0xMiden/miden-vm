use std::{
    io::{BufReader, BufWriter, Read, Write},
    sync::{Arc, Mutex},
};

use crate::{
    base_message::{BaseMessage, Sendable},
    errors::{DeserializationError, ServerError},
    events::Event,
    requests::Request,
    responses::Response,
};

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

pub use crate::framing::MAX_CONTENT_LENGTH;

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
        let Some(body) = crate::framing::read_frame(&mut self.input_buffer)? else {
            return Ok(None);
        };
        let content = std::str::from_utf8(&body)
            .map_err(|e| ServerError::ParseError(DeserializationError::DecodingError(e)))?;
        // Deserialize seq and command separately to avoid serde
        // #[serde(flatten)] issues with newer serde versions (>=1.0.171)
        // where flatten + adjacently-tagged enums can fail.
        let raw: serde_json::Value = serde_json::from_str(content).map_err(|e| {
            eprintln!("[DAP-RS] JSON parse error: {e}");
            ServerError::ParseError(DeserializationError::SerdeError(e))
        })?;
        let seq = raw.get("seq").and_then(serde_json::Value::as_i64).ok_or_else(|| {
            eprintln!("[DAP-RS] Missing seq field");
            ServerError::ParseError(DeserializationError::SerdeError(
                serde_json::from_str::<()>("\"missing seq field\"").unwrap_err(),
            ))
        })?;
        let mut raw = raw;
        if matches!(
            raw.get("command").and_then(serde_json::Value::as_str),
            Some("configurationDone" | "threads")
        ) && raw
            .get("arguments")
            .and_then(serde_json::Value::as_object)
            .is_some_and(serde_json::Map::is_empty)
        {
            raw.as_object_mut().unwrap().remove("arguments");
        }
        let command = serde_json::from_value(raw)
            .map_err(|e| ServerError::ParseError(DeserializationError::SerdeError(e)))?;
        let request = Request { seq, command };
        Ok(Some(request))
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
}

impl<W: Write> ServerOutput<W> {
    pub fn send(&mut self, body: Sendable) -> Result<(), ServerError> {
        self.sequence_number += 1;

        let message = BaseMessage { seq: self.sequence_number, message: body };

        let resp_json = serde_json::to_string(&message).map_err(ServerError::SerializationError)?;
        crate::framing::write_frame(&mut self.output_buffer, &resp_json)
            .map_err(ServerError::IoError)?;
        Ok(())
    }

    pub fn respond(&mut self, response: Response) -> Result<(), ServerError> {
        self.send(Sendable::Response(response))
    }

    pub fn send_event(&mut self, event: Event) -> Result<(), ServerError> {
        self.send(Sendable::Event(event))
    }
}

#[cfg(test)]
mod tests;
