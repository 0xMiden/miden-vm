#[cfg(feature = "client")]
use serde::Deserialize;
use serde::Serialize;

use crate::{events::Event, responses::Response, reverse_requests::ReverseRequest};

/// Represents the base protocol message, in which all other messages are wrapped.
///
/// Specification: [Response](https://microsoft.github.io/debug-adapter-protocol/specification)
#[cfg_attr(feature = "client", derive(Deserialize))]
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BaseMessage {
    /// Sequence number of the message. The `seq` for
    /// the first message is 1, and for each message is incremented by 1.
    pub seq: i64,
    #[serde(flatten)]
    pub message: Sendable,
}

#[cfg_attr(feature = "client", derive(Deserialize))]
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type")]
pub enum Sendable {
    Response(Response),
    Event(Event),
    ReverseRequest(ReverseRequest),
}

#[cfg(test)]
mod tests;
