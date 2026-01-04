use alloc::{boxed::Box, string::String, vec::Vec};
use core::fmt;

use miden_core::field::ExtensionField;

use crate::Felt;

/// A message that can be sent on a bus.
pub(crate) trait BusMessage<E: ExtensionField<Felt>>: fmt::Display {
    /// The concrete value that this message evaluates to.
    fn value(&self, alphas: &[E]) -> E;

    /// The source of this message (e.g. "mload" or "memory chiplet").
    fn source(&self) -> &str;
}

/// A debugger for a bus that can be used to track outstanding requests and responses.
///
/// Note: we use `Vec` internally instead of a `BTreeMap`, since messages can have collisions (i.e.
/// 2 messages sent with the same key), which results in relatively complex insertion/deletion
/// logic. Since this is only used in debug/test code, the performance hit is acceptable.
pub(crate) struct BusDebugger<E: ExtensionField<Felt>> {
    pub bus_name: String,
    pub outstanding_requests: Vec<(E, Box<dyn BusMessage<E>>)>,
    pub outstanding_responses: Vec<(E, Box<dyn BusMessage<E>>)>,
}

impl<E> BusDebugger<E>
where
    E: ExtensionField<Felt>,
{
    pub fn new(bus_name: String) -> Self {
        Self {
            bus_name,
            outstanding_requests: Vec::new(),
            outstanding_responses: Vec::new(),
        }
    }
}

impl<E> BusDebugger<E>
where
    E: ExtensionField<Felt>,
{
    /// Attempts to match the request with an existing response. If a match is found, the response
    /// is removed from the list of outstanding responses. Otherwise, the request is added to the
    /// list of outstanding requests.
    #[cfg(any(test, feature = "bus-debugger"))]
    pub fn add_request(&mut self, request_msg: Box<dyn BusMessage<E>>, alphas: &[E]) {
        let msg_value = request_msg.value(alphas);

        if let Some(pos) =
            self.outstanding_responses.iter().position(|(value, _)| *value == msg_value)
        {
            self.outstanding_responses.swap_remove(pos);
        } else {
            self.outstanding_requests.push((msg_value, request_msg));
        }
    }

    /// Attempts to match the response with an existing request. If a match is found, the request is
    /// removed from the list of outstanding requests. Otherwise, the response is added to the list
    /// of outstanding responses.
    #[cfg(any(test, feature = "bus-debugger"))]
    pub fn add_response(&mut self, response_msg: Box<dyn BusMessage<E>>, alphas: &[E]) {
        let msg_value = response_msg.value(alphas);

        if let Some(pos) =
            self.outstanding_requests.iter().position(|(value, _)| *value == msg_value)
        {
            self.outstanding_requests.swap_remove(pos);
        } else {
            self.outstanding_responses.push((msg_value, response_msg));
        }
    }

    /// Returns true if there are no outstanding requests or responses.
    ///
    /// This is meant to be called at the end of filling the bus. If there are any outstanding
    /// requests or responses, it means that there is a mismatch between the requests and responses,
    /// and the test should fail. The `Debug` implementation for `BusDebugger` will print out the
    /// outstanding requests and responses.
    pub fn is_empty(&self) -> bool {
        self.outstanding_requests.is_empty() && self.outstanding_responses.is_empty()
    }
}

impl<E> fmt::Display for BusDebugger<E>
where
    E: ExtensionField<Felt>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            writeln!(f, "Bus '{}' is empty.", self.bus_name)?;
        } else {
            writeln!(f, "Bus '{}' construction failed.", self.bus_name)?;

            if !self.outstanding_requests.is_empty() {
                writeln!(f, "The following requests are still outstanding:")?;
                for (_value, msg) in &self.outstanding_requests {
                    writeln!(f, "- {}: {}", msg.source(), msg)?;
                }
            }

            if !self.outstanding_responses.is_empty() {
                writeln!(f, "\nThe following responses are still outstanding:")?;
                for (_value, msg) in &self.outstanding_responses {
                    writeln!(f, "- {}: {}", msg.source(), msg)?;
                }
            }
        }

        Ok(())
    }
}
