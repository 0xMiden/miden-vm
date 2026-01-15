//! Utilities for testing MASM code against malicious advice provider data.
//!
//! This module provides tools for injecting arbitrary (potentially malicious) values
//! into the advice stack during test execution. This enables testing that MASM code
//! properly validates non-deterministic data received from the advice provider.
//!
//! # Usage
//!
//! 1. Create a `MaliciousAdviceHandler` with the values you want to inject
//! 2. Register it with a test using `test.add_event_handler()`
//! 3. In your MASM code, emit the corresponding event to trigger the injection
//! 4. Verify that the MASM code properly validates/rejects the malicious data
//!
//! # Example
//!
//! ```ignore
//! use miden_test_utils::{MaliciousAdviceHandler, build_debug_test};
//! use miden_core::{Felt, EventName};
//!
//! // Create a handler that will push invalid values
//! let handler = MaliciousAdviceHandler::new(vec![
//!     Felt::new(999),  // wrong pointer
//!     Felt::new(0),    // wrong flag
//! ]);
//!
//! let source = r#"
//!     begin
//!         # Setup some data...
//!         emit.event("inject_malicious_data")
//!         # MASM code reads from advice stack and should validate
//!         adv_push.2
//!         # Validation should fail here if data is invalid
//!     end
//! "#;
//!
//! let mut test = build_debug_test!(source, &[]);
//! test.add_event_handler(
//!     EventName::new("inject_malicious_data"),
//!     handler
//! );
//!
//! // Expect execution to fail due to validation
//! test.execute().expect_err("expected validation to fail");
//! ```

use alloc::{sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use miden_core::Felt;
use miden_processor::{AdviceMutation, EventError, EventHandler, ProcessState};

/// An event handler that injects predetermined values onto the advice stack.
///
/// This handler is useful for testing that MASM code properly validates data
/// received from the advice provider. By injecting known-bad values, tests can
/// verify that validation logic correctly rejects invalid inputs.
///
/// # Thread Safety
///
/// This handler is thread-safe and can be cloned. The call counter is shared
/// across clones, which is useful for verifying the handler was triggered.
#[derive(Clone)]
pub struct MaliciousAdviceHandler {
    /// Values to push onto the advice stack when triggered.
    /// Values are pushed in order, so the first element will be deepest on the stack.
    values: Arc<Vec<Felt>>,
    /// Counter for how many times this handler has been invoked.
    call_count: Arc<AtomicUsize>,
}

impl MaliciousAdviceHandler {
    /// Creates a new handler that will push the given values onto the advice stack.
    ///
    /// The values are pushed in the order provided, meaning the first element in the
    /// vector will end up deepest on the advice stack, and the last element will be
    /// on top (first to be popped).
    pub fn new(values: impl IntoIterator<Item = Felt>) -> Self {
        Self {
            values: Arc::new(values.into_iter().collect()),
            call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Creates a new handler from u64 values for convenience.
    pub fn from_u64s(values: impl IntoIterator<Item = u64>) -> Self {
        Self::new(values.into_iter().map(Felt::new))
    }

    /// Returns how many times this handler has been invoked.
    pub fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }

    /// Resets the call counter to zero.
    pub fn reset_call_count(&self) {
        self.call_count.store(0, Ordering::SeqCst);
    }
}

impl EventHandler for MaliciousAdviceHandler {
    fn on_event(&self, _process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(vec![AdviceMutation::extend_stack(self.values.iter().copied())])
    }
}

impl core::fmt::Debug for MaliciousAdviceHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MaliciousAdviceHandler")
            .field("values", &self.values)
            .field("call_count", &self.call_count.load(Ordering::SeqCst))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malicious_handler_creation() {
        let handler = MaliciousAdviceHandler::from_u64s([1, 2, 3, 4]);
        assert_eq!(handler.call_count(), 0);
        assert_eq!(handler.values.len(), 4);
    }

    #[test]
    fn test_malicious_handler_clone_shares_counter() {
        let handler1 = MaliciousAdviceHandler::from_u64s([1, 2, 3]);
        let handler2 = handler1.clone();

        // Simulate calling the handler
        handler1.call_count.fetch_add(1, Ordering::SeqCst);

        // Both should see the same count
        assert_eq!(handler1.call_count(), 1);
        assert_eq!(handler2.call_count(), 1);
    }
}
