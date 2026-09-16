use std::sync::{Arc, OnceLock};

use miden_core::events::EventName;
use miden_processor::{
    ProcessorState,
    event::{TraceError, TraceHandler},
};

// Zero padding would hide dropped caller data.
pub(super) const CALLER_WORD: [u64; 4] = [101, 102, 103, 104];
pub(super) const VERIFIER_RETURN: EventName = EventName::new("test::verifier_return");

/// Captures the verifier's stack before the test program truncates it.
#[derive(Clone, Debug, Default)]
pub(super) struct VerifierStack {
    values: Arc<OnceLock<Vec<u64>>>,
}

impl TraceHandler for VerifierStack {
    fn on_trace(&self, process: &ProcessorState) -> Result<(), TraceError> {
        // trace places the system event ID and trace ID above the verifier's stack.
        let values = process
            .get_stack_state()
            .into_iter()
            .skip(2)
            .map(|value| value.as_canonical_u64())
            .collect();
        self.values
            .set(values)
            .expect("verifier return trace was emitted more than once");
        Ok(())
    }
}

impl VerifierStack {
    #[track_caller]
    pub(super) fn assert_outputs_and_caller(&self, expected_outputs: &[u64]) {
        let values = self.values.get().expect("verifier return trace was not emitted");
        let expected_len = expected_outputs.len() + CALLER_WORD.len();
        assert!(
            values.len() >= expected_len,
            "verifier returned too few stack elements: {values:?}"
        );

        let (outputs, rest) = values.split_at(expected_outputs.len());
        let (caller, padding) = rest.split_at(CALLER_WORD.len());
        assert_eq!(outputs, expected_outputs, "verifier returned unexpected outputs");
        assert_eq!(caller, CALLER_WORD, "verifier changed caller data");
        // The VM adds zero padding when the stack would fall below 16 elements.
        assert!(
            padding.iter().all(|&value| value == 0),
            "unexpected values below the caller word"
        );
    }
}
