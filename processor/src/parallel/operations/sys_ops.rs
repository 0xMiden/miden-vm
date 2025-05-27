use super::CoreTraceFragmentGenerator;
use crate::processor::Processor;

impl CoreTraceFragmentGenerator {
    /// Asserts that the top element on the stack is 1.
    pub(crate) fn op_assert(&mut self) {
        #[cfg(debug_assertions)]
        {
            let value = self.stack_get(0);
            debug_assert!(
                value == miden_core::ONE,
                "Assertion failed: expected 1, got {value} at clock {}",
                self.state.system.clk
            );
        }

        self.decrement_stack_size();
    }
}
