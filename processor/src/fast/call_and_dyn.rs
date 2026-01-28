use alloc::vec::Vec;

use miden_core::{ZERO, stack::MIN_STACK_DEPTH, utils::range};

use crate::{
    errors::OperationError,
    fast::{ExecutionContextInfo, FastProcessor, INITIAL_STACK_TOP_IDX, STACK_BUFFER_SIZE, Tracer},
};

impl FastProcessor {
    /// Saves the current execution context and truncates the stack to 16 elements in preparation to
    /// start a new execution context.
    pub(super) fn save_context_and_truncate_stack(&mut self, tracer: &mut impl Tracer) {
        let overflow_stack = if self.stack_size() > MIN_STACK_DEPTH {
            // save the overflow stack, and zero out the buffer.
            //
            // Note: we need to zero the overflow buffer, since the new context expects ZERO's to be
            // pulled in if they decrement the stack size (e.g. by executing a `drop`).
            let overflow_stack =
                self.stack[self.stack_bot_idx..self.stack_top_idx - MIN_STACK_DEPTH].to_vec();
            self.stack[self.stack_bot_idx..self.stack_top_idx - MIN_STACK_DEPTH].fill(ZERO);

            overflow_stack
        } else {
            Vec::new()
        };

        self.stack_bot_idx = self.stack_top_idx - MIN_STACK_DEPTH;

        self.call_stack.push(ExecutionContextInfo {
            overflow_stack,
            ctx: self.ctx,
            fn_hash: self.caller_hash,
        });

        tracer.start_context();
    }

    /// Restores the execution context to the state it was in before the last `call`, `syscall` or
    /// `dyncall`.
    ///
    /// This includes restoring the overflow stack and the system parameters.
    ///
    /// # Errors
    /// - Returns an error if the overflow stack is larger than the space available in the stack
    ///   buffer.
    pub(super) fn restore_context(
        &mut self,
        tracer: &mut impl Tracer,
    ) -> Result<(), OperationError> {
        // when a call/dyncall/syscall node ends, stack depth must be exactly 16.
        if self.stack_size() > MIN_STACK_DEPTH {
            return Err(OperationError::InvalidStackDepthOnReturn { depth: self.stack_size() });
        }

        let ctx_info = self
            .call_stack
            .pop()
            .expect("execution context stack should never be empty when restoring context");

        // restore the overflow stack
        self.restore_overflow_stack(&ctx_info);

        // restore system parameters
        self.ctx = ctx_info.ctx;
        self.caller_hash = ctx_info.fn_hash;

        tracer.restore_context();

        Ok(())
    }

    /// Restores the overflow stack from a previous context.
    ///
    /// If necessary, moves the stack in the buffer to make room for the overflow stack to be
    /// restored.
    ///
    /// # Preconditions
    /// - The current stack depth is exactly `MIN_STACK_DEPTH` (16).
    #[inline(always)]
    fn restore_overflow_stack(&mut self, ctx_info: &ExecutionContextInfo) {
        let target_overflow_len = ctx_info.overflow_stack.len();

        // Check if there's enough room to restore the overflow stack in the current stack buffer.
        if target_overflow_len > self.stack_bot_idx {
            // There's not enough room to restore the overflow stack, so we have to move the
            // location of the stack in the buffer. We reset it so that after restoring the overflow
            // stack, the stack_bot_idx is at its original position (i.e. INITIAL_STACK_TOP_IDX -
            // 16).
            let new_stack_top_idx =
                core::cmp::min(INITIAL_STACK_TOP_IDX + target_overflow_len, STACK_BUFFER_SIZE - 1);

            self.reset_stack_in_buffer(new_stack_top_idx);
        }

        // Restore the overflow
        self.stack[range(self.stack_bot_idx - target_overflow_len, target_overflow_len)]
            .copy_from_slice(&ctx_info.overflow_stack);
        self.stack_bot_idx -= target_overflow_len;
    }
}
