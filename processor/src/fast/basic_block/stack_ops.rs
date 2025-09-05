use miden_core::{WORD_SIZE, ZERO};

use crate::{
    ErrorContext, ExecutionError,
    fast::{FastProcessor, Tracer},
};

impl FastProcessor {
    /// Analogous to `Process::op_pad`.
    pub fn op_pad(&mut self, tracer: &mut impl Tracer) {
        self.increment_stack_size(tracer);
        self.stack_write(0, ZERO);
    }

    /// Analogous to `Process::op_swap`.
    pub fn op_swap(&mut self) {
        self.stack_swap(0, 1);
    }

    /// Analogous to `Process::op_swapdw`.
    pub fn op_swap_double_word(&mut self) {
        self.stack_swap(0, 8);
        self.stack_swap(1, 9);
        self.stack_swap(2, 10);
        self.stack_swap(3, 11);
        self.stack_swap(4, 12);
        self.stack_swap(5, 13);
        self.stack_swap(6, 14);
        self.stack_swap(7, 15);
    }

    /// Rotates the top `n` elements of the stack to the left by 1.
    ///
    /// For example, if the stack is [a, b, c, d], with `d` at the top, then `rotate_left(3)` will
    /// result in the top 3 elements being rotated left: [a, c, d, b].
    ///
    /// This operation is useful for implementing the `movup` instructions.
    ///
    /// The stack size doesn't change.
    ///
    /// Note: This method doesn't use the `stack_get()` and `stack_write()` methods because it is
    /// more efficient to directly manipulate the stack array (~10% performance difference).
    #[inline(always)]
    pub fn rotate_left(&mut self, n: usize) {
        let rotation_bot_index = self.stack_top_idx - n;
        let new_stack_top_element = self.stack[rotation_bot_index];

        // shift the top n elements down by 1, starting from the bottom of the rotation.
        for i in 0..n - 1 {
            self.stack[rotation_bot_index + i] = self.stack[rotation_bot_index + i + 1];
        }

        // Set the top element (which comes from the bottom of the rotation).
        self.stack_write(0, new_stack_top_element);
    }

    /// Rotates the top `n` elements of the stack to the right by 1.
    ///
    /// Analogous to `rotate_left`, but in the opposite direction.
    ///
    /// Note: This method doesn't use the `stack_get()` and `stack_write()` methods because it is
    /// more efficient to directly manipulate the stack array (~10% performance difference).
    #[inline(always)]
    pub fn rotate_right(&mut self, n: usize) {
        let rotation_bot_index = self.stack_top_idx - n;
        let new_stack_bot_element = self.stack[self.stack_top_idx - 1];

        // shift the top n elements up by 1, starting from the top of the rotation.
        for i in 1..n {
            self.stack[self.stack_top_idx - i] = self.stack[self.stack_top_idx - i - 1];
        }

        // Set the bot element (which comes from the top of the rotation).
        self.stack[rotation_bot_index] = new_stack_bot_element;
    }

    /// Duplicates the n'th element from the top of the stack to the top of the stack.
    ///
    /// The size of the stack is incremented by 1.
    #[inline(always)]
    pub fn dup_nth(&mut self, n: usize, tracer: &mut impl Tracer) {
        let to_dup = self.stack_get(n);
        self.increment_stack_size(tracer);
        self.stack_write(0, to_dup);
    }

    /// Swaps the nth word from the top of the stack with the top word of the stack.
    ///
    /// Valid values of `n` are 1, 2, and 3.
    pub fn swapw_nth(&mut self, n: usize) {
        // For example, for n=3, the stack words and variables look like:
        //    3     2     1     0
        // | ... | ... | ... | ... |
        // ^                 ^
        // nth_word       top_word
        let (rest_of_stack, top_word) = self.stack.split_at_mut(self.stack_top_idx - WORD_SIZE);
        let (_, nth_word) = rest_of_stack.split_at_mut(rest_of_stack.len() - n * WORD_SIZE);

        nth_word[0..WORD_SIZE].swap_with_slice(&mut top_word[0..WORD_SIZE]);
    }

    /// Analogous to `Process::op_cswap`.
    pub fn op_cswap(
        &mut self,
        err_ctx: &impl ErrorContext,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        let condition = self.stack_get(0);
        self.decrement_stack_size(tracer);

        match condition.as_int() {
            0 => {
                // do nothing, a and b are already in the right place
            },
            1 => {
                self.stack_swap(0, 1);
            },
            _ => {
                return Err(ExecutionError::not_binary_value_op(condition, err_ctx));
            },
        }

        Ok(())
    }

    /// Analogous to `Process::op_cswapw`.
    pub fn op_cswapw(
        &mut self,
        err_ctx: &impl ErrorContext,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        let condition = self.stack_get(0);
        self.decrement_stack_size(tracer);

        match condition.as_int() {
            0 => {
                // do nothing, the words are already in the right place
            },
            1 => {
                self.stack_swap(0, 4);
                self.stack_swap(1, 5);
                self.stack_swap(2, 6);
                self.stack_swap(3, 7);
            },
            _ => {
                return Err(ExecutionError::not_binary_value_op(condition, err_ctx));
            },
        }

        Ok(())
    }
}
