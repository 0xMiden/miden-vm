use super::{ExecutionError, MIN_STACK_DEPTH, Process};
use crate::{ErrorContext, ZERO};

impl Process {
    // STACK MANIPULATION
    // --------------------------------------------------------------------------------------------
    /// Pushes a ZERO onto the stack.
    pub(super) fn op_pad(&mut self) -> Result<(), ExecutionError> {
        self.stack.set(0, ZERO);
        self.stack.shift_right(0);
        Ok(())
    }

    /// Removes the top element off the stack.
    pub(super) fn op_drop(&mut self) -> Result<(), ExecutionError> {
        self.stack.shift_left(1);
        Ok(())
    }

    /// Pushes the copy the n-th item onto the stack. n is 0-based.
    pub(super) fn op_dup(&mut self, n: usize) -> Result<(), ExecutionError> {
        let value = self.stack.get(n);
        self.stack.set(0, value);
        self.stack.shift_right(0);
        Ok(())
    }

    /// Swaps stack elements 0 and 1.
    pub(super) fn op_swap(&mut self) -> Result<(), ExecutionError> {
        let a = self.stack.get(0);
        let b = self.stack.get(1);
        self.stack.set(0, b);
        self.stack.set(1, a);
        self.stack.copy_state(2);
        Ok(())
    }

    /// Swaps stack elements 0, 1, 2, and 3 with elements 4, 5, 6, and 7.
    pub(super) fn op_swapw(&mut self) -> Result<(), ExecutionError> {
        let a0 = self.stack.get(0);
        let a1 = self.stack.get(1);
        let a2 = self.stack.get(2);
        let a3 = self.stack.get(3);
        let b0 = self.stack.get(4);
        let b1 = self.stack.get(5);
        let b2 = self.stack.get(6);
        let b3 = self.stack.get(7);

        self.stack.set(0, b0);
        self.stack.set(1, b1);
        self.stack.set(2, b2);
        self.stack.set(3, b3);
        self.stack.set(4, a0);
        self.stack.set(5, a1);
        self.stack.set(6, a2);
        self.stack.set(7, a3);

        self.stack.copy_state(8);
        Ok(())
    }

    /// Swaps stack elements 0, 1, 2, and 3 with elements 8, 9, 10, and 11.
    pub(super) fn op_swapw2(&mut self) -> Result<(), ExecutionError> {
        let a0 = self.stack.get(0);
        let a1 = self.stack.get(1);
        let a2 = self.stack.get(2);
        let a3 = self.stack.get(3);
        let b0 = self.stack.get(4);
        let b1 = self.stack.get(5);
        let b2 = self.stack.get(6);
        let b3 = self.stack.get(7);
        let c0 = self.stack.get(8);
        let c1 = self.stack.get(9);
        let c2 = self.stack.get(10);
        let c3 = self.stack.get(11);

        self.stack.set(0, c0);
        self.stack.set(1, c1);
        self.stack.set(2, c2);
        self.stack.set(3, c3);
        self.stack.set(4, b0);
        self.stack.set(5, b1);
        self.stack.set(6, b2);
        self.stack.set(7, b3);
        self.stack.set(8, a0);
        self.stack.set(9, a1);
        self.stack.set(10, a2);
        self.stack.set(11, a3);

        self.stack.copy_state(12);
        Ok(())
    }

    /// Swaps stack elements 0, 1, 2, and 3, with elements 12, 13, 14, and 15.
    pub(super) fn op_swapw3(&mut self) -> Result<(), ExecutionError> {
        let a0 = self.stack.get(0);
        let a1 = self.stack.get(1);
        let a2 = self.stack.get(2);
        let a3 = self.stack.get(3);
        let b0 = self.stack.get(4);
        let b1 = self.stack.get(5);
        let b2 = self.stack.get(6);
        let b3 = self.stack.get(7);
        let c0 = self.stack.get(8);
        let c1 = self.stack.get(9);
        let c2 = self.stack.get(10);
        let c3 = self.stack.get(11);
        let d0 = self.stack.get(12);
        let d1 = self.stack.get(13);
        let d2 = self.stack.get(14);
        let d3 = self.stack.get(15);

        self.stack.set(0, d0);
        self.stack.set(1, d1);
        self.stack.set(2, d2);
        self.stack.set(3, d3);
        self.stack.set(4, b0);
        self.stack.set(5, b1);
        self.stack.set(6, b2);
        self.stack.set(7, b3);
        self.stack.set(8, c0);
        self.stack.set(9, c1);
        self.stack.set(10, c2);
        self.stack.set(11, c3);
        self.stack.set(12, a0);
        self.stack.set(13, a1);
        self.stack.set(14, a2);
        self.stack.set(15, a3);

        // this is needed to ensure stack helper registers are copied over correctly
        self.stack.copy_state(16);

        Ok(())
    }

    /// Swaps the top two words pair wise.
    ///
    /// Input: [D, C, B, A, ...]
    /// Output: [B, A, D, C, ...]
    pub(super) fn op_swapdw(&mut self) -> Result<(), ExecutionError> {
        let a0 = self.stack.get(0);
        let a1 = self.stack.get(1);
        let a2 = self.stack.get(2);
        let a3 = self.stack.get(3);
        let b0 = self.stack.get(4);
        let b1 = self.stack.get(5);
        let b2 = self.stack.get(6);
        let b3 = self.stack.get(7);
        let c0 = self.stack.get(8);
        let c1 = self.stack.get(9);
        let c2 = self.stack.get(10);
        let c3 = self.stack.get(11);
        let d0 = self.stack.get(12);
        let d1 = self.stack.get(13);
        let d2 = self.stack.get(14);
        let d3 = self.stack.get(15);

        self.stack.set(0, c0);
        self.stack.set(1, c1);
        self.stack.set(2, c2);
        self.stack.set(3, c3);
        self.stack.set(4, d0);
        self.stack.set(5, d1);
        self.stack.set(6, d2);
        self.stack.set(7, d3);
        self.stack.set(8, a0);
        self.stack.set(9, a1);
        self.stack.set(10, a2);
        self.stack.set(11, a3);
        self.stack.set(12, b0);
        self.stack.set(13, b1);
        self.stack.set(14, b2);
        self.stack.set(15, b3);

        // this is needed to ensure stack helper registers are copied over correctly
        self.stack.copy_state(16);

        Ok(())
    }

    /// Moves n-th element to the top of the stack. n is 0-based.
    ///
    /// Elements between 0 and n are shifted right by one slot.
    pub(super) fn op_movup(&mut self, n: usize) -> Result<(), ExecutionError> {
        debug_assert!(n < MIN_STACK_DEPTH - 1, "n too large");

        // move the nth value to the top of the stack
        let value = self.stack.get(n);
        self.stack.set(0, value);

        // shift all values up to n by one slot to the right
        for i in 0..n {
            let value = self.stack.get(i);
            self.stack.set(i + 1, value);
        }

        // all other items on the stack remain in place
        self.stack.copy_state(n + 1);
        Ok(())
    }

    /// Moves element 0 to the n-th position on the stack. n is 0-based.
    ///
    /// Elements between 0 and n are shifted left by one slot.
    pub(super) fn op_movdn(&mut self, n: usize) -> Result<(), ExecutionError> {
        debug_assert!(n < MIN_STACK_DEPTH - 1, "n too large");

        // move the value at the top of the stack to the nth position
        let value = self.stack.get(0);
        self.stack.set(n, value);

        // shift all values up to n by one slot to the left
        for i in 0..n {
            let value = self.stack.get(i + 1);
            self.stack.set(i, value);
        }

        // all other items on the stack remain in place
        self.stack.copy_state(n + 1);
        Ok(())
    }

    // CONDITIONAL MANIPULATION
    // --------------------------------------------------------------------------------------------

    /// Pops an element off the stack, and if the element is 1, swaps the top two elements on the
    /// stack. If the popped element is 0, the stack remains unchanged.
    ///
    /// # Errors
    /// Returns an error if the top element of the stack is neither 0 nor 1.
    pub(super) fn op_cswap(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let c = self.stack.get(0);
        let b = self.stack.get(1);
        let a = self.stack.get(2);

        match c.as_int() {
            0 => {
                self.stack.set(0, b);
                self.stack.set(1, a);
            },
            1 => {
                self.stack.set(0, a);
                self.stack.set(1, b);
            },
            _ => return Err(ExecutionError::not_binary_value_op(c, err_ctx)),
        }

        self.stack.shift_left(3);
        Ok(())
    }

    /// Pops an element off the stack, and if the element is 1, swaps elements 0, 1, 2, and 3 with
    /// elements 4, 5, 6, and 7. If the popped element is 0, the stack remains unchanged.
    ///
    /// # Errors
    /// Returns an error if the top element of the stack is neither 0 nor 1.
    pub(super) fn op_cswapw(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let c = self.stack.get(0);
        let b0 = self.stack.get(1);
        let b1 = self.stack.get(2);
        let b2 = self.stack.get(3);
        let b3 = self.stack.get(4);
        let a0 = self.stack.get(5);
        let a1 = self.stack.get(6);
        let a2 = self.stack.get(7);
        let a3 = self.stack.get(8);

        match c.as_int() {
            0 => {
                self.stack.set(0, b0);
                self.stack.set(1, b1);
                self.stack.set(2, b2);
                self.stack.set(3, b3);
                self.stack.set(4, a0);
                self.stack.set(5, a1);
                self.stack.set(6, a2);
                self.stack.set(7, a3);
            },
            1 => {
                self.stack.set(0, a0);
                self.stack.set(1, a1);
                self.stack.set(2, a2);
                self.stack.set(3, a3);
                self.stack.set(4, b0);
                self.stack.set(5, b1);
                self.stack.set(6, b2);
                self.stack.set(7, b3);
            },
            _ => return Err(ExecutionError::not_binary_value_op(c, err_ctx)),
        }

        self.stack.shift_left(9);
        Ok(())
    }
}
