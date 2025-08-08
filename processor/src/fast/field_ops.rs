use miden_core::{Felt, FieldElement, ONE, ZERO};

use super::{ExecutionError, FastProcessor};
use crate::{ErrorContext, operations::utils::assert_binary};

const TWO: Felt = Felt::new(2);

impl FastProcessor {
    /// Analogous to `Process::op_add`.
    pub fn op_add(&mut self) -> Result<(), ExecutionError> {
        self.pop2_applyfn_push(|a, b| Ok(a + b))
    }

    /// Analogous to `Process::op_neg`.
    pub fn op_neg(&mut self) -> Result<(), ExecutionError> {
        let element = self.stack_get(0);
        self.stack_write(0, -element);
        Ok(())
    }

    /// Analogous to `Process::op_mul`.
    pub fn op_mul(&mut self) -> Result<(), ExecutionError> {
        self.pop2_applyfn_push(|a, b| Ok(a * b))
    }

    /// Analogous to `Process::op_inv`.
    #[inline(always)]
    pub fn op_inv(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let top = self.stack_get_mut(0);
        if (*top) == ZERO {
            return Err(ExecutionError::divide_by_zero(self.clk, err_ctx));
        }
        *top = top.inv();
        Ok(())
    }

    /// Analogous to `Process::op_inc`.
    pub fn op_incr(&mut self) -> Result<(), ExecutionError> {
        *self.stack_get_mut(0) += ONE;
        Ok(())
    }

    /// Analogous to `Process::op_and`.
    #[inline(always)]
    pub fn op_and(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        self.pop2_applyfn_push(|a, b| {
            assert_binary(b, err_ctx)?;
            assert_binary(a, err_ctx)?;

            if a == ONE && b == ONE { Ok(ONE) } else { Ok(ZERO) }
        })
    }

    /// Analogous to `Process::op_or`.
    #[inline(always)]
    pub fn op_or(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        self.pop2_applyfn_push(|a, b| {
            assert_binary(b, err_ctx)?;
            assert_binary(a, err_ctx)?;

            if a == ONE || b == ONE { Ok(ONE) } else { Ok(ZERO) }
        })
    }

    /// Analogous to `Process::op_not`.
    #[inline(always)]
    pub fn op_not(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let top = self.stack_get_mut(0);
        if *top == ZERO {
            *top = ONE;
        } else if *top == ONE {
            *top = ZERO;
        } else {
            return Err(ExecutionError::not_binary_value_op(*top, err_ctx));
        }
        Ok(())
    }

    /// Analogous to `Process::op_eq`.
    pub fn op_eq(&mut self) -> Result<(), ExecutionError> {
        self.pop2_applyfn_push(|a, b| if a == b { Ok(ONE) } else { Ok(ZERO) })
    }

    /// Analogous to `Process::op_eqz`.
    pub fn op_eqz(&mut self) -> Result<(), ExecutionError> {
        let top = self.stack_get_mut(0);
        if (*top) == ZERO {
            *top = ONE;
        } else {
            *top = ZERO;
        }
        Ok(())
    }

    /// Analogous to `Process::op_expacc`.
    pub fn op_expacc(&mut self) {
        let old_base = self.stack_get(1);
        let old_acc = self.stack_get(2);
        let old_exp_int = self.stack_get(3).as_int();

        // Compute new exponent.
        let new_exp = Felt::new(old_exp_int >> 1);

        // Compute new accumulator. We update the accumulator only when the least significant bit of
        // the exponent is 1.
        let exp_lsb = old_exp_int & 1;
        let acc_update_val = if exp_lsb == 1 { old_base } else { ONE };
        let new_acc = old_acc * acc_update_val;

        // Compute the new base.
        let new_base = old_base * old_base;

        self.stack_write(0, Felt::new(exp_lsb));
        self.stack_write(1, new_base);
        self.stack_write(2, new_acc);
        self.stack_write(3, new_exp);
    }

    /// Analogous to `Process::op_ext2mul`.
    ///
    /// Gets the top four values from the stack [b1, b0, a1, a0], where a = (a1, a0) and
    /// b = (b1, b0) are elements of the extension field, and outputs the product c = (c1, c0)
    /// where c0 = b0 * a0 - 2 * b1 * a1 and c1 = (b0 + b1) * (a1 + a0) - b0 * a0. It pushes 0 to
    /// the first and second positions on the stack, c1 and c2 to the third and fourth positions,
    /// and leaves the rest of the stack unchanged.
    pub fn op_ext2mul(&mut self) {
        let [a0, a1, b0, b1] = self.stack_get_word(0).into();

        /* top 2 elements remain unchanged */

        let b0_times_a0 = b0 * a0;
        self.stack_write(2, (b0 + b1) * (a1 + a0) - b0_times_a0);
        self.stack_write(3, b0_times_a0 - TWO * b1 * a1);
    }

    // HELPERS
    // ----------------------------------------------------------------------------------------------

    /// Pops the top two elements from the stack, applies the given function to them, and pushes the
    /// result back onto the stack.
    ///
    /// The size of the stack is decremented by 1.
    #[inline(always)]
    fn pop2_applyfn_push(
        &mut self,
        f: impl FnOnce(Felt, Felt) -> Result<Felt, ExecutionError>,
    ) -> Result<(), ExecutionError> {
        let b = self.stack_get(0);
        let a = self.stack_get(1);

        self.decrement_stack_size();
        self.stack_write(0, f(a, b)?);

        Ok(())
    }
}
