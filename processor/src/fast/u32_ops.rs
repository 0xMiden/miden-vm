use vm_core::{Felt, ZERO};

use super::FastProcessor;
use crate::{ExecutionError, utils::split_element};

impl FastProcessor {
    /// Analogous to `Process::op_u32split`.
    pub fn op_u32split(&mut self) -> Result<(), ExecutionError> {
        let top = self.stack_get(0);
        let (hi, lo) = split_element(top);

        self.increment_stack_size();
        self.stack_write(0, hi);
        self.stack_write(1, lo);

        Ok(())
    }

    /// Analogous to `Process::op_u32add`.
    pub fn op_u32add(&mut self) -> Result<(), ExecutionError> {
        self.u32_pop2_applyfn_push_lowhigh(|a, b| a + b)
    }

    /// Analogous to `Process::op_u32add3`.
    ///
    /// Pops three elements off the stack, adds them, splits the result into low and high 32-bit
    /// values, and pushes these values back onto the stack.
    ///
    /// The size of the stack is decremented by 1.
    pub fn op_u32add3(&mut self) -> Result<(), ExecutionError> {
        let (sum_hi, sum_lo) = {
            let c = self.stack[self.stack_top_idx - 1].as_int();
            let b = self.stack[self.stack_top_idx - 2].as_int();
            let a = self.stack[self.stack_top_idx - 3].as_int();

            // Check that a, b, and c are u32 values.
            if a > u32::MAX as u64 {
                return Err(ExecutionError::NotU32Value(Felt::new(a), ZERO));
            }
            if b > u32::MAX as u64 {
                return Err(ExecutionError::NotU32Value(Felt::new(b), ZERO));
            }
            if c > u32::MAX as u64 {
                return Err(ExecutionError::NotU32Value(Felt::new(c), ZERO));
            }
            let result = Felt::new(a + b + c);
            split_element(result)
        };

        // write the high 32 bits to the new top of the stack, and low 32 bits after
        self.stack[self.stack_top_idx - 2] = sum_hi;
        self.stack[self.stack_top_idx - 3] = sum_lo;

        self.decrement_stack_size();
        Ok(())
    }

    /// Analogous to `Process::op_u32sub`.
    pub fn op_u32sub(&mut self, op_idx: usize) -> Result<(), ExecutionError> {
        self.u32_pop2_applyfn_push_results(op_idx as u32, |first_old, second_old| {
            let result = second_old.wrapping_sub(first_old);
            let first_new = result >> 63;
            let second_new = result & u32::MAX as u64;

            Ok((first_new, second_new))
        })
    }

    /// Analogous to `Process::op_u32mul`.
    pub fn op_u32mul(&mut self) -> Result<(), ExecutionError> {
        self.u32_pop2_applyfn_push_lowhigh(|a, b| a * b)
    }

    /// Analogous to `Process::op_u32madd`.
    ///
    /// Pops three elements off the stack, multiplies the first two and adds the third element to
    /// the result, splits the result into low and high 32-bit values, and pushes these values
    /// back onto the stack.
    pub fn op_u32madd(&mut self) -> Result<(), ExecutionError> {
        let (result_hi, result_lo) = {
            let b = self.stack_get(0).as_int();
            let a = self.stack_get(1).as_int();
            let c = self.stack_get(2).as_int();

            // Check that a, b, and c are u32 values.
            if b > u32::MAX as u64 {
                return Err(ExecutionError::NotU32Value(Felt::new(a), ZERO));
            }
            if a > u32::MAX as u64 {
                return Err(ExecutionError::NotU32Value(Felt::new(b), ZERO));
            }
            if c > u32::MAX as u64 {
                return Err(ExecutionError::NotU32Value(Felt::new(c), ZERO));
            }
            let result = Felt::new(a * b + c);
            split_element(result)
        };

        // write the high 32 bits to the new top of the stack, and low 32 bits after
        self.decrement_stack_size();
        self.stack_write(0, result_hi);
        self.stack_write(1, result_lo);
        Ok(())
    }

    /// Analogous to `Process::op_u32div`.
    pub fn op_u32div(&mut self, op_idx: usize) -> Result<(), ExecutionError> {
        let clk = self.clk + op_idx;
        self.u32_pop2_applyfn_push_results(0, |first, second| {
            if first == 0 {
                return Err(ExecutionError::DivideByZero(clk));
            }

            // a/b = n*q + r for some n>=0 and 0<=r<b
            let q = second / first;
            let r = second - q * first;

            // r is placed on top of the stack, followed by q
            Ok((r, q))
        })
    }

    /// Analogous to `Process::op_u32and`.
    pub fn op_u32and(&mut self) -> Result<(), ExecutionError> {
        self.u32_pop2_applyfn_push(|a, b| a & b)
    }

    /// Analogous to `Process::op_u32xor`.
    pub fn op_u32xor(&mut self) -> Result<(), ExecutionError> {
        self.u32_pop2_applyfn_push(|a, b| a ^ b)
    }

    /// Analogous to `Process::op_u32assert2`.
    pub fn op_u32assert2(&mut self, err_code: u32) -> Result<(), ExecutionError> {
        self.u32_pop2_applyfn_push_results(err_code, |first, second| Ok((first, second)))
    }

    // HELPERS
    // ----------------------------------------------------------------------------------------------

    /// Equivalent to `pop2_applyfn_push`, but for u32 values.
    fn u32_pop2_applyfn_push(
        &mut self,
        f: impl FnOnce(u64, u64) -> u64,
    ) -> Result<(), ExecutionError> {
        let b = self.stack[self.stack_top_idx - 1].as_int();
        let a = self.stack[self.stack_top_idx - 2].as_int();

        // Check that a and b are u32 values.
        if b > u32::MAX as u64 {
            return Err(ExecutionError::NotU32Value(Felt::new(b), ZERO));
        }
        if a > u32::MAX as u64 {
            return Err(ExecutionError::NotU32Value(Felt::new(a), ZERO));
        }

        let result = f(a, b);
        self.decrement_stack_size();
        self.stack_write(0, Felt::new(result));

        Ok(())
    }

    /// Pops 2 elements from the stack, applies the given function to them, and pushes the low/high
    /// u32 values of the result back onto the stack.
    ///
    /// Specifically, this function
    /// 1. pops the top two elements from the stack,
    /// 2. applies the given function to them,
    /// 3. splits the result into low/high u32 values, and
    /// 4. pushes the low/high values back onto the stack.
    ///
    /// The size of the stack doesn't change.
    #[inline(always)]
    fn u32_pop2_applyfn_push_lowhigh(
        &mut self,
        f: impl FnOnce(u64, u64) -> u64,
    ) -> Result<(), ExecutionError> {
        let b = self.stack_get(0).as_int();
        let a = self.stack_get(1).as_int();

        // Check that a and b are u32 values.
        if a > u32::MAX as u64 {
            return Err(ExecutionError::NotU32Value(Felt::new(a), ZERO));
        }
        if b > u32::MAX as u64 {
            return Err(ExecutionError::NotU32Value(Felt::new(b), ZERO));
        }

        let result = Felt::new(f(a, b));
        let (hi, lo) = split_element(result);

        self.stack_write(0, hi);
        self.stack_write(1, lo);
        Ok(())
    }

    /// Pops 2 elements from the stack, applies the given function to them, and pushes the resulting
    /// 2 u32 values back onto the stack.
    ///
    /// The size of the stack doesn't change.
    #[inline(always)]
    fn u32_pop2_applyfn_push_results(
        &mut self,
        err_code: u32,
        f: impl FnOnce(u64, u64) -> Result<(u64, u64), ExecutionError>,
    ) -> Result<(), ExecutionError> {
        let first_old = self.stack_get(0).as_int();
        let second_old = self.stack_get(1).as_int();

        // Check that a and b are u32 values.
        if first_old > u32::MAX as u64 {
            return Err(ExecutionError::NotU32Value(Felt::new(first_old), Felt::from(err_code)));
        }
        if second_old > u32::MAX as u64 {
            return Err(ExecutionError::NotU32Value(Felt::new(second_old), Felt::from(err_code)));
        }

        let (first_new, second_new) = f(first_old, second_old)?;

        self.stack_write(0, Felt::new(first_new));
        self.stack_write(1, Felt::new(second_new));
        Ok(())
    }
}
