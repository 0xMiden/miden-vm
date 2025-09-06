use alloc::vec::Vec;

use miden_core::{Felt, ZERO};
use paste::paste;

use crate::{
    ErrorContext, ExecutionError,
    fast::{FastProcessor, Tracer},
    utils::split_element,
};

const U32_MAX: u64 = u32::MAX as u64;

macro_rules! require_u32_operands {
    ($processor:expr, [$($idx:expr),*], $err_ctx:expr) => {
        require_u32_operands!($processor, [$($idx),*], ZERO, $err_ctx)
    };
    ($processor:expr, [$($idx:expr),*], $errno:expr, $err_ctx:expr) => {{
        let mut invalid_values = Vec::new();

        paste!{
            $(
                let [<operand_ $idx>] = $processor.stack_get($idx);
                if [<operand_ $idx>].as_int() > U32_MAX {
                    invalid_values.push([<operand_ $idx>]);
                }
            )*

            if !invalid_values.is_empty() {
                return Err(ExecutionError::not_u32_values(invalid_values, $errno, $err_ctx));
            }
            // Return tuple of operands based on indices
            ($([<operand_ $idx>].as_int()),*)
        }
    }};
}

impl FastProcessor {
    /// Analogous to `Process::op_u32split`.
    #[inline(always)]
    pub fn op_u32split(&mut self, tracer: &mut impl Tracer) {
        let top = self.stack_get(0);
        let (hi, lo) = split_element(top);

        self.increment_stack_size(tracer);
        self.stack_write(0, hi);
        self.stack_write(1, lo);
    }

    /// Analogous to `Process::op_u32add`.
    pub fn op_u32add(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        self.u32_pop2_applyfn_push_lowhigh(|a, b| a + b, err_ctx)
    }

    /// Analogous to `Process::op_u32add3`.
    ///
    /// Pops three elements off the stack, adds them, splits the result into low and high 32-bit
    /// values, and pushes these values back onto the stack.
    ///
    /// The size of the stack is decremented by 1.
    #[inline(always)]
    pub fn op_u32add3(
        &mut self,
        err_ctx: &impl ErrorContext,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        let (c, b, a) = require_u32_operands!(self, [0, 1, 2], err_ctx);

        let result = Felt::new(a + b + c);
        let (sum_hi, sum_lo) = split_element(result);

        // write the high 32 bits to the new top of the stack, and low 32 bits after
        self.decrement_stack_size(tracer);
        self.stack_write(0, sum_hi);
        self.stack_write(1, sum_lo);
        Ok(())
    }

    /// Analogous to `Process::op_u32sub`.
    #[inline(always)]
    pub fn op_u32sub(
        &mut self,
        op_idx: usize,
        err_ctx: &impl ErrorContext,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        let op_idx = Felt::from(op_idx as u32);
        self.u32_pop2_applyfn_push_results(
            op_idx,
            |first_old, second_old| {
                let result = second_old.wrapping_sub(first_old);
                let first_new = result >> 63;
                let second_new = result & u32::MAX as u64;

                Ok((first_new, second_new))
            },
            err_ctx,
            tracer,
        )
    }

    /// Analogous to `Process::op_u32mul`.
    pub fn op_u32mul(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        self.u32_pop2_applyfn_push_lowhigh(|a, b| a * b, err_ctx)
    }

    /// Analogous to `Process::op_u32madd`.
    ///
    /// Pops three elements off the stack, multiplies the first two and adds the third element to
    /// the result, splits the result into low and high 32-bit values, and pushes these values
    /// back onto the stack.
    #[inline(always)]
    pub fn op_u32madd(
        &mut self,
        err_ctx: &impl ErrorContext,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        let (b, a, c) = require_u32_operands!(self, [0, 1, 2], err_ctx);

        let result = Felt::new(a * b + c);
        let (result_hi, result_lo) = split_element(result);

        // write the high 32 bits to the new top of the stack, and low 32 bits after
        self.decrement_stack_size(tracer);
        self.stack_write(0, result_hi);
        self.stack_write(1, result_lo);
        Ok(())
    }

    /// Analogous to `Process::op_u32div`.
    #[inline(always)]
    pub fn op_u32div(
        &mut self,
        err_ctx: &impl ErrorContext,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        let clk = self.clk;
        self.u32_pop2_applyfn_push_results(
            ZERO,
            |first, second| {
                if first == 0 {
                    return Err(ExecutionError::divide_by_zero(clk, err_ctx));
                }

                // a/b = n*q + r for some n>=0 and 0<=r<b
                let q = second / first;
                let r = second - q * first;

                // r is placed on top of the stack, followed by q
                Ok((r, q))
            },
            err_ctx,
            tracer,
        )
    }

    /// Analogous to `Process::op_u32and`.
    #[inline(always)]
    pub fn op_u32and(
        &mut self,
        err_ctx: &impl ErrorContext,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        self.u32_pop2_applyfn_push(|a, b| a & b, err_ctx, tracer)
    }

    /// Analogous to `Process::op_u32xor`.
    #[inline(always)]
    pub fn op_u32xor(
        &mut self,
        err_ctx: &impl ErrorContext,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        self.u32_pop2_applyfn_push(|a, b| a ^ b, err_ctx, tracer)
    }

    /// Analogous to `Process::op_u32assert2`.
    #[inline(always)]
    pub fn op_u32assert2(
        &mut self,
        err_code: Felt,
        err_ctx: &impl ErrorContext,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        self.u32_pop2_applyfn_push_results(
            err_code,
            |first, second| Ok((first, second)),
            err_ctx,
            tracer,
        )
    }

    // HELPERS
    // ----------------------------------------------------------------------------------------------

    /// Equivalent to `pop2_applyfn_push`, but for u32 values.
    #[inline(always)]
    fn u32_pop2_applyfn_push(
        &mut self,
        f: impl FnOnce(u64, u64) -> u64,
        err_ctx: &impl ErrorContext,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        let (b, a) = require_u32_operands!(self, [0, 1], err_ctx);

        let result = f(a, b);
        self.decrement_stack_size(tracer);
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
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        let (b, a) = require_u32_operands!(self, [0, 1], err_ctx);

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
        err_code: Felt,
        f: impl FnOnce(u64, u64) -> Result<(u64, u64), ExecutionError>,
        err_ctx: &impl ErrorContext,
        _tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        let (first_old, second_old) = require_u32_operands!(self, [0, 1], err_code, err_ctx);

        let (first_new, second_new) = f(first_old, second_old)?;

        self.stack_write(0, Felt::new(first_new));
        self.stack_write(1, Felt::new(second_new));
        Ok(())
    }
}
