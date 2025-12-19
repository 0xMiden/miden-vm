use alloc::vec::Vec;

use paste::paste;

use super::{
    super::utils::{split_element, split_u32_into_u16},
    ExecutionError, Felt, FieldElement, Operation, Process,
};
use crate::{ErrorContext, ZERO};

const U32_MAX: u64 = u32::MAX as u64;

macro_rules! require_u32_operands {
    ($stack:expr, [$($idx:expr),*], $err_ctx:expr) => {{
        paste!{
            let mut invalid_values = Vec::new();

            $(
                let [<_operand_ $idx>] = $stack.get($idx);
                if [<_operand_ $idx>].as_int() > U32_MAX {
                    invalid_values.push([<_operand_ $idx>]);
                }
            )*

            if !invalid_values.is_empty() {
                return Err(ExecutionError::not_u32_values(invalid_values, $err_ctx));
            }
            // Return tuple of operands based on indices
            ($([<_operand_ $idx>].as_int()),*)
        }
    }};
}

impl Process {
    // CASTING OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Pops the top element off the stack, splits it into low and high 32-bit values, and pushes
    /// these values back onto the stack.
    pub(super) fn op_u32split(&mut self) -> Result<(), ExecutionError> {
        let a = self.stack.get(0);
        let (hi, lo) = split_element(a);

        self.add_range_checks(Operation::U32split, lo, hi, true);

        self.stack.set(0, hi);
        self.stack.set(1, lo);
        self.stack.shift_right(1);
        Ok(())
    }

    /// Pops top two element off the stack, splits them into low and high 32-bit values, checks if
    /// the high values are equal to 0; if they are, puts the original elements back onto the
    /// stack; if they are not, returns an error.
    pub(super) fn op_u32assert2(
        &mut self,
        err_code: Felt,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        let (b, a) = require_u32_operands!(self.stack, [0, 1], err_ctx);

        self.add_range_checks(Operation::U32assert2(err_code), Felt::new(a), Felt::new(b), false);

        self.stack.copy_state(0);
        Ok(())
    }

    // ARITHMETIC OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Pops two elements off the stack, adds them, splits the result into low and high 32-bit
    /// values, and pushes these values back onto the stack.
    pub(super) fn op_u32add(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let (b, a) = require_u32_operands!(self.stack, [0, 1], err_ctx);

        let result = Felt::new(a + b);
        let (hi, lo) = split_element(result);
        self.add_range_checks(Operation::U32add, lo, hi, false);

        self.stack.set(0, hi);
        self.stack.set(1, lo);
        self.stack.copy_state(2);
        Ok(())
    }

    /// Pops three elements off the stack, adds them, splits the result into low and high 32-bit
    /// values, and pushes these values back onto the stack.
    pub(super) fn op_u32add3(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let (c, b, a) = require_u32_operands!(self.stack, [0, 1, 2], err_ctx);
        let result = Felt::new(a + b + c);
        let (hi, lo) = split_element(result);

        self.add_range_checks(Operation::U32add3, lo, hi, false);

        self.stack.set(0, hi);
        self.stack.set(1, lo);
        self.stack.shift_left(3);
        Ok(())
    }

    /// Pops two elements off the stack, subtracts the top element from the second element, and
    /// pushes the result as well as a flag indicating whether there was underflow back onto the
    /// stack.
    pub(super) fn op_u32sub(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let (b, a) = require_u32_operands!(self.stack, [0, 1], err_ctx);
        let result = a.wrapping_sub(b);
        let d = Felt::new(result >> 63);
        let c = Felt::new(result & U32_MAX);

        // Force this operation to consume 4 range checks, even though only `lo` is needed.
        // This is required for making the constraints more uniform and grouping the opcodes of
        // operations requiring range checks under a common degree-4 prefix.
        self.add_range_checks(Operation::U32sub, c, ZERO, false);

        self.stack.set(0, d);
        self.stack.set(1, c);
        self.stack.copy_state(2);
        Ok(())
    }

    /// Pops two elements off the stack, multiplies them, splits the result into low and high
    /// 32-bit values, and pushes these values back onto the stack.
    pub(super) fn op_u32mul(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let (b, a) = require_u32_operands!(self.stack, [0, 1], err_ctx);
        let result = Felt::new(a * b);
        let (hi, lo) = split_element(result);

        self.add_range_checks(Operation::U32mul, lo, hi, true);

        self.stack.set(0, hi);
        self.stack.set(1, lo);
        self.stack.copy_state(2);
        Ok(())
    }

    /// Pops three elements off the stack, multiplies the first two and adds the third element to
    /// the result, splits the result into low and high 32-bit values, and pushes these values
    /// back onto the stack.
    pub(super) fn op_u32madd(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let (b, a, c) = require_u32_operands!(self.stack, [0, 1, 2], err_ctx);
        let result = Felt::new(a * b + c);
        let (hi, lo) = split_element(result);

        self.add_range_checks(Operation::U32madd, lo, hi, true);

        self.stack.set(0, hi);
        self.stack.set(1, lo);
        self.stack.shift_left(3);
        Ok(())
    }

    /// Pops two elements off the stack, divides the second element by the top element, and pushes
    /// the quotient and the remainder back onto the stack.
    ///
    /// # Errors
    /// Returns an error if the divisor is ZERO.
    pub(super) fn op_u32div(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let (b, a) = require_u32_operands!(self.stack, [0, 1], err_ctx);

        if b == 0 {
            return Err(ExecutionError::divide_by_zero(self.system.clk(), err_ctx));
        }

        let q = a / b;
        let r = a - q * b;

        // These range checks help enforce that q <= a.
        let lo = Felt::new(a - q);
        // These range checks help enforce that r < b.
        let hi = Felt::new(b - r - 1);
        self.add_range_checks(Operation::U32div, lo, hi, false);

        self.stack.set(0, Felt::new(r));
        self.stack.set(1, Felt::new(q));
        self.stack.copy_state(2);
        Ok(())
    }

    // BITWISE OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Pops two elements off the stack, computes their bitwise AND, and pushes the result back
    /// onto the stack.
    pub(super) fn op_u32and(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let (b, a) = require_u32_operands!(self.stack, [0, 1], err_ctx);
        let result = self.chiplets.bitwise.u32and(Felt::new(a), Felt::new(b), err_ctx)?;

        self.stack.set(0, result);
        self.stack.shift_left(2);

        Ok(())
    }

    /// Pops two elements off the stack, computes their bitwise XOR, and pushes the result back onto
    /// the stack.
    pub(super) fn op_u32xor(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let (b, a) = require_u32_operands!(self.stack, [0, 1], err_ctx);
        let result = self.chiplets.bitwise.u32xor(Felt::new(a), Felt::new(b), err_ctx)?;

        self.stack.set(0, result);
        self.stack.shift_left(2);

        Ok(())
    }

    /// Adds 16-bit range checks to the RangeChecker for the high and low 16-bit limbs of two field
    /// elements which are assumed to have 32-bit integer values. This results in 4 range checks.
    ///
    /// All range-checked values are added to the decoder to help with constraint evaluation. When
    /// `check_element_validity` is specified, a fifth helper value is added to the decoder trace
    /// with the value of `m`, which is used to enforce the following element validity constraint:
    /// (1 - m * (2^32 - 1 - hi)) * lo = 0
    /// `m` is set to the inverse of (2^32 - 1 - hi) to enforce that hi =/= 2^32 - 1.
    fn add_range_checks(
        &mut self,
        op: Operation,
        lo: Felt,
        hi: Felt,
        check_element_validity: bool,
    ) {
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());

        // add lookup values to the range checker.
        self.range.add_range_checks(self.system.clk(), &[t0, t1, t2, t3]);

        // save the range check lookups to the decoder's user operation helper columns.
        let mut helper_values =
            [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), ZERO];

        if check_element_validity {
            let m = (Felt::from(u32::MAX) - hi).inv();
            helper_values[4] = m;
        }

        self.decoder.set_user_op_helpers(op, &helper_values);
    }
}
