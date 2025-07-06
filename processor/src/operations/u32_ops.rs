use super::{
    super::utils::{split_element, split_u32_into_u16},
    ExecutionError, Felt, FieldElement, Operation, Process,
};
use crate::{ErrorContext, ZERO};

const U32_MAX: u64 = u32::MAX as u64;

macro_rules! require_u32_operand {
    ($stack:expr, $idx:literal, $err_ctx:expr) => {
        require_u32_operand!($stack, $idx, ZERO, $err_ctx)
    };

    ($stack:expr, $idx:literal, $errno:expr, $err_ctx:expr) => {{
        let operand = $stack.get($idx);
        if operand.as_int() > U32_MAX {
            return Err(ExecutionError::not_u32_value(operand, $errno, $err_ctx));
        }
        operand
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
        let b = require_u32_operand!(self.stack, 0, err_code, err_ctx);
        let a = require_u32_operand!(self.stack, 1, err_code, err_ctx);

        self.add_range_checks(Operation::U32assert2(err_code), a, b, false);

        self.stack.copy_state(0);
        Ok(())
    }

    // ARITHMETIC OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Pops two elements off the stack, adds them, splits the result into low and high 32-bit
    /// values, and pushes these values back onto the stack.
    pub(super) fn op_u32add(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let b = require_u32_operand!(self.stack, 0, err_ctx).as_int();
        let a = require_u32_operand!(self.stack, 1, err_ctx).as_int();

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
        let c = require_u32_operand!(self.stack, 0, err_ctx).as_int();
        let b = require_u32_operand!(self.stack, 1, err_ctx).as_int();
        let a = require_u32_operand!(self.stack, 2, err_ctx).as_int();
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
        let b = require_u32_operand!(self.stack, 0, err_ctx).as_int();
        let a = require_u32_operand!(self.stack, 1, err_ctx).as_int();
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
        let b = require_u32_operand!(self.stack, 0, err_ctx).as_int();
        let a = require_u32_operand!(self.stack, 1, err_ctx).as_int();
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
        let b = require_u32_operand!(self.stack, 0, err_ctx).as_int();
        let a = require_u32_operand!(self.stack, 1, err_ctx).as_int();
        let c = require_u32_operand!(self.stack, 2, err_ctx).as_int();
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
        let b = require_u32_operand!(self.stack, 0, err_ctx).as_int();
        let a = require_u32_operand!(self.stack, 1, err_ctx).as_int();

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
        let b = require_u32_operand!(self.stack, 0, err_ctx);
        let a = require_u32_operand!(self.stack, 1, err_ctx);
        let result = self.chiplets.bitwise.u32and(a, b, err_ctx)?;

        self.stack.set(0, result);
        self.stack.shift_left(2);

        Ok(())
    }

    /// Pops two elements off the stack, computes their bitwise XOR, and pushes the result back onto
    /// the stack.
    pub(super) fn op_u32xor(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let b = require_u32_operand!(self.stack, 0, err_ctx);
        let a = require_u32_operand!(self.stack, 1, err_ctx);
        let result = self.chiplets.bitwise.u32xor(a, b, err_ctx)?;

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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_air::trace::decoder::NUM_USER_OP_HELPERS;
    use miden_core::{mast::MastForest, stack::MIN_STACK_DEPTH};
    use miden_test_utils::rand::rand_value;

    use super::{
        super::{Felt, Operation},
        Process, split_u32_into_u16,
    };
    use crate::{DefaultHost, StackInputs, ZERO};

    // CASTING OPERATIONS
    // --------------------------------------------------------------------------------------------

    #[test]
    fn op_u32split() {
        // --- test a random value ---------------------------------------------
        let mut host = DefaultHost::default();
        let program = &MastForest::default();

        let a: u64 = rand_value();
        let stack = StackInputs::try_from_ints([a]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let hi = a >> 32;
        let lo = (a as u32) as u64;

        process.execute_op(Operation::U32split, program, &mut host).unwrap();
        let mut expected = [ZERO; 16];
        expected[0] = Felt::new(hi);
        expected[1] = Felt::new(lo);
        assert_eq!(expected, process.stack.trace_state());

        // --- test the rest of the stack is not modified -----------------------
        let b: u64 = rand_value();
        let stack = StackInputs::try_from_ints([a, b]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let hi = b >> 32;
        let lo = (b as u32) as u64;

        process.execute_op(Operation::U32split, program, &mut host).unwrap();
        let mut expected = [ZERO; 16];
        expected[0] = Felt::new(hi);
        expected[1] = Felt::new(lo);
        expected[2] = Felt::new(a);
        assert_eq!(expected, process.stack.trace_state());
    }

    #[test]
    fn op_u32assert2() {
        // --- test random values ensuring other elements are still values are still intact -------
        let mut host = DefaultHost::default();
        let program = &MastForest::default();

        let (a, b, c, d) = get_rand_values();
        let stack = StackInputs::try_from_ints([d as u64, c as u64, b as u64, a as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);

        process.execute_op(Operation::U32assert2(ZERO), program, &mut host).unwrap();
        let expected = build_expected(&[a, b, c, d]);
        assert_eq!(expected, process.stack.trace_state());
    }

    // ARITHMETIC OPERATIONS
    // --------------------------------------------------------------------------------------------

    #[test]
    fn op_u32add() {
        // --- test random values ---------------------------------------------
        let mut host = DefaultHost::default();
        let (a, b, c, d) = get_rand_values();
        let stack = StackInputs::try_from_ints([d as u64, c as u64, b as u64, a as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let program = &MastForest::default();

        let (result, over) = a.overflowing_add(b);

        process.execute_op(Operation::U32add, program, &mut host).unwrap();
        let expected = build_expected(&[over as u32, result, c, d]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test overflow --------------------------------------------------
        let a = u32::MAX - 1;
        let b = 2u32;

        let stack = StackInputs::try_from_ints([a as u64, b as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let (result, over) = a.overflowing_add(b);
        let (b1, b0) = split_u32_into_u16(result.into());

        process.execute_op(Operation::U32add, program, &mut host).unwrap();
        let expected = build_expected(&[over as u32, result]);
        assert_eq!(expected, process.stack.trace_state());

        let expected_helper_registers =
            build_expected_helper_registers(&[b0 as u32, b1 as u32, over as u32]);
        assert_eq!(expected_helper_registers, process.decoder.get_user_op_helpers());
    }

    #[test]
    fn op_u32add3() {
        let mut host = DefaultHost::default();
        let a = rand_value::<u32>() as u64;
        let b = rand_value::<u32>() as u64;
        let c = rand_value::<u32>() as u64;
        let d = rand_value::<u32>() as u64;

        let stack = StackInputs::try_from_ints([d, c, b, a]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let program = &MastForest::default();

        let result = a + b + c;
        let hi = (result >> 32) as u32;
        let lo = result as u32;
        assert!(hi <= 2);

        process.execute_op(Operation::U32add3, program, &mut host).unwrap();
        let expected = build_expected(&[hi, lo, d as u32]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test with minimum stack depth ----------------------------------
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();
        assert!(process.execute_op(Operation::U32add3, program, &mut host).is_ok());
    }

    #[test]
    fn op_u32sub() {
        // --- test random values ---------------------------------------------
        let mut host = DefaultHost::default();
        let program = &MastForest::default();

        let (a, b, c, d) = get_rand_values();
        let stack = StackInputs::try_from_ints([d as u64, c as u64, b as u64, a as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let (result, under) = b.overflowing_sub(a);

        process.execute_op(Operation::U32sub, program, &mut host).unwrap();
        let expected = build_expected(&[under as u32, result, c, d]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test underflow -------------------------------------------------
        let a = 10u32;
        let b = 11u32;

        let stack = StackInputs::try_from_ints([a as u64, b as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let (result, under) = a.overflowing_sub(b);

        process.execute_op(Operation::U32sub, program, &mut host).unwrap();
        let expected = build_expected(&[under as u32, result]);
        assert_eq!(expected, process.stack.trace_state());
    }

    #[test]
    fn op_u32mul() {
        let mut host = DefaultHost::default();
        let program = &MastForest::default();

        let (a, b, c, d) = get_rand_values();
        let stack = StackInputs::try_from_ints([d as u64, c as u64, b as u64, a as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let result = (a as u64) * (b as u64);
        let hi = (result >> 32) as u32;
        let lo = result as u32;

        process.execute_op(Operation::U32mul, program, &mut host).unwrap();
        let expected = build_expected(&[hi, lo, c, d]);
        assert_eq!(expected, process.stack.trace_state());
    }

    #[test]
    fn op_u32madd() {
        let mut host = DefaultHost::default();
        let program = &MastForest::default();

        let (a, b, c, d) = get_rand_values();
        let stack = StackInputs::try_from_ints([d as u64, c as u64, b as u64, a as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let result = (a as u64) * (b as u64) + (c as u64);
        let hi = (result >> 32) as u32;
        let lo = result as u32;

        process.execute_op(Operation::U32madd, program, &mut host).unwrap();
        let expected = build_expected(&[hi, lo, d]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test with minimum stack depth ----------------------------------
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();
        assert!(process.execute_op(Operation::U32madd, program, &mut host).is_ok());
    }

    #[test]
    fn op_u32div() {
        let mut host = DefaultHost::default();
        let program = &MastForest::default();

        let (a, b, c, d) = get_rand_values();
        let stack = StackInputs::try_from_ints([d as u64, c as u64, b as u64, a as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let q = b / a;
        let r = b % a;

        process.execute_op(Operation::U32div, program, &mut host).unwrap();
        let expected = build_expected(&[r, q, c, d]);
        assert_eq!(expected, process.stack.trace_state());
    }

    // BITWISE OPERATIONS
    // --------------------------------------------------------------------------------------------

    #[test]
    fn op_u32and() {
        let mut host = DefaultHost::default();
        let (a, b, c, d) = get_rand_values();
        let stack = StackInputs::try_from_ints([d as u64, c as u64, b as u64, a as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let program = &MastForest::default();

        process.execute_op(Operation::U32and, program, &mut host).unwrap();
        let expected = build_expected(&[a & b, c, d]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test with minimum stack depth ----------------------------------
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();
        assert!(process.execute_op(Operation::U32and, program, &mut host).is_ok());
    }

    #[test]
    fn op_u32xor() {
        let mut host = DefaultHost::default();
        let (a, b, c, d) = get_rand_values();
        let stack = StackInputs::try_from_ints([d as u64, c as u64, b as u64, a as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let program = &MastForest::default();

        process.execute_op(Operation::U32xor, program, &mut host).unwrap();
        let expected = build_expected(&[a ^ b, c, d]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test with minimum stack depth ----------------------------------
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();
        assert!(process.execute_op(Operation::U32xor, program, &mut host).is_ok());
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    fn get_rand_values() -> (u32, u32, u32, u32) {
        let a = rand_value::<u64>() as u32;
        let b = rand_value::<u64>() as u32;
        let c = rand_value::<u64>() as u32;
        let d = rand_value::<u64>() as u32;
        (d, c, b, a)
    }

    fn build_expected(values: &[u32]) -> [Felt; MIN_STACK_DEPTH] {
        let mut expected = [ZERO; MIN_STACK_DEPTH];
        for (&value, result) in values.iter().zip(expected.iter_mut()) {
            *result = Felt::new(value as u64);
        }
        expected
    }

    fn build_expected_helper_registers(values: &[u32]) -> [Felt; NUM_USER_OP_HELPERS] {
        let mut expected = [ZERO; NUM_USER_OP_HELPERS];
        for (&value, result) in values.iter().zip(expected.iter_mut()) {
            *result = Felt::new(value as u64);
        }
        expected
    }
}
