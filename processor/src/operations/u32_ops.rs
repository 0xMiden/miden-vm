use vm_core::{Field, PrimeCharacteristicRing, PrimeField64};

use super::{
    super::utils::{split_element, split_u32_into_u16},
    ExecutionError, Felt, Operation, Process,
};
use crate::ZERO;

const U32_MAX: u64 = u32::MAX as u64;

macro_rules! require_u32_operand {
    ($stack:expr, $idx:literal) => {
        require_u32_operand!($stack, $idx, ZERO)
    };

    ($stack:expr, $idx:literal, $errno:expr) => {{
        let operand = $stack.get($idx);
        if operand.as_canonical_u64() > U32_MAX {
            return Err(ExecutionError::NotU32Value(operand, $errno));
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
    pub(super) fn op_u32assert2(&mut self, err_code: u32) -> Result<(), ExecutionError> {
        let b = require_u32_operand!(self.stack, 0, Felt::from_u32(err_code));
        let a = require_u32_operand!(self.stack, 1, Felt::from_u32(err_code));

        self.add_range_checks(Operation::U32assert2(err_code), a, b, false);

        self.stack.copy_state(0);
        Ok(())
    }

    // ARITHMETIC OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Pops two elements off the stack, adds them, splits the result into low and high 32-bit
    /// values, and pushes these values back onto the stack.
    pub(super) fn op_u32add(&mut self) -> Result<(), ExecutionError> {
        let b = require_u32_operand!(self.stack, 0).as_canonical_u64();
        let a = require_u32_operand!(self.stack, 1).as_canonical_u64();

        let result = Felt::from_u64(a + b);
        let (hi, lo) = split_element(result);
        self.add_range_checks(Operation::U32add, lo, hi, false);

        self.stack.set(0, hi);
        self.stack.set(1, lo);
        self.stack.copy_state(2);
        Ok(())
    }

    /// Pops three elements off the stack, adds them, splits the result into low and high 32-bit
    /// values, and pushes these values back onto the stack.
    pub(super) fn op_u32add3(&mut self) -> Result<(), ExecutionError> {
        let c = require_u32_operand!(self.stack, 0).as_canonical_u64();
        let b = require_u32_operand!(self.stack, 1).as_canonical_u64();
        let a = require_u32_operand!(self.stack, 2).as_canonical_u64();
        let result = Felt::from_u64(a + b + c);
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
    pub(super) fn op_u32sub(&mut self) -> Result<(), ExecutionError> {
        let b = require_u32_operand!(self.stack, 0).as_canonical_u64();
        let a = require_u32_operand!(self.stack, 1).as_canonical_u64();
        let result = a.wrapping_sub(b);
        let d = Felt::from_u64(result >> 63);
        let c = Felt::from_u64(result & U32_MAX);

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
    pub(super) fn op_u32mul(&mut self) -> Result<(), ExecutionError> {
        let b = require_u32_operand!(self.stack, 0).as_canonical_u64();
        let a = require_u32_operand!(self.stack, 1).as_canonical_u64();
        let result = Felt::from_u64(a * b);
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
    pub(super) fn op_u32madd(&mut self) -> Result<(), ExecutionError> {
        let b = require_u32_operand!(self.stack, 0).as_canonical_u64();
        let a = require_u32_operand!(self.stack, 1).as_canonical_u64();
        let c = require_u32_operand!(self.stack, 2).as_canonical_u64();
        let result = Felt::from_u64(a * b + c);
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
    pub(super) fn op_u32div(&mut self) -> Result<(), ExecutionError> {
        let b = require_u32_operand!(self.stack, 0).as_canonical_u64();
        let a = require_u32_operand!(self.stack, 1).as_canonical_u64();

        if b == 0 {
            return Err(ExecutionError::DivideByZero(self.system.clk()));
        }

        let q = a / b;
        let r = a - q * b;

        // These range checks help enforce that q <= a.
        let lo = Felt::from_u64(a - q);
        // These range checks help enforce that r < b.
        let hi = Felt::from_u64(b - r - 1);
        self.add_range_checks(Operation::U32div, lo, hi, false);

        self.stack.set(0, Felt::from_u64(r));
        self.stack.set(1, Felt::from_u64(q));
        self.stack.copy_state(2);
        Ok(())
    }

    // BITWISE OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Pops two elements off the stack, computes their bitwise AND, and pushes the result back
    /// onto the stack.
    pub(super) fn op_u32and(&mut self) -> Result<(), ExecutionError> {
        let b = require_u32_operand!(self.stack, 0);
        let a = require_u32_operand!(self.stack, 1);
        let result = self.chiplets.bitwise.u32and(a, b)?;

        self.stack.set(0, result);
        self.stack.shift_left(2);

        Ok(())
    }

    /// Pops two elements off the stack, computes their bitwise XOR, and pushes the result back onto
    /// the stack.
    pub(super) fn op_u32xor(&mut self) -> Result<(), ExecutionError> {
        let b = require_u32_operand!(self.stack, 0);
        let a = require_u32_operand!(self.stack, 1);
        let result = self.chiplets.bitwise.u32xor(a, b)?;

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
        let (t1, t0) = split_u32_into_u16(lo.as_canonical_u64());
        let (t3, t2) = split_u32_into_u16(hi.as_canonical_u64());

        // add lookup values to the range checker.
        self.range.add_range_checks(self.system.clk(), &[t0, t1, t2, t3]);

        // save the range check lookups to the decoder's user operation helper columns.
        let mut helper_values = [
            Felt::from_u16(t0),
            Felt::from_u16(t1),
            Felt::from_u16(t2),
            Felt::from_u16(t3),
            ZERO,
        ];

        if check_element_validity {
            let m = (Felt::from_u32(u32::MAX) - hi).try_inverse().unwrap_or(ZERO);
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
    use test_utils::rand::rand_value;
    use vm_core::{PrimeCharacteristicRing, stack::MIN_STACK_DEPTH};

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
        let a: u64 = rand_value();
        let stack = StackInputs::try_from_ints([a]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let hi = a >> 32;
        let lo = (a as u32) as u64;

        process.execute_op(Operation::U32split, &mut host).unwrap();
        let mut expected = [ZERO; 16];
        expected[0] = Felt::from_u64(hi);
        expected[1] = Felt::from_u64(lo);
        assert_eq!(expected, process.stack.trace_state());

        // --- test the rest of the stack is not modified -----------------------
        let b: u64 = rand_value();
        let stack = StackInputs::try_from_ints([a, b]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let hi = b >> 32;
        let lo = (b as u32) as u64;

        process.execute_op(Operation::U32split, &mut host).unwrap();
        let mut expected = [ZERO; 16];
        expected[0] = Felt::from_u64(hi);
        expected[1] = Felt::from_u64(lo);
        expected[2] = Felt::from_u64(a);
        assert_eq!(expected, process.stack.trace_state());
    }

    #[test]
    fn op_u32assert2() {
        // --- test random values ensuring other elements are still values are still intact -------
        let mut host = DefaultHost::default();
        let (a, b, c, d) = get_rand_values();
        let stack = StackInputs::try_from_ints([d as u64, c as u64, b as u64, a as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);

        process.execute_op(Operation::U32assert2(0), &mut host).unwrap();
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
        let (result, over) = a.overflowing_add(b);

        process.execute_op(Operation::U32add, &mut host).unwrap();
        let expected = build_expected(&[over as u32, result, c, d]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test overflow --------------------------------------------------
        let a = u32::MAX - 1;
        let b = 2u32;

        let stack = StackInputs::try_from_ints([a as u64, b as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let (result, over) = a.overflowing_add(b);
        let (b1, b0) = split_u32_into_u16(result.into());

        process.execute_op(Operation::U32add, &mut host).unwrap();
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

        let result = a + b + c;
        let hi = (result >> 32) as u32;
        let lo = result as u32;
        assert!(hi <= 2);

        process.execute_op(Operation::U32add3, &mut host).unwrap();
        let expected = build_expected(&[hi, lo, d as u32]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test with minimum stack depth ----------------------------------
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();
        assert!(process.execute_op(Operation::U32add3, &mut host).is_ok());
    }

    #[test]
    fn op_u32sub() {
        // --- test random values ---------------------------------------------
        let mut host = DefaultHost::default();
        let (a, b, c, d) = get_rand_values();
        let stack = StackInputs::try_from_ints([d as u64, c as u64, b as u64, a as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let (result, under) = b.overflowing_sub(a);

        process.execute_op(Operation::U32sub, &mut host).unwrap();
        let expected = build_expected(&[under as u32, result, c, d]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test underflow -------------------------------------------------
        let a = 10u32;
        let b = 11u32;

        let stack = StackInputs::try_from_ints([a as u64, b as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let (result, under) = a.overflowing_sub(b);

        process.execute_op(Operation::U32sub, &mut host).unwrap();
        let expected = build_expected(&[under as u32, result]);
        assert_eq!(expected, process.stack.trace_state());
    }

    #[test]
    fn op_u32mul() {
        let mut host = DefaultHost::default();
        let (a, b, c, d) = get_rand_values();
        let stack = StackInputs::try_from_ints([d as u64, c as u64, b as u64, a as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let result = (a as u64) * (b as u64);
        let hi = (result >> 32) as u32;
        let lo = result as u32;

        process.execute_op(Operation::U32mul, &mut host).unwrap();
        let expected = build_expected(&[hi, lo, c, d]);
        assert_eq!(expected, process.stack.trace_state());
    }

    #[test]
    fn op_u32madd() {
        let mut host = DefaultHost::default();
        let (a, b, c, d) = get_rand_values();
        let stack = StackInputs::try_from_ints([d as u64, c as u64, b as u64, a as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let result = (a as u64) * (b as u64) + (c as u64);
        let hi = (result >> 32) as u32;
        let lo = result as u32;

        process.execute_op(Operation::U32madd, &mut host).unwrap();
        let expected = build_expected(&[hi, lo, d]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test with minimum stack depth ----------------------------------
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();
        assert!(process.execute_op(Operation::U32madd, &mut host).is_ok());
    }

    #[test]
    fn op_u32div() {
        let mut host = DefaultHost::default();
        let (a, b, c, d) = get_rand_values();
        let stack = StackInputs::try_from_ints([d as u64, c as u64, b as u64, a as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let q = b / a;
        let r = b % a;

        process.execute_op(Operation::U32div, &mut host).unwrap();
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

        process.execute_op(Operation::U32and, &mut host).unwrap();
        let expected = build_expected(&[a & b, c, d]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test with minimum stack depth ----------------------------------
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();
        assert!(process.execute_op(Operation::U32and, &mut host).is_ok());
    }

    #[test]
    fn op_u32xor() {
        let mut host = DefaultHost::default();
        let (a, b, c, d) = get_rand_values();
        let stack = StackInputs::try_from_ints([d as u64, c as u64, b as u64, a as u64]).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);

        process.execute_op(Operation::U32xor, &mut host).unwrap();
        let expected = build_expected(&[a ^ b, c, d]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test with minimum stack depth ----------------------------------
        let mut process = Process::new_dummy_with_decoder_helpers_and_empty_stack();
        assert!(process.execute_op(Operation::U32xor, &mut host).is_ok());
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
            *result = Felt::from_u64(value as u64);
        }
        expected
    }

    fn build_expected_helper_registers(values: &[u32]) -> [Felt; NUM_USER_OP_HELPERS] {
        let mut expected = [ZERO; NUM_USER_OP_HELPERS];
        for (&value, result) in values.iter().zip(expected.iter_mut()) {
            *result = Felt::from_u64(value as u64);
        }
        expected
    }
}
