use miden_air::trace::decoder::NUM_USER_OP_HELPERS;
use miden_core::{Felt, FieldElement, ZERO};

use super::CoreTraceFragmentGenerator;
use crate::{
    processor::Processor,
    utils::{split_element, split_u32_into_u16},
};

impl CoreTraceFragmentGenerator {
    /// Pops the top element off the stack, splits it into low and high 32-bit values, and pushes
    /// these values back onto the stack.
    pub fn op_u32split(&mut self) -> [Felt; NUM_USER_OP_HELPERS] {
        let a = self.stack_get(0);
        let (hi, lo) = split_element(a);

        // Update stack
        self.increment_stack_size();
        self.stack_write(0, hi);
        self.stack_write(1, lo);

        // Compute helpers for range checks
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());
        let m = (Felt::from(u32::MAX) - hi).inv();

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), m, ZERO]
    }

    /// Pops two elements off the stack, adds them, splits the result into low and high 32-bit
    /// values, and pushes these values back onto the stack.
    pub fn op_u32add(&mut self) -> [Felt; NUM_USER_OP_HELPERS] {
        let b = self.require_u32_operand(0).as_int();
        let a = self.require_u32_operand(1).as_int();

        // Update stack
        let result = Felt::new(a + b);
        let (hi, lo) = split_element(result);

        self.stack_write(0, hi);
        self.stack_write(1, lo);

        // Compute helpers for range checks
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());

        // For u32add, check_element_validity is false
        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), ZERO, ZERO]
    }

    /// Pops three elements off the stack, adds them, splits the result into low and high 32-bit
    /// values, and pushes these values back onto the stack.
    pub fn op_u32add3(&mut self) -> [Felt; NUM_USER_OP_HELPERS] {
        let c = self.require_u32_operand(0).as_int();
        let b = self.require_u32_operand(1).as_int();
        let a = self.require_u32_operand(2).as_int();

        // Update stack
        let result = Felt::new(a + b + c);
        let (hi, lo) = split_element(result);

        self.decrement_stack_size();
        self.stack_write(0, hi);
        self.stack_write(1, lo);

        // Compute helpers for range checks
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), ZERO, ZERO]
    }

    /// Pops two elements off the stack, subtracts the top element from the second element, and
    /// pushes the result as well as a flag indicating whether there was underflow back onto the
    /// stack.
    pub fn op_u32sub(&mut self, _op_idx: usize) -> [Felt; NUM_USER_OP_HELPERS] {
        let first_old = self.require_u32_operand(0).as_int();
        let second_old = self.require_u32_operand(1).as_int();

        // Update stack
        let result = second_old.wrapping_sub(first_old);
        let first_new = Felt::new(result >> 63);
        let second_new = Felt::new(result & (u32::MAX as u64));

        self.stack_write(0, first_new);
        self.stack_write(1, second_new);

        // Compute helpers for range checks (only `second_new` needs range checking)
        let (t1, t0) = split_u32_into_u16(second_new.as_int());

        [Felt::from(t0), Felt::from(t1), ZERO, ZERO, ZERO, ZERO]
    }

    /// Pops two elements off the stack, multiplies them, splits the result into low and high
    /// 32-bit values, and pushes these values back onto the stack.
    pub fn op_u32mul(&mut self) -> [Felt; NUM_USER_OP_HELPERS] {
        let b = self.require_u32_operand(0).as_int();
        let a = self.require_u32_operand(1).as_int();

        // Update stack
        let result = Felt::new(a * b);
        let (hi, lo) = split_element(result);

        self.stack_write(0, hi);
        self.stack_write(1, lo);

        // Compute helpers for range checks
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());
        let m = (Felt::from(u32::MAX) - hi).inv();

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), m, ZERO]
    }

    /// Pops three elements off the stack, multiplies the first two and adds the third element to
    /// the result, splits the result into low and high 32-bit values, and pushes these values
    /// back onto the stack.
    pub fn op_u32madd(&mut self) -> [Felt; NUM_USER_OP_HELPERS] {
        let b = self.require_u32_operand(0).as_int();
        let a = self.require_u32_operand(1).as_int();
        let c = self.require_u32_operand(2).as_int();

        // Update stack
        let result = Felt::new(a * b + c);
        let (hi, lo) = split_element(result);

        self.decrement_stack_size();
        self.stack_write(0, hi);
        self.stack_write(1, lo);

        // Compute helpers for range checks
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());
        let m = (Felt::from(u32::MAX) - hi).inv();

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), m, ZERO]
    }

    /// Pops two elements off the stack, divides the second element by the top element, and pushes
    /// the quotient and the remainder back onto the stack.
    pub fn op_u32div(&mut self) -> [Felt; NUM_USER_OP_HELPERS] {
        let denominator = self.require_u32_operand(0).as_int();
        let numerator = self.require_u32_operand(1).as_int();

        if denominator == 0 {
            panic!("Division by zero - this should not happen in parallel execution");
        }

        // Update stack
        let quotient = numerator / denominator;
        let remainder = numerator - quotient * denominator;

        self.stack_write(0, Felt::new(remainder));
        self.stack_write(1, Felt::new(quotient));

        // Compute helpers for range checks
        let (t1, t0) = split_u32_into_u16(numerator - quotient);
        let (t3, t2) = split_u32_into_u16(denominator - remainder - 1);

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), ZERO, ZERO]
    }

    /// Pops two elements off the stack, computes their bitwise AND, and pushes the result back
    /// onto the stack.
    pub fn op_u32and(&mut self) {
        let b = self.require_u32_operand(0).as_int();
        let a = self.require_u32_operand(1).as_int();

        let result = a & b;

        // Update stack
        self.decrement_stack_size();
        self.stack_write(0, Felt::new(result));
    }

    /// Pops two elements off the stack, computes their bitwise XOR, and pushes the result back
    /// onto the stack.
    pub fn op_u32xor(&mut self) {
        let b = self.require_u32_operand(0).as_int();
        let a = self.require_u32_operand(1).as_int();

        let result = a ^ b;

        // Update stack
        self.decrement_stack_size();
        self.stack_write(0, Felt::new(result));
    }

    /// Pops top two element off the stack, splits them into low and high 32-bit values, checks if
    /// the high values are equal to 0; if they are, puts the original elements back onto the
    /// stack; if they are not, returns an error.
    pub fn op_u32assert2(&mut self, _err_code: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        let first = self.require_u32_operand(0);
        let second = self.require_u32_operand(1);

        // Stack remains unchanged for assert operations

        // Compute helpers for range checks for both operands
        let (t1, t0) = split_u32_into_u16(second.as_int());
        let (t3, t2) = split_u32_into_u16(first.as_int());

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), ZERO, ZERO]
    }

    /// Helper method to check if a stack operand is a valid u32 value
    #[track_caller]
    fn require_u32_operand(&self, idx: usize) -> Felt {
        let operand = self.stack_get(idx);
        if operand.as_int() > u32::MAX as u64 {
            panic!("u32 operand validation failed - this should not happen in parallel execution")
        }
        operand
    }
}
