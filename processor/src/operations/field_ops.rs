use miden_core::{Field, ONE, Operation, PrimeCharacteristicRing, ZERO};

use super::{ExecutionError, Felt, Process, utils::assert_binary};
use crate::ErrorContext;

// FIELD OPERATIONS
// ================================================================================================

impl Process {
    // ARITHMETIC OPERATIONS
    // --------------------------------------------------------------------------------------------
    /// Pops two elements off the stack, adds them together, and pushes the result back onto the
    /// stack.
    pub(super) fn op_add(&mut self) -> Result<(), ExecutionError> {
        let b = self.stack.get(0);
        let a = self.stack.get(1);
        self.stack.set(0, a + b);
        self.stack.shift_left(2);
        Ok(())
    }

    /// Pops an element off the stack, computes its additive inverse, and pushes the result back
    /// onto the stack.
    pub(super) fn op_neg(&mut self) -> Result<(), ExecutionError> {
        let a = self.stack.get(0);
        self.stack.set(0, -a);
        self.stack.copy_state(1);
        Ok(())
    }

    /// Pops two elements off the stack, multiplies them, and pushes the result back onto the
    /// stack.
    pub(super) fn op_mul(&mut self) -> Result<(), ExecutionError> {
        let b = self.stack.get(0);
        let a = self.stack.get(1);
        self.stack.set(0, a * b);
        self.stack.shift_left(2);
        Ok(())
    }

    /// Pops an element off the stack, computes its multiplicative inverse, and pushes the result
    /// back onto the stack.
    ///
    /// # Errors
    /// Returns an error if the value on the top of the stack is ZERO.
    pub(super) fn op_inv(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let a = self.stack.get(0);
        if a == ZERO {
            return Err(ExecutionError::divide_by_zero(self.system.clk(), err_ctx));
        }

        self.stack.set(0, a.inverse());
        self.stack.copy_state(1);
        Ok(())
    }

    /// Pops an element off the stack, adds ONE to it, and pushes the result back onto the stack.
    pub(super) fn op_incr(&mut self) -> Result<(), ExecutionError> {
        let a = self.stack.get(0);
        self.stack.set(0, a + ONE);
        self.stack.copy_state(1);
        Ok(())
    }

    // BOOLEAN OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Pops two elements off the stack, computes their boolean AND, and pushes the result back
    /// onto the stack.
    ///
    /// # Errors
    /// Returns an error if either of the two elements on the top of the stack is not a binary
    /// value.
    pub(super) fn op_and(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let b = assert_binary(self.stack.get(0), err_ctx)?;
        let a = assert_binary(self.stack.get(1), err_ctx)?;
        if a == ONE && b == ONE {
            self.stack.set(0, ONE);
        } else {
            self.stack.set(0, ZERO);
        }
        self.stack.shift_left(2);
        Ok(())
    }

    /// Pops two elements off the stack, computes their boolean OR, and pushes the result back
    /// onto the stack.
    ///
    /// # Errors
    /// Returns an error if either of the two elements on the top of the stack is not a binary
    /// value.
    pub(super) fn op_or(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let b = assert_binary(self.stack.get(0), err_ctx)?;
        let a = assert_binary(self.stack.get(1), err_ctx)?;
        if a == ONE || b == ONE {
            self.stack.set(0, ONE);
        } else {
            self.stack.set(0, ZERO);
        }
        self.stack.shift_left(2);
        Ok(())
    }

    /// Pops an element off the stack, computes its boolean NOT, and pushes the result back onto
    /// the stack.
    ///
    /// # Errors
    /// Returns an error if the value on the top of the stack is not a binary value.
    pub(super) fn op_not(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let a = assert_binary(self.stack.get(0), err_ctx)?;
        self.stack.set(0, ONE - a);
        self.stack.copy_state(1);
        Ok(())
    }

    // COMPARISON OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Pops two elements off the stack and compares them. If the elements are equal, pushes ONE
    /// onto the stack, otherwise pushes ZERO onto the stack.
    pub(super) fn op_eq(&mut self) -> Result<(), ExecutionError> {
        let b = self.stack.get(0);
        let a = self.stack.get(1);

        // helper variable provided by the prover. If top elements are same, then, it can be set to
        // anything otherwise set it to the reciprocal of the difference between the top two
        // elements.
        let mut h0 = ZERO;

        if a == b {
            self.stack.set(0, ONE);
        } else {
            self.stack.set(0, ZERO);
            // setting h0 to the inverse of the difference between the top two elements of the
            // stack.
            h0 = (b - a).inverse();
        }

        // save h0 in the decoder helper register.
        self.decoder.set_user_op_helpers(Operation::Eq, &[h0]);

        self.stack.shift_left(2);
        Ok(())
    }

    /// Pops an element off the stack and compares it to ZERO. If the element is ZERO, pushes ONE
    /// onto the stack, otherwise pushes ZERO onto the stack.
    pub(super) fn op_eqz(&mut self) -> Result<(), ExecutionError> {
        let a = self.stack.get(0);

        // helper variable provided by the prover. If the top element is zero, then, h0 can be set
        // to anything otherwise set it to the inverse of the top element in the stack.
        let mut h0 = ZERO;

        if a == ZERO {
            self.stack.set(0, ONE);
        } else {
            // setting h0 to the inverse of the top element of the stack.
            h0 = a.inverse();
            self.stack.set(0, ZERO);
        }

        // save h0 in the decoder helper register.
        self.decoder.set_user_op_helpers(Operation::Eq, &[h0]);

        self.stack.copy_state(1);
        Ok(())
    }

    /// Computes a single turn of exp accumulation for the given inputs. The top 4 elements in the
    /// stack are arranged as follows (from the top):
    /// - 0: least significant bit of the exponent in the previous trace if there's an expacc call,
    ///   otherwise ZERO,
    /// - 1: base of the exponentiation; i.e. `b` in `b^a`,
    /// - 2: accumulated result of the exponentiation so far,
    /// - 3: the exponent; i.e. `a` in `b^a`.
    ///
    /// It is expected that `Expacc` is called at least `num_exp_bits` times, where `num_exp_bits`
    /// is the number of bits needed to represent `exp`. The initial call to `Expacc` should set the
    /// stack as [0, base, 1, exponent]. The subsequent call will set the stack either as
    /// - [0, base^2, acc, exp/2], or
    /// - [1, base^2, acc * base, exp/2],
    ///
    /// depending on the least significant bit of the exponent.
    ///
    /// Expacc is based on the observation that the exponentiation of a number can be computed by
    /// repeatedly squaring the base and multiplying those powers of the base by the accumulator,
    /// for the powers of the base which correspond to the exponent's bits which are set to 1.
    ///
    /// For example, take b^5 = (b^2)^2 * b. Over the course of 3 iterations (5 = 101b), the
    /// algorithm will compute b, b^2 and b^4 (placed in `base_acc`). Hence, we want to multiply
    /// `base_acc` in `result_acc` when `base_acc = b` and when `base_acc = b^4`, which occurs on
    /// the first and third iterations (corresponding to the `1` bits in the binary representation
    /// of 5).
    pub(super) fn op_expacc(&mut self) -> Result<(), ExecutionError> {
        let old_base_acc = self.stack.get(1);
        let old_result_acc = self.stack.get(2);
        let old_exp = self.stack.get(3);

        // Compute new exponent.
        let new_exp = Felt::from_u64(old_exp.as_int() >> 1);

        // Compute new accumulator. We update the accumulator only when the least significant bit of
        // the exponent is 1.
        let exp_lsb = old_exp.as_int() & 1;
        let result_acc_update = if exp_lsb == 1 { old_base_acc } else { ONE };
        let new_result_acc = old_result_acc * result_acc_update;

        // Compute the new base.
        let new_base_acc = old_base_acc * old_base_acc;

        // Update the stack with the new values.
        self.stack.set(0, Felt::from_u64(exp_lsb));
        self.stack.set(1, new_base_acc);
        self.stack.set(2, new_result_acc);
        self.stack.set(3, new_exp);
        self.stack.copy_state(4);

        // save value multiplied in the accumulator in the decoder helper register.
        self.decoder.set_user_op_helpers(Operation::Expacc, &[result_acc_update]);

        Ok(())
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::{Field, ONE, PrimeCharacteristicRing, ZERO, mast::MastForest};
    use miden_utils_testing::rand::rand_value;

    use super::{
        super::{Felt, MIN_STACK_DEPTH, Operation},
        Process,
    };
    use crate::{AdviceInputs, DefaultHost, StackInputs};

    // ARITHMETIC OPERATIONS
    // --------------------------------------------------------------------------------------------

    #[test]
    fn op_add() {
        // initialize the stack with a few values
        let (a, b, c) = get_rand_values();
        let stack = StackInputs::try_from_ints([c.as_int(), b.as_int(), a.as_int()]).unwrap();
        let mut process = Process::new_dummy(stack);
        let mut host = DefaultHost::default();
        let program = &MastForest::default();

        // add the top two values
        process.execute_op(Operation::Add, program, &mut host).unwrap();
        let expected = build_expected(&[a + b, c]);

        assert_eq!(MIN_STACK_DEPTH, process.stack.depth());
        assert_eq!(2, process.stack.current_clk());
        assert_eq!(expected, process.stack.trace_state());

        // calling add with a stack of minimum depth is ok
        let mut process = Process::new_dummy_with_empty_stack();
        assert!(process.execute_op(Operation::Add, program, &mut host).is_ok());
    }

    #[test]
    fn op_neg() {
        // initialize the stack with a few values
        let (a, b, c) = get_rand_values();
        let stack = StackInputs::try_from_ints([c.as_int(), b.as_int(), a.as_int()]).unwrap();
        let mut process = Process::new_dummy(stack);
        let mut host = DefaultHost::default();
        let program = &MastForest::default();

        // negate the top value
        process.execute_op(Operation::Neg, program, &mut host).unwrap();
        let expected = build_expected(&[-a, b, c]);

        assert_eq!(expected, process.stack.trace_state());
        assert_eq!(MIN_STACK_DEPTH, process.stack.depth());
        assert_eq!(2, process.stack.current_clk());
    }

    #[test]
    fn op_mul() {
        // initialize the stack with a few values
        let (a, b, c) = get_rand_values();
        let stack = StackInputs::try_from_ints([c.as_int(), b.as_int(), a.as_int()]).unwrap();
        let mut process = Process::new_dummy(stack);
        let mut host = DefaultHost::default();
        let program = &MastForest::default();

        // add the top two values
        process.execute_op(Operation::Mul, program, &mut host).unwrap();
        let expected = build_expected(&[a * b, c]);

        assert_eq!(MIN_STACK_DEPTH, process.stack.depth());
        assert_eq!(2, process.stack.current_clk());
        assert_eq!(expected, process.stack.trace_state());

        // calling mul with a stack of minimum depth is ok
        let mut process = Process::new_dummy_with_empty_stack();
        assert!(process.execute_op(Operation::Mul, program, &mut host).is_ok());
    }

    #[test]
    fn op_inverse() {
        // initialize the stack with a few values
        let (a, b, c) = get_rand_values();
        let stack = StackInputs::try_from_ints([c.as_int(), b.as_int(), a.as_int()]).unwrap();
        let mut process = Process::new_dummy(stack);
        let mut host = DefaultHost::default();
        let program = &MastForest::default();

        // invert the top value
        if b != ZERO {
            process.execute_op(Operation::Inv, program, &mut host).unwrap();
            let expected = build_expected(&[a.inverse(), b, c]);

            assert_eq!(MIN_STACK_DEPTH, process.stack.depth());
            assert_eq!(2, process.stack.current_clk());
            assert_eq!(expected, process.stack.trace_state());
        }

        // inverting zero should be an error
        process.execute_op(Operation::Pad, program, &mut host).unwrap();
        assert!(process.execute_op(Operation::Inv, program, &mut host).is_err());
    }

    #[test]
    fn op_incr() {
        // initialize the stack with a few values
        let (a, b, c) = get_rand_values();
        let stack = StackInputs::try_from_ints([c.as_int(), b.as_int(), a.as_int()]).unwrap();
        let mut process = Process::new_dummy(stack);
        let mut host = DefaultHost::default();
        let program = &MastForest::default();

        // negate the top value
        process.execute_op(Operation::Incr, program, &mut host).unwrap();
        let expected = build_expected(&[a + ONE, b, c]);

        assert_eq!(MIN_STACK_DEPTH, process.stack.depth());
        assert_eq!(2, process.stack.current_clk());
        assert_eq!(expected, process.stack.trace_state());
    }

    // BOOLEAN OPERATIONS
    // --------------------------------------------------------------------------------------------

    #[test]
    fn op_and() {
        let mut host = DefaultHost::default();
        // --- test 0 AND 0 ---------------------------------------------------
        let stack = StackInputs::try_from_ints([2, 0, 0]).unwrap();
        let mut process = Process::new_dummy(stack);
        let program = &MastForest::default();

        process.execute_op(Operation::And, program, &mut host).unwrap();
        let expected = build_expected(&[ZERO, Felt::new(2)]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test 1 AND 0 ---------------------------------------------------
        let stack = StackInputs::try_from_ints([2, 0, 1]).unwrap();
        let mut process = Process::new_dummy(stack);

        process.execute_op(Operation::And, program, &mut host).unwrap();
        let expected = build_expected(&[ZERO, Felt::new(2)]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test 0 AND 1 ---------------------------------------------------
        let stack = StackInputs::try_from_ints([2, 1, 0]).unwrap();
        let mut process = Process::new_dummy(stack);

        process.execute_op(Operation::And, program, &mut host).unwrap();
        let expected = build_expected(&[ZERO, Felt::new(2)]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test 1 AND 1 ---------------------------------------------------
        let stack = StackInputs::try_from_ints([2, 1, 1]).unwrap();
        let mut process = Process::new_dummy(stack);

        process.execute_op(Operation::And, program, &mut host).unwrap();
        let expected = build_expected(&[ONE, Felt::new(2)]);
        assert_eq!(expected, process.stack.trace_state());

        // --- first operand is not binary ------------------------------------
        let stack = StackInputs::try_from_ints([2, 1, 2]).unwrap();
        let mut process = Process::new_dummy(stack);
        assert!(process.execute_op(Operation::And, program, &mut host).is_err());

        // --- second operand is not binary -----------------------------------
        let stack = StackInputs::try_from_ints([2, 2, 1]).unwrap();
        let mut process = Process::new_dummy(stack);
        assert!(process.execute_op(Operation::And, program, &mut host).is_err());

        // --- calling AND with a stack of minimum depth is ok ----------------
        let mut process = Process::new_dummy_with_empty_stack();
        assert!(process.execute_op(Operation::And, program, &mut host).is_ok());
    }

    #[test]
    fn op_or() {
        let mut host = DefaultHost::default();
        // --- test 0 OR 0 ---------------------------------------------------
        let stack = StackInputs::try_from_ints([2, 0, 0]).unwrap();
        let mut process = Process::new_dummy(stack);
        let program = &MastForest::default();

        process.execute_op(Operation::Or, program, &mut host).unwrap();
        let expected = build_expected(&[ZERO, Felt::new(2)]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test 1 OR 0 ---------------------------------------------------
        let stack = StackInputs::try_from_ints([2, 0, 1]).unwrap();
        let mut process = Process::new_dummy(stack);

        process.execute_op(Operation::Or, program, &mut host).unwrap();
        let expected = build_expected(&[ONE, Felt::new(2)]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test 0 OR 1 ---------------------------------------------------
        let stack = StackInputs::try_from_ints([2, 1, 0]).unwrap();
        let mut process = Process::new_dummy(stack);

        process.execute_op(Operation::Or, program, &mut host).unwrap();
        let expected = build_expected(&[ONE, Felt::new(2)]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test 1 OR 0 ---------------------------------------------------
        let stack = StackInputs::try_from_ints([2, 1, 1]).unwrap();
        let mut process = Process::new_dummy(stack);

        process.execute_op(Operation::Or, program, &mut host).unwrap();
        let expected = build_expected(&[ONE, Felt::new(2)]);
        assert_eq!(expected, process.stack.trace_state());

        // --- first operand is not binary ------------------------------------
        let stack = StackInputs::try_from_ints([2, 1, 2]).unwrap();
        let mut process = Process::new_dummy(stack);
        assert!(process.execute_op(Operation::Or, program, &mut host).is_err());

        // --- second operand is not binary -----------------------------------
        let stack = StackInputs::try_from_ints([2, 2, 1]).unwrap();
        let mut process = Process::new_dummy(stack);
        assert!(process.execute_op(Operation::Or, program, &mut host).is_err());

        // --- calling OR with a stack of minimum depth is a ok ----------------
        let mut process = Process::new_dummy_with_empty_stack();
        assert!(process.execute_op(Operation::Or, program, &mut host).is_ok());
    }

    #[test]
    fn op_not() {
        let mut host = DefaultHost::default();
        // --- test NOT 0 -----------------------------------------------------
        let stack = StackInputs::try_from_ints([2, 0]).unwrap();
        let mut process = Process::new_dummy(stack);
        let program = &MastForest::default();

        process.execute_op(Operation::Not, program, &mut host).unwrap();
        let expected = build_expected(&[ONE, Felt::new(2)]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test NOT 1 ----------------------------------------------------
        let stack = StackInputs::try_from_ints([2, 1]).unwrap();
        let mut process = Process::new_dummy(stack);
        process.execute_op(Operation::Not, program, &mut host).unwrap();
        let expected = build_expected(&[ZERO, Felt::new(2)]);
        assert_eq!(expected, process.stack.trace_state());

        // --- operand is not binary ------------------------------------------
        let stack = StackInputs::try_from_ints([2, 2]).unwrap();
        let mut process = Process::new_dummy(stack);
        assert!(process.execute_op(Operation::Not, program, &mut host).is_err());
    }

    // COMPARISON OPERATIONS
    // --------------------------------------------------------------------------------------------

    #[test]
    fn op_eq() {
        // --- test when top two values are equal -----------------------------
        let advice_inputs = AdviceInputs::default();
        let stack_inputs = StackInputs::try_from_ints([3, 7, 7]).unwrap();
        let (mut process, mut host) =
            Process::new_dummy_with_inputs_and_decoder_helpers(stack_inputs, advice_inputs);
        let program = &MastForest::default();

        process.execute_op(Operation::Eq, program, &mut host).unwrap();
        let expected = build_expected(&[ONE, Felt::new(3)]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test when top two values are not equal -------------------------
        let advice_inputs = AdviceInputs::default();
        let stack_inputs = StackInputs::try_from_ints([3, 5, 7]).unwrap();
        let (mut process, mut host) =
            Process::new_dummy_with_inputs_and_decoder_helpers(stack_inputs, advice_inputs);

        process.execute_op(Operation::Eq, program, &mut host).unwrap();
        let expected = build_expected(&[ZERO, Felt::new(3)]);
        assert_eq!(expected, process.stack.trace_state());

        // --- calling EQ with a stack of minimum depth is a ok ---------------
        let advice_inputs = AdviceInputs::default();
        let stack_inputs = StackInputs::default();
        let (mut process, mut host) =
            Process::new_dummy_with_inputs_and_decoder_helpers(stack_inputs, advice_inputs);
        assert!(process.execute_op(Operation::Eq, program, &mut host).is_ok());
    }

    #[test]
    fn op_eqz() {
        // --- test when top is zero ------------------------------------------
        let advice_inputs = AdviceInputs::default();
        let stack_inputs = StackInputs::try_from_ints([3, 0]).unwrap();
        let (mut process, mut host) =
            Process::new_dummy_with_inputs_and_decoder_helpers(stack_inputs, advice_inputs);
        let program = &MastForest::default();

        process.execute_op(Operation::Eqz, program, &mut host).unwrap();
        let expected = build_expected(&[ONE, Felt::new(3)]);
        assert_eq!(expected, process.stack.trace_state());

        // --- test when top is not zero --------------------------------------
        let advice_inputs = AdviceInputs::default();
        let stack_inputs = StackInputs::try_from_ints([3, 4]).unwrap();
        let (mut process, mut host) =
            Process::new_dummy_with_inputs_and_decoder_helpers(stack_inputs, advice_inputs);

        process.execute_op(Operation::Eqz, program, &mut host).unwrap();
        let expected = build_expected(&[ZERO, Felt::new(3)]);
        assert_eq!(expected, process.stack.trace_state());
    }

    // EXPONENT OPERATIONS
    // --------------------------------------------------------------------------------------------

    #[test]
    fn op_expacc() {
        // --- when base = 0 and exp is even, acc doesn't change --------------------------------

        let old_exp = 8;
        let old_acc = 1;
        let old_base = 0;

        let new_exp = Felt::from_u64(4_u64);
        let new_acc = Felt::from_u64(1_u64);
        let new_base = Felt::from_u64(0_u64);

        let advice_inputs = AdviceInputs::default();
        let stack_inputs = StackInputs::try_from_ints([old_exp, old_acc, old_base, 0]).unwrap();
        let (mut process, mut host) =
            Process::new_dummy_with_inputs_and_decoder_helpers(stack_inputs, advice_inputs);
        let program = &MastForest::default();

        process.execute_op(Operation::Expacc, program, &mut host).unwrap();
        let expected = build_expected(&[ZERO, new_base, new_acc, new_exp]);
        assert_eq!(expected, process.stack.trace_state());

        // --- when base = 0 and exp is odd, acc becomes 0 --------------------------------------

        let old_exp = 9;
        let old_acc = 1;
        let old_base = 0;

        let new_exp = Felt::from_u64(4_u64);
        let new_acc = Felt::from_u64(0_u64);
        let new_base = Felt::from_u64(0_u64);

        let advice_inputs = AdviceInputs::default();
        let stack_inputs = StackInputs::try_from_ints([old_exp, old_acc, old_base, 0]).unwrap();
        let (mut process, mut host) =
            Process::new_dummy_with_inputs_and_decoder_helpers(stack_inputs, advice_inputs);

        process.execute_op(Operation::Expacc, program, &mut host).unwrap();
        let expected = build_expected(&[ONE, new_base, new_acc, new_exp]);
        assert_eq!(expected, process.stack.trace_state());

        // --- when exp = 0, acc doesn't change, and base doubles -------------------------------

        let old_exp = 0;
        let old_acc = 32;
        let old_base = 4;

        let new_exp = Felt::from_u64(0_u64);
        let new_acc = Felt::from_u64(32_u64);
        let new_base = Felt::from_u64(16_u64);

        let advice_inputs = AdviceInputs::default();
        let stack_inputs = StackInputs::try_from_ints([old_exp, old_acc, old_base, 0]).unwrap();
        let (mut process, mut host) =
            Process::new_dummy_with_inputs_and_decoder_helpers(stack_inputs, advice_inputs);

        process.execute_op(Operation::Expacc, program, &mut host).unwrap();
        let expected = build_expected(&[ZERO, new_base, new_acc, new_exp]);
        assert_eq!(expected, process.stack.trace_state());

        // --- when lsb(exp) == 1, acc is updated
        // ----------------------------------------------------------

        let old_exp = 3;
        let old_acc = 1;
        let old_base = 16;

        let new_exp = Felt::from_u64(1_u64);
        let new_acc = Felt::from_u64(16_u64);
        let new_base = Felt::from_u64(16_u64 * 16_u64);

        let advice_inputs = AdviceInputs::default();
        let stack_inputs = StackInputs::try_from_ints([old_exp, old_acc, old_base, 0]).unwrap();
        let (mut process, mut host) =
            Process::new_dummy_with_inputs_and_decoder_helpers(stack_inputs, advice_inputs);

        process.execute_op(Operation::Expacc, program, &mut host).unwrap();
        let expected = build_expected(&[ONE, new_base, new_acc, new_exp]);
        assert_eq!(expected, process.stack.trace_state());

        // --- when lsb(exp) == 1 & base is 2**32 -------------------------------------------
        // base will overflow the field after this operation (which is allowed).

        let old_exp = 17;
        let old_acc = 5;
        let old_base = u32::MAX as u64 + 1_u64;

        let new_exp = Felt::from_u64(8_u64);
        let new_acc = Felt::from_u64(old_acc * old_base);
        let new_base = Felt::from_u64(old_base) * Felt::from_u64(old_base);

        let advice_inputs = AdviceInputs::default();
        let stack_inputs = StackInputs::try_from_ints([old_exp, old_acc, old_base, 0]).unwrap();
        let (mut process, mut host) =
            Process::new_dummy_with_inputs_and_decoder_helpers(stack_inputs, advice_inputs);

        process.execute_op(Operation::Expacc, program, &mut host).unwrap();
        let expected = build_expected(&[ONE, new_base, new_acc, new_exp]);
        assert_eq!(expected, process.stack.trace_state());
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    fn get_rand_values() -> (Felt, Felt, Felt) {
        let a = rand_value();
        let b = rand_value();
        let c = rand_value();
        (Felt::from_u64(a), Felt::from_u64(b), Felt::from_u64(c))
    }

    fn build_expected(values: &[Felt]) -> [Felt; 16] {
        let mut expected = [ZERO; 16];
        for (&value, result) in values.iter().zip(expected.iter_mut()) {
            *result = value;
        }
        expected
    }
}
