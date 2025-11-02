use miden_core::{Felt, FieldElement, Operation, QuadFelt};

use crate::{ExecutionError, Process, errors::ErrorContext};

// CONSTANTS
// ================================================================================================

const ALPHA_ADDR_INDEX: usize = 13;
const ACC_HIGH_INDEX: usize = 14;
const ACC_LOW_INDEX: usize = 15;

// HORNER EVALUATION OPERATIONS
// ================================================================================================

impl Process {
    // HORNER EVALUATION WITH COEFFICIENTS OVER BASE FIELD
    // --------------------------------------------------------------------------------------------

    /// Performs 8 steps of the Horner evaluation method on a polynomial with coefficients over
    /// the base field, i.e., it computes
    ///
    /// acc' = (((acc_tmp * alpha + c4) * alpha + c5) * alpha + c6) * alpha + c7
    ///
    /// where
    ///
    /// acc_tmp := (((acc * alpha + c0) * alpha + c1) * alpha + c2) * alpha + c3
    ///
    ///
    /// In other words, the intsruction computes the evaluation at alpha of the polynomial
    ///
    /// P(X) := c0 * X^7 + c1 * X^6 + ... + c6 * X + c7
    ///
    /// As can be seen from the two equations defining acc', the instruction can be used in order
    /// to compute the evaluation of polynomials of arbitrary degree by repeated invocations of
    /// the same instruction interleaved with any operation that loads the next batch of 8
    /// coefficients on the top of the operand stack, i.e., `mem_stream` or `adv_pipe`.
    ///
    /// The stack transition of the instruction can be visualized as follows:
    ///
    /// Input:
    ///
    /// +------+------+------+------+------+------+------+------+---+---+---+---+---+----------+------+------+
    /// |  c7  |  c6  |  c5  |  c4  |  c3  |  c2  |  c1  |  c0  | - | - | - | - | - |alpha_addr| acc1 | acc0 |
    /// +------+------+------+------+------+------+------+------+---+---+---+---+---+----------+------+------+
    ///
    ///
    /// Output:
    ///
    /// +------+------+------+------+------+------+------+------+---+---+---+---+---+----------+-------+-------+
    /// |  c7  |  c6  |  c5  |  c4  |  c3  |  c2  |  c1  |  c0  | - | - | - | - | - |alpha_addr| acc1' | acc0' |
    /// +------+------+------+------+------+------+------+------+---+---+---+---+---+----------+-------+-------+
    ///
    ///
    /// Here:
    ///
    /// 1. ci for i in 0..=7 stands for the the value of the i-th coefficient in the current batch
    ///    of 8 coefficients of the polynomial.
    /// 2. (acc0, acc1) stands for an extension field element accumulating the values of the Horner
    ///    evaluation procedure. (acc0', acc1') is the updated value of this accumulator.
    /// 3. alpha_addr is the memory address of the evaluation point i.e., alpha.
    ///
    /// The instruction also makes use of the helper registers to hold the value of
    /// alpha = (alpha0, alpha1) during the course of its execution.
    /// The helper registers are also used in order to hold the second half of the memory word
    /// containing (alpha0, alpha1), as well as the temporary values acc_tmp.
    pub(super) fn op_horner_eval_base(
        &mut self,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        // read the values of the coefficients, over the base field, from the stack
        let coef = self.get_coeff_as_base_elements();

        // read the evaluation point alpha from memory
        // we also read the second half of the memory word containing alpha
        let (alpha, k0, k1) = self.get_evaluation_point(err_ctx)?;

        // compute the temporary and updated accumulator values
        let acc_old = self.get_accumulator();
        let acc_tmp = coef
            .iter()
            .rev()
            .take(4)
            .fold(acc_old, |acc, coef| QuadFelt::from(*coef) + alpha * acc);
        let acc_new = coef
            .iter()
            .rev()
            .skip(4)
            .fold(acc_tmp, |acc, coef| QuadFelt::from(*coef) + alpha * acc);

        // copy over the stack state to the next cycle changing only the accumulator values
        self.stack.copy_state(0);
        self.stack.set(ACC_HIGH_INDEX, acc_new.to_base_elements()[1]);
        self.stack.set(ACC_LOW_INDEX, acc_new.to_base_elements()[0]);

        // set the helper registers
        self.decoder.set_user_op_helpers(
            Operation::HornerBase,
            &[
                alpha.base_element(0),
                alpha.base_element(1),
                k0,
                k1,
                acc_tmp.base_element(0),
                acc_tmp.base_element(1),
            ],
        );

        Ok(())
    }

    /// Performs 4 steps of the Horner evaluation method on a polynomial with coefficients over
    /// the quadratic extension field, i.e., it computes
    ///
    /// acc' = (acc_tmp * alpha + c2) * alpha + c3
    ///
    /// where
    ///
    /// acc_tmp = (acc * alpha + c0) * alpha + c1
    ///
    ///
    /// In other words, the intsruction computes the evaluation at alpha of the polynomial
    ///
    /// P(X) := c0 * X^3 + c1 * X^2 + c2 * X + c3
    ///
    /// As can be seen from the two equations defining acc', the instruction can be used in order
    /// to compute the evaluation of polynomials of arbitrary degree by repeated invocations of
    /// the same instruction interleaved with any operation that loads the next batch of 4
    /// coefficients on the top of the operand stack, i.e., `mem_stream` or `adv_pipe`.
    ///
    /// The stack transition of the instruction can be visualized as follows:
    ///
    /// Input:
    ///
    /// +------+------+------+------+------+------+------+------+---+---+---+---+---+----------+------+------+
    /// | c3_1 | c3_0 | c2_1 | c2_0 | c1_1 | c1_0 | c0_1 | c0_0 | - | - | - | - | - |alpha_addr| acc1 | acc0 |
    /// +------+------+------+------+------+------+------+------+---+---+---+---+---+----------+------+------+
    ///
    ///
    /// Output:
    ///
    /// +------+------+------+------+------+------+------+------+---+---+---+---+---+----------+-------+-------+
    /// | c3_1 | c3_0 | c2_1 | c2_0 | c1_1 | c1_0 | c0_1 | c0_0 | - | - | - | - | - |alpha_addr| acc1' | acc0' |
    /// +------+------+------+------+------+------+------+------+---+---+---+---+---+----------+-------+-------+
    ///
    ///
    /// Here:
    ///
    /// 1. ci for i in 0..=4 stands for the the value of the i-th coefficient in the current batch
    ///    of 4 extension field coefficients of the polynomial.
    /// 2. (acc0, acc1) stands for an extension field element accumulating the values of the Horner
    ///    evaluation procedure. (acc0', acc1') is the updated value of this accumulator.
    /// 3. alpha_addr is the memory address of the evaluation point i.e., alpha.
    ///
    /// The instruction also makes use of the helper registers to hold the value of
    /// alpha = (alpha0, alpha1) during the course of its execution.
    /// The helper registers are also used in order to hold the second half of the memory word
    /// containing (alpha0, alpha1), as well as the temporary values acc_tmp.
    pub(super) fn op_horner_eval_ext(
        &mut self,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        // read the values of the coefficients, over the extension field, from the stack
        let coef = self.get_coeff_as_quad_ext_elements();

        // read the evaluation point from memory
        // we also read the second half of the memory word containing alpha
        let (alpha, k0, k1) = self.get_evaluation_point(err_ctx)?;

        // compute the temporary and updated accumulator values
        let acc_old = self.get_accumulator();
        let acc_tmp = coef.iter().rev().take(2).fold(acc_old, |acc, coef| *coef + alpha * acc);
        let acc_new = coef.iter().rev().skip(2).fold(acc_tmp, |acc, coef| *coef + alpha * acc);

        // copy over the stack state to the next cycle changing only the accumulator values
        self.stack.copy_state(0);
        self.stack.set(ACC_HIGH_INDEX, acc_new.to_base_elements()[1]);
        self.stack.set(ACC_LOW_INDEX, acc_new.to_base_elements()[0]);

        // set the helper registers
        self.decoder.set_user_op_helpers(
            Operation::HornerBase,
            &[
                alpha.base_element(0),
                alpha.base_element(1),
                k0,
                k1,
                acc_tmp.base_element(0),
                acc_tmp.base_element(1),
            ],
        );

        Ok(())
    }

    //// HELPER METHODS
    //// ------------------------------------------------------------------------------------------

    /// Returns the top 8 elements of the operand stack.
    fn get_coeff_as_base_elements(&self) -> [Felt; 8] {
        let c0 = self.stack.get(0);
        let c1 = self.stack.get(1);
        let c2 = self.stack.get(2);
        let c3 = self.stack.get(3);
        let c4 = self.stack.get(4);
        let c5 = self.stack.get(5);
        let c6 = self.stack.get(6);
        let c7 = self.stack.get(7);

        [c0, c1, c2, c3, c4, c5, c6, c7]
    }

    /// Returns the top 8 elements of the operand stack.
    fn get_coeff_as_quad_ext_elements(&self) -> [QuadFelt; 4] {
        let c0_1 = self.stack.get(0);
        let c0_0 = self.stack.get(1);
        let c1_1 = self.stack.get(2);
        let c1_0 = self.stack.get(3);
        let c2_1 = self.stack.get(4);
        let c2_0 = self.stack.get(5);
        let c3_1 = self.stack.get(6);
        let c3_0 = self.stack.get(7);

        [
            QuadFelt::new(c0_0, c0_1),
            QuadFelt::new(c1_0, c1_1),
            QuadFelt::new(c2_0, c2_1),
            QuadFelt::new(c3_0, c3_1),
        ]
    }

    /// Returns the evaluation point.
    /// Also returns the second half, i.e., two field elements, that are stored next to
    /// the evaluation point.
    fn get_evaluation_point(
        &mut self,
        err_ctx: &impl ErrorContext,
    ) -> Result<(QuadFelt, Felt, Felt), ExecutionError> {
        let ctx = self.system.ctx();
        let addr = self.stack.get(ALPHA_ADDR_INDEX);
        let word = self
            .chiplets
            .memory
            .read_word(ctx, addr, self.system.clk(), err_ctx)
            .map_err(ExecutionError::MemoryError)?;
        let alpha_0 = word[0];
        let alpha_1 = word[1];

        Ok((QuadFelt::new(alpha_0, alpha_1), word[2], word[3]))
    }

    /// Reads the accumulator values.
    fn get_accumulator(&self) -> QuadFelt {
        let acc1 = self.stack.get(ACC_HIGH_INDEX);
        let acc0 = self.stack.get(ACC_LOW_INDEX);

        QuadFelt::new(acc0, acc1)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::{Felt, Operation, QuadFelt, StackInputs, ZERO, mast::MastForest};
    use miden_utils_testing::{build_test, rand::rand_array};

    use super::{ACC_HIGH_INDEX, ACC_LOW_INDEX, ALPHA_ADDR_INDEX, *};
    use crate::{ContextId, DefaultHost, Process};

    #[test]
    fn horner_eval_base() {
        // --- build stack inputs -----------------------------------------------------------------
        let mut inputs = rand_array::<Felt, 16>();

        // set alpha_addr pointer
        inputs[ALPHA_ADDR_INDEX] = Felt::new(1000);

        // set initial accumulator to zero
        inputs[ACC_HIGH_INDEX] = ZERO;
        inputs[ACC_LOW_INDEX] = ZERO;
        inputs.reverse();

        // --- setup the operand stack ------------------------------------------------------------
        let mut host = DefaultHost::default();
        let stack_inputs = StackInputs::new(inputs.to_vec()).expect("inputs length too long");
        let mut process = Process::new_dummy_with_decoder_helpers(stack_inputs);
        let program = &MastForest::default();

        // --- setup memory -----------------------------------------------------------------------
        let ctx = ContextId::root();

        // Note: the first 2 elements of `alpha` are the actual evaluation point, the other 2 are
        // junk.
        let alpha_mem_word = rand_array::<Felt, 4>();
        process
            .chiplets
            .memory
            .write_word(
                ctx,
                inputs[2].as_int().try_into().expect("Shouldn't fail by construction"),
                process.system.clk(),
                alpha_mem_word.into(),
                &(),
            )
            .unwrap();
        process.execute_op(Operation::Noop, program, &mut host).unwrap();

        // --- execute HORNER_BASE operation ------------------------------------------------------
        process.execute_op(Operation::HornerBase, program, &mut host).unwrap();

        // --- check that the top 8 stack elements were not affected ------------------------------
        let stack_state = process.stack.trace_state();
        inputs.reverse();
        assert_eq!(stack_state[0], inputs[0]);
        assert_eq!(stack_state[1], inputs[1]);
        assert_eq!(stack_state[2], inputs[2]);
        assert_eq!(stack_state[3], inputs[3]);
        assert_eq!(stack_state[4], inputs[4]);
        assert_eq!(stack_state[5], inputs[5]);
        assert_eq!(stack_state[6], inputs[6]);
        assert_eq!(stack_state[7], inputs[7]);

        // --- check that the accumulator was updated correctly -----------------------------------
        let acc1_old = inputs[ACC_HIGH_INDEX];
        let acc0_old = inputs[ACC_LOW_INDEX];
        let acc_old = QuadFelt::new(acc0_old, acc1_old);

        let alpha = QuadFelt::new(alpha_mem_word[0], alpha_mem_word[1]);

        let acc_tmp = stack_state
            .iter()
            .take(8)
            .rev()
            .take(4)
            .fold(acc_old, |acc, coef| QuadFelt::from(*coef) + alpha * acc);

        let acc_new = stack_state
            .iter()
            .take(8)
            .rev()
            .skip(4)
            .fold(acc_tmp, |acc, coef| QuadFelt::from(*coef) + alpha * acc);

        assert_eq!(acc_new.to_base_elements()[1], stack_state[ACC_HIGH_INDEX]);
        assert_eq!(acc_new.to_base_elements()[0], stack_state[ACC_LOW_INDEX]);

        // --- check that memory pointers were untouched ------------------------------------------
        assert_eq!(inputs[12], stack_state[12]);
        assert_eq!(inputs[ALPHA_ADDR_INDEX], stack_state[ALPHA_ADDR_INDEX]);

        // --- check that the helper registers were updated correctly -----------------------------
        let helper_reg_expected = [
            alpha_mem_word[0],
            alpha_mem_word[1],
            alpha_mem_word[2],
            alpha_mem_word[3],
            acc_tmp.base_element(0),
            acc_tmp.base_element(1),
        ];
        assert_eq!(helper_reg_expected, process.decoder.get_user_op_helpers());
    }

    #[test]
    fn horner_eval_ext() {
        // --- build stack inputs -----------------------------------------------------------------
        let mut inputs = rand_array::<Felt, 16>();

        // set alpha_addr pointer
        inputs[ALPHA_ADDR_INDEX] = Felt::new(1000);

        // set initial accumulator to zero
        inputs[ACC_HIGH_INDEX] = ZERO;
        inputs[ACC_LOW_INDEX] = ZERO;
        inputs.reverse();

        // --- setup the operand stack ------------------------------------------------------------
        let mut host = DefaultHost::default();
        let stack_inputs = StackInputs::new(inputs.to_vec()).expect("inputs lenght too long");
        let mut process = Process::new_dummy_with_decoder_helpers(stack_inputs);
        let program = &MastForest::default();

        // --- setup memory -----------------------------------------------------------------------
        let ctx = ContextId::root();

        let alpha_mem_word = rand_array::<Felt, 4>();
        process
            .chiplets
            .memory
            .write_word(
                ctx,
                inputs[2].as_int().try_into().expect("Shouldn't fail by construction"),
                process.system.clk(),
                alpha_mem_word.into(),
                &(),
            )
            .unwrap();
        process.execute_op(Operation::Noop, program, &mut host).unwrap();

        // --- execute HORNER_BASE operation ------------------------------------------------------
        process.execute_op(Operation::HornerExt, program, &mut host).unwrap();

        // --- check that the top 8 stack elements were not affected ------------------------------
        let stack_state = process.stack.trace_state();
        inputs.reverse();
        assert_eq!(stack_state[0], inputs[0]);
        assert_eq!(stack_state[1], inputs[1]);
        assert_eq!(stack_state[2], inputs[2]);
        assert_eq!(stack_state[3], inputs[3]);
        assert_eq!(stack_state[4], inputs[4]);
        assert_eq!(stack_state[5], inputs[5]);
        assert_eq!(stack_state[6], inputs[6]);
        assert_eq!(stack_state[7], inputs[7]);

        // --- check that the accumulator was updated correctly -----------------------------------
        let acc1_old = inputs[ACC_HIGH_INDEX];
        let acc0_old = inputs[ACC_LOW_INDEX];
        let acc_old = QuadFelt::new(acc0_old, acc1_old);

        let alpha = QuadFelt::new(alpha_mem_word[0], alpha_mem_word[1]);

        let coefficients: Vec<_> = stack_state
            .chunks(2)
            .take(4)
            .map(|coef| QuadFelt::new(coef[1], coef[0]))
            .collect();

        let acc_tmp =
            coefficients.iter().rev().take(2).fold(acc_old, |acc, coef| *coef + alpha * acc);
        let acc_new =
            coefficients.iter().rev().skip(2).fold(acc_tmp, |acc, coef| *coef + alpha * acc);

        assert_eq!(acc_new.to_base_elements()[1], stack_state[ACC_HIGH_INDEX]);
        assert_eq!(acc_new.to_base_elements()[0], stack_state[ACC_LOW_INDEX]);

        // --- check that memory pointers were untouched ------------------------------------------
        assert_eq!(inputs[12], stack_state[12]);
        assert_eq!(inputs[ALPHA_ADDR_INDEX], stack_state[ALPHA_ADDR_INDEX]);

        // --- check that the helper registers were updated correctly -----------------------------
        let helper_reg_expected = [
            alpha_mem_word[0],
            alpha_mem_word[1],
            alpha_mem_word[2],
            alpha_mem_word[3],
            acc_tmp.base_element(0),
            acc_tmp.base_element(1),
        ];
        assert_eq!(helper_reg_expected, process.decoder.get_user_op_helpers());
    }

    #[test]
    fn prove_verify_horner_base() {
        let source = "
            begin
                # Load the evaluation point from the advice stack and store it at `alpha_addr`
                padw
                adv_loadw
                push.1000
                mem_storew_be
                dropw

                # Execute
                horner_eval_base
            end
        ";

        // --- build stack inputs -----------------------------------------------------------------
        let mut inputs = rand_array::<Felt, 16>();

        // set alpha_addr pointer
        inputs[ALPHA_ADDR_INDEX] = Felt::new(1000);

        // sample a random evaluation point
        let a: [Felt; 2] = rand_array();
        let alpha_0 = a[0];
        let alpha_1 = a[1];
        let alpha = QuadFelt::new(alpha_0, alpha_1);

        // compute the evaluation
        let acc_old = QuadFelt::new(inputs[ACC_LOW_INDEX], inputs[ACC_HIGH_INDEX]);
        let acc_new = inputs
            .iter()
            .take(8)
            .rev()
            .fold(acc_old, |acc, coef| QuadFelt::from(*coef) + alpha * acc);
        inputs.reverse();

        // prepare the advice stack with the generated data
        let adv_stack = [a[0], a[1], ZERO, ZERO];
        let adv_stack: Vec<u64> = adv_stack.iter().map(|e| e.as_int()).collect();

        // create the expected operand stack
        let mut expected = Vec::new();
        // updated accumulators
        expected.extend_from_slice(&[acc_new.to_base_elements()[0], acc_new.to_base_elements()[1]]);
        // the rest of the stack should remain unchanged
        expected.extend_from_slice(&inputs[2..]);
        let expected: Vec<u64> = expected.iter().rev().map(|e| e.as_int()).collect();

        // convert input stack
        let inputs: Vec<u64> = inputs.iter().map(|e| e.as_int()).collect();

        let test = build_test!(source, &inputs, &adv_stack);
        test.expect_stack(&expected);

        let pub_inputs: Vec<u64> = inputs.to_vec();
        test.prove_and_verify(pub_inputs, false);
    }

    #[test]
    fn prove_verify_horner_ext() {
        let source = "
            begin
                # Load the evaluation point from the advice stack and store it at `alpha_addr`
                padw
                adv_loadw
                push.1000
                mem_storew_be
                dropw

                # Execute
                horner_eval_ext
            end
        ";

        // --- build stack inputs -----------------------------------------------------------------
        let mut inputs = rand_array::<Felt, 16>();

        // set alpha_addr pointer
        inputs[ALPHA_ADDR_INDEX] = Felt::new(1000);

        // sample a random evaluation point
        let a: [Felt; 2] = rand_array();
        let alpha_0 = a[0];
        let alpha_1 = a[1];
        let alpha = QuadFelt::new(alpha_0, alpha_1);

        // compute the evaluation
        let acc_old = QuadFelt::new(inputs[ACC_LOW_INDEX], inputs[ACC_HIGH_INDEX]);
        let acc_new = inputs
            .chunks(2)
            .take(4)
            .rev()
            .fold(acc_old, |acc, coef| QuadFelt::new(coef[1], coef[0]) + alpha * acc);
        inputs.reverse();

        // prepare the advice stack with the generated data
        let adv_stack = [a[0], a[1], ZERO, ZERO];
        let adv_stack: Vec<u64> = adv_stack.iter().map(|e| e.as_int()).collect();

        // create the expected operand stack
        let mut expected = Vec::new();
        // updated accumulators
        expected.extend_from_slice(&[acc_new.to_base_elements()[0], acc_new.to_base_elements()[1]]);
        // the rest of the stack should remain unchanged
        expected.extend_from_slice(&inputs[2..]);
        let expected: Vec<u64> = expected.iter().rev().map(|e| e.as_int()).collect();

        // convert input stack
        let inputs: Vec<u64> = inputs.iter().map(|e| e.as_int()).collect();

        let test = build_test!(source, &inputs, &adv_stack);
        test.expect_stack(&expected);

        let pub_inputs: Vec<u64> = inputs.to_vec();
        test.prove_and_verify(pub_inputs, false);
    }
}
