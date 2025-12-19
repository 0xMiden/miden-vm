use miden_core::{Felt, FieldElement, ONE, Operation, QuadFelt};

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
    /// the base field using a 3-level computation to reduce constraint degree.
    ///
    /// The computation is broken into 3 levels:
    /// - Level 1: tmp0 = (acc * α + c₀) * α + c₁
    /// - Level 2: tmp1 = ((tmp0 * α + c₂) * α + c₃) * α + c₄
    /// - Level 3: acc' = ((tmp1 * α + c₅) * α + c₆) * α + c₇
    ///
    /// In other words, the instruction computes the evaluation at alpha of the polynomial:
    ///
    /// P(X) := c₀ * X^7 + c₁ * X^6 + c₂ * X^5 + c₃ * X^4 + c₄ * X^3 + c₅ * X^2 + c₆ * X + c₇
    ///
    /// The instruction can be used to compute the evaluation of polynomials of arbitrary degree
    /// by repeated invocations interleaved with any operation that loads the next batch of 8
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
    /// 3. alpha_addr is the memory address pointing to the evaluation point α. The operation reads
    ///    α₀ from alpha_addr and α₁ from alpha_addr + 1.
    ///
    /// The instruction uses helper registers to store intermediate values:
    /// - h₀, h₁: evaluation point α = (α₀, α₁)
    /// - h₂, h₃: Level 2 intermediate result tmp1
    /// - h₄, h₅: Level 1 intermediate result tmp0
    pub(super) fn op_horner_eval_base(
        &mut self,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        // read the values of the coefficients, over the base field, from the stack
        let coef = self.get_coeff_as_base_elements();
        let c7 = QuadFelt::from(coef[0]);
        let c6 = QuadFelt::from(coef[1]);
        let c5 = QuadFelt::from(coef[2]);
        let c4 = QuadFelt::from(coef[3]);
        let c3 = QuadFelt::from(coef[4]);
        let c2 = QuadFelt::from(coef[5]);
        let c1 = QuadFelt::from(coef[6]);
        let c0 = QuadFelt::from(coef[7]);

        // read the evaluation point alpha from memory
        let alpha = self.get_evaluation_point_elements(err_ctx)?;

        // read the current accumulator
        let acc = self.get_accumulator();

        // Level 1: tmp0 = (acc * α + c₀) * α + c₁
        let tmp0 = (acc * alpha + c0) * alpha + c1;

        // Level 2: tmp1 = ((tmp0 * α + c₂) * α + c₃) * α + c₄
        let tmp1 = ((tmp0 * alpha + c2) * alpha + c3) * alpha + c4;

        // Level 3: acc' = ((tmp1 * α + c₅) * α + c₆) * α + c₇
        let acc_new = ((tmp1 * alpha + c5) * alpha + c6) * alpha + c7;

        // copy over the stack state to the next cycle changing only the accumulator values
        self.stack.copy_state(0);
        self.stack.set(ACC_HIGH_INDEX, acc_new.to_base_elements()[1]);
        self.stack.set(ACC_LOW_INDEX, acc_new.to_base_elements()[0]);

        // set the helper registers
        // h₀, h₁: evaluation point α
        // h₂, h₃: intermediate result tmp1 (Level 2)
        // h₄, h₅: intermediate result tmp0 (Level 1)
        self.decoder.set_user_op_helpers(
            Operation::HornerBase,
            &[
                alpha.base_element(0),
                alpha.base_element(1),
                tmp1.base_element(0),
                tmp1.base_element(1),
                tmp0.base_element(0),
                tmp0.base_element(1),
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
    /// In other words, the instruction computes the evaluation at alpha of the polynomial
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
    /// 1. ci for i in 0..=3 stands for the value of the i-th coefficient in the current batch of 4
    ///    extension field coefficients of the polynomial.
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
            Operation::HornerExt,
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
    fn get_evaluation_point_elements(
        &mut self,
        err_ctx: &impl ErrorContext,
    ) -> Result<QuadFelt, ExecutionError> {
        let ctx = self.system.ctx();
        let addr = self.stack.get(ALPHA_ADDR_INDEX);
        let alpha_0 = self
            .chiplets
            .memory
            .read(ctx, addr, self.system.clk(), err_ctx)
            .map_err(ExecutionError::MemoryError)?;
        let alpha_1 = self
            .chiplets
            .memory
            .read(ctx, addr + ONE, self.system.clk(), err_ctx)
            .map_err(ExecutionError::MemoryError)?;

        Ok(QuadFelt::new(alpha_0, alpha_1))
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
