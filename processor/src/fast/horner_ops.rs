use core::array;

use miden_core::{Felt, QuadFelt};

use super::FastProcessor;
use crate::{ErrorContext, ExecutionError, fast::tracer::Tracer};

// CONSTANTS
// ================================================================================================

const ALPHA_ADDR_INDEX: usize = 13;
const ACC_HIGH_INDEX: usize = 14;
const ACC_LOW_INDEX: usize = 15;

impl FastProcessor {
    /// Analogous to `Process::op_horner_eval_base`.
    #[inline(always)]
    pub fn op_horner_eval_base(
        &mut self,
        tracer: &mut impl Tracer,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        // read the values of the coefficients, over the base field, from the stack
        let coeffs = self.get_coeffs_as_base_elements();

        // read the evaluation point alpha from memory
        let alpha = self.get_evaluation_point(tracer, err_ctx)?;

        // compute the updated accumulator value
        let (acc_new1, acc_new0) = {
            let acc_old = self.get_accumulator();
            let acc_new = coeffs
                .iter()
                .rev()
                .fold(acc_old, |acc, coef| QuadFelt::from(*coef) + alpha * acc);

            let acc_new_base_elements = acc_new.to_base_elements();

            (acc_new_base_elements[1], acc_new_base_elements[0])
        };

        // Update the accumulator values
        self.stack_write(ACC_HIGH_INDEX, acc_new1);
        self.stack_write(ACC_LOW_INDEX, acc_new0);

        Ok(())
    }

    /// Analogous to `Process::op_horner_eval_ext`.
    #[inline(always)]
    pub fn op_horner_eval_ext(
        &mut self,
        tracer: &mut impl Tracer,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        // read the values of the coefficients, over the base field, from the stack
        let coef = self.get_coeffs_as_quad_ext_elements();

        // read the evaluation point alpha from memory
        let alpha = self.get_evaluation_point(tracer, err_ctx)?;

        // compute the updated accumulator value
        let (acc_new1, acc_new0) = {
            let acc_old = self.get_accumulator();
            let acc_new = coef.iter().rev().fold(acc_old, |acc, coef| *coef + alpha * acc);

            let acc_new_base_elements = acc_new.to_base_elements();

            (acc_new_base_elements[1], acc_new_base_elements[0])
        };

        // Update the accumulator values
        self.stack_write(ACC_HIGH_INDEX, acc_new1);
        self.stack_write(ACC_LOW_INDEX, acc_new0);

        Ok(())
    }

    // HELPER METHODS
    //// ------------------------------------------------------------------------------------------

    /// Returns the top 8 elements of the operand stack, such that the element on top of the stack
    /// appears first in the return array.
    fn get_coeffs_as_base_elements(&self) -> [Felt; 8] {
        array::from_fn(|i| self.stack_get(i))
    }

    /// Returns the top 8 elements of the operand stack.
    fn get_coeffs_as_quad_ext_elements(&self) -> [QuadFelt; 4] {
        let c0 = [self.stack_get(0), self.stack_get(1)];
        let c1 = [self.stack_get(2), self.stack_get(3)];
        let c2 = [self.stack_get(4), self.stack_get(5)];
        let c3 = [self.stack_get(6), self.stack_get(7)];

        [
            QuadFelt::new(c0[1], c0[0]),
            QuadFelt::new(c1[1], c1[0]),
            QuadFelt::new(c2[1], c2[0]),
            QuadFelt::new(c3[1], c3[0]),
        ]
    }

    /// Returns the evaluation point.
    fn get_evaluation_point(
        &mut self,
        tracer: &mut impl Tracer,
        err_ctx: &impl ErrorContext,
    ) -> Result<QuadFelt, ExecutionError> {
        let (alpha_0, alpha_1) = {
            let addr = self.stack_get(ALPHA_ADDR_INDEX);
            let word = self
                .memory
                .read_word(self.ctx, addr, self.clk, err_ctx, tracer)
                .map_err(ExecutionError::MemoryError)?;

            (word[0], word[1])
        };

        Ok(QuadFelt::new(alpha_0, alpha_1))
    }

    /// Reads the accumulator values.
    fn get_accumulator(&self) -> QuadFelt {
        let acc1 = self.stack_get(ACC_HIGH_INDEX);
        let acc0 = self.stack_get(ACC_LOW_INDEX);

        QuadFelt::new(acc0, acc1)
    }
}
