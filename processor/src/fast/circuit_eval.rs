use miden_air::RowIndex;
use miden_core::{Felt, FieldElement, QuadFelt};

use super::{FastProcessor, memory::Memory};
use crate::{
    ContextId, ExecutionError,
    chiplets::{CircuitEvaluation, MAX_NUM_ACE_WIRES, PTR_OFFSET_ELEM, PTR_OFFSET_WORD},
    errors::{AceError, ErrorContext},
};

impl FastProcessor {
    /// Checks that the evaluation of an arithmetic circuit is equal to zero.
    ///
    /// The inputs are composed of:
    ///
    /// 1. a pointer to the memory region containing the arithmetic circuit description, which
    ///    itself is arranged as:
    ///
    ///    a. `Read` section:
    ///       1. Inputs to the circuit which are elements in the quadratic extension field,
    ///       2. Constants of the circuit which are elements in the quadratic extension field,
    ///
    ///    b. `Eval` section, which contains the encodings of the evaluation gates of the circuit,
    ///    where each gate is encoded as a single base field element.
    /// 2. the number of quadratic extension field elements read in the `READ` section,
    /// 3. the number of field elements, one base field element per gate, in the `EVAL` section,
    ///
    /// Stack transition:
    /// [ptr, num_read, num_eval, ...] -> [ptr, num_read, num_eval, ...]
    pub fn op_eval_circuit(
        &mut self,
        op_idx: usize,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        let num_eval = self.stack_get(2);
        let num_read = self.stack_get(1);
        let ptr = self.stack_get(0);
        let ctx = self.ctx;
        let clk = self.clk;
        let circuit_evaluation = eval_circuit_fast_(
            ctx,
            ptr,
            clk,
            num_read,
            num_eval,
            &mut self.memory,
            op_idx,
            err_ctx,
        )?;
        self.ace.add_circuit_evaluation(clk, circuit_evaluation);

        Ok(())
    }
}

/// Identical to `[chiplets::ace::eval_circuit]` but adapted for use with `[FastProcessor]`.
#[allow(clippy::too_many_arguments)]
pub fn eval_circuit_fast_(
    ctx: ContextId,
    ptr: Felt,
    clk: RowIndex,
    num_vars: Felt,
    num_eval: Felt,
    mem: &mut Memory,
    op_idx: usize,
    err_ctx: &impl ErrorContext,
) -> Result<CircuitEvaluation, ExecutionError> {
    let num_vars = num_vars.as_int();
    let num_eval = num_eval.as_int();

    let num_wires = num_vars + num_eval;
    if num_wires > MAX_NUM_ACE_WIRES as u64 {
        return Err(ExecutionError::failed_arithmetic_evaluation(
            err_ctx,
            AceError::TooManyWires(num_wires),
        ));
    }

    // Ensure vars and instructions are word-aligned and non-empty. Note that variables are
    // quadratic extension field elements while instructions are encoded as base field elements.
    // Hence we can pack 2 variables and 4 instructions per word.
    if !num_vars.is_multiple_of(2) || num_vars == 0 {
        return Err(ExecutionError::failed_arithmetic_evaluation(
            err_ctx,
            AceError::NumVarIsNotWordAlignedOrIsEmpty(num_vars),
        ));
    }
    if !num_eval.is_multiple_of(4) || num_eval == 0 {
        return Err(ExecutionError::failed_arithmetic_evaluation(
            err_ctx,
            AceError::NumEvalIsNotWordAlignedOrIsEmpty(num_eval),
        ));
    }

    // Ensure instructions are word-aligned and non-empty
    let num_read_rows = num_vars as u32 / 2;
    let num_eval_rows = num_eval as u32;

    let mut evaluation_context =
        CircuitEvaluation::new(ctx, clk + op_idx, num_read_rows, num_eval_rows);

    let mut ptr = ptr;
    // perform READ operations
    for _ in 0..num_read_rows {
        let word = mem
            .read_word(ctx, ptr, clk + op_idx, err_ctx)
            .map_err(ExecutionError::MemoryError)?;
        evaluation_context.do_read(ptr, word)?;
        ptr += PTR_OFFSET_WORD;
    }
    // perform EVAL operations
    for _ in 0..num_eval_rows {
        let instruction =
            mem.read_element(ctx, ptr, err_ctx).map_err(ExecutionError::MemoryError)?;
        evaluation_context.do_eval(ptr, instruction, err_ctx)?;
        ptr += PTR_OFFSET_ELEM;
    }

    // Ensure the circuit evaluated to zero.
    if !evaluation_context.output_value().is_some_and(|eval| eval == QuadFelt::ZERO) {
        return Err(ExecutionError::failed_arithmetic_evaluation(
            err_ctx,
            AceError::CircuitNotEvaluateZero,
        ));
    }

    Ok(evaluation_context)
}
