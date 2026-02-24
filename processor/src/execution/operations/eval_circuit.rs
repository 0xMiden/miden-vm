use miden_air::trace::RowIndex;
use miden_core::field::{PrimeCharacteristicRing, QuadFelt};

use crate::{
    ContextId, Felt,
    errors::{AceError, AceEvalError},
    processor::{MemoryInterface, Processor, StackInterface, SystemInterface},
    trace::chiplets::{CircuitEvaluation, MAX_NUM_ACE_WIRES, PTR_OFFSET_ELEM, PTR_OFFSET_WORD},
    tracer::Tracer,
};

/// Checks that the evaluation of an arithmetic circuit is equal to zero.
///
/// The inputs are composed of:
///
/// 1. a pointer to the memory region containing the arithmetic circuit description, which itself is
///    arranged as:
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
#[inline(always)]
pub(super) fn op_eval_circuit<P, T>(processor: &mut P, tracer: &mut T) -> Result<(), AceEvalError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    let num_eval = processor.stack().get(2);
    let num_read = processor.stack().get(1);
    let ptr = processor.stack().get(0);
    let ctx = processor.system().ctx();
    let clk = processor.system().clock();

    let circuit_evaluation =
        eval_circuit_impl(ctx, ptr, clk, num_read, num_eval, processor.memory_mut(), tracer)?;
    tracer.record_circuit_evaluation(circuit_evaluation);

    Ok(())
}

/// Evaluates an arithmetic circuit encoded in memory starting at `ptr`.
///
/// This reads `num_vars` quadratic extension field elements from memory (the READ section), then
/// reads `num_eval` base field element gate encodings (the EVAL section), evaluating each gate
/// in sequence. Returns the resulting [`CircuitEvaluation`] if the circuit evaluates to zero.
pub(crate) fn eval_circuit_impl(
    ctx: ContextId,
    ptr: Felt,
    clk: RowIndex,
    num_vars: Felt,
    num_eval: Felt,
    mem: &mut impl MemoryInterface,
    tracer: &mut impl Tracer,
) -> Result<CircuitEvaluation, AceEvalError> {
    let num_vars = num_vars.as_canonical_u64();
    let num_eval = num_eval.as_canonical_u64();

    let num_wires = num_vars + num_eval;
    if num_wires > MAX_NUM_ACE_WIRES as u64 {
        const {
            // If this fails, update the error message below
            assert!(MAX_NUM_ACE_WIRES == (1_u32 << 30) - 1);
        }
        return Err(
            AceError(format!("num of wires must be less than 2^30 but was {num_wires}")).into()
        );
    }

    // Ensure vars and instructions are word-aligned and non-empty. Note that variables are
    // quadratic extension field elements while instructions are encoded as base field elements.
    // Hence we can pack 2 variables and 4 instructions per word.
    if !num_vars.is_multiple_of(2) || num_vars == 0 {
        return Err(AceError(format!(
            "num of variables should be word aligned and non-zero but was {num_vars}"
        ))
        .into());
    }
    if !num_eval.is_multiple_of(4) || num_eval == 0 {
        return Err(AceError(format!(
            "num of evaluation gates should be word aligned and non-zero but was {num_eval}"
        ))
        .into());
    }

    // Ensure instructions are word-aligned and non-empty
    let num_read_rows = num_vars as u32 / 2;
    let num_eval_rows = num_eval as u32;

    let mut evaluation_context = CircuitEvaluation::new(ctx, clk, num_read_rows, num_eval_rows);

    let mut ptr = ptr;
    // perform READ operations
    // Note: we pass in a `NoopTracer`, because the parallel trace generation skips the circuit
    // evaluation completely
    for _ in 0..num_read_rows {
        let word = mem.read_word(ctx, ptr, clk)?;
        tracer.record_memory_read_word(word, ptr, ctx, clk);
        evaluation_context.do_read(ptr, word);
        ptr += PTR_OFFSET_WORD;
    }
    // perform EVAL operations
    for _ in 0..num_eval_rows {
        let instruction = mem.read_element(ctx, ptr)?;
        tracer.record_memory_read_element(instruction, ptr, ctx, clk);
        evaluation_context.do_eval(ptr, instruction)?;
        ptr += PTR_OFFSET_ELEM;
    }

    // Ensure the circuit evaluated to zero.
    if evaluation_context.output_value().is_none_or(|eval| eval != QuadFelt::ZERO) {
        return Err(AceError("circuit does not evaluate to zero".into()).into());
    }

    Ok(evaluation_context)
}
