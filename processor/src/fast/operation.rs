use miden_air::{
    Felt,
    trace::{RowIndex, chiplets::hasher::HasherState, decoder::NUM_USER_OP_HELPERS},
};
use miden_core::{
    WORD_SIZE, Word, ZERO,
    crypto::{hash::Rpo256, merkle::MerklePath},
    field::{PrimeCharacteristicRing, PrimeField64, QuadFelt},
    precompile::{PrecompileTranscript, PrecompileTranscriptState},
};

use crate::{
    AdviceProvider, ContextId, ErrorContext, ExecutionError, ProcessState,
    chiplets::{CircuitEvaluation, MAX_NUM_ACE_WIRES, PTR_OFFSET_ELEM, PTR_OFFSET_WORD},
    errors::AceError,
    fast::{FastProcessor, STACK_BUFFER_SIZE, Tracer, memory::Memory},
    processor::{
        HasherInterface, MemoryInterface, OperationHelperRegisters, Processor, StackInterface,
        SystemInterface,
    },
};

impl Processor for FastProcessor {
    type HelperRegisters = NoopHelperRegisters;
    type System = Self;
    type Stack = Self;
    type AdviceProvider = AdviceProvider;
    type Memory = Memory;
    type Hasher = Self;

    #[inline(always)]
    fn stack(&mut self) -> &mut Self::Stack {
        self
    }

    #[inline(always)]
    fn state(&mut self) -> ProcessState<'_> {
        self.state()
    }

    #[inline(always)]
    fn advice_provider(&mut self) -> &mut Self::AdviceProvider {
        &mut self.advice
    }

    #[inline(always)]
    fn memory(&mut self) -> &mut Self::Memory {
        &mut self.memory
    }

    #[inline(always)]
    fn hasher(&mut self) -> &mut Self::Hasher {
        self
    }

    #[inline(always)]
    fn system(&mut self) -> &mut Self::System {
        self
    }

    #[inline(always)]
    fn precompile_transcript_state(&self) -> PrecompileTranscriptState {
        self.pc_transcript.state()
    }

    #[inline(always)]
    fn set_precompile_transcript_state(&mut self, state: PrecompileTranscriptState) {
        self.pc_transcript = PrecompileTranscript::from_state(state);
    }

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
    ///
    /// Note that we do not record any memory reads in this operation (through a
    /// [crate::fast::Tracer]), because the parallel trace generation skips the circuit
    /// evaluation completely.
    fn op_eval_circuit(
        &mut self,
        err_ctx: &impl ErrorContext,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        let num_eval = self.stack_get(2);
        let num_read = self.stack_get(1);
        let ptr = self.stack_get(0);
        let ctx = self.ctx;
        let circuit_evaluation = eval_circuit_fast_(
            ctx,
            ptr,
            self.clk,
            num_read,
            num_eval,
            &mut self.memory,
            err_ctx,
            tracer,
        )?;
        self.ace.add_circuit_evaluation(self.clk, circuit_evaluation.clone());
        tracer.record_circuit_evaluation(self.clk, circuit_evaluation);

        Ok(())
    }
}

impl HasherInterface for FastProcessor {
    #[inline(always)]
    fn permute(&mut self, mut input_state: HasherState) -> (Felt, HasherState) {
        Rpo256::apply_permutation(&mut input_state);

        // Return a default value for the address, as it is not needed in trace generation.
        (ZERO, input_state)
    }

    #[inline(always)]
    fn verify_merkle_root(
        &mut self,
        claimed_root: Word,
        value: Word,
        path: Option<&MerklePath>,
        index: Felt,
        on_err: impl FnOnce() -> ExecutionError,
    ) -> Result<Felt, ExecutionError> {
        let path = path.expect("fast processor expects a valid Merkle path");
        match path.verify(index.as_canonical_u64(), value, &claimed_root) {
            // Return a default value for the address, as it is not needed in trace generation.
            Ok(_) => Ok(ZERO),
            Err(_) => Err(on_err()),
        }
    }

    #[inline(always)]
    fn update_merkle_root(
        &mut self,
        claimed_old_root: Word,
        old_value: Word,
        new_value: Word,
        path: Option<&MerklePath>,
        index: Felt,
        on_err: impl FnOnce() -> ExecutionError,
    ) -> Result<(Felt, Word), ExecutionError> {
        let path = path.expect("fast processor expects a valid Merkle path");

        // Verify the old value against the claimed old root.
        if path.verify(index.as_canonical_u64(), old_value, &claimed_old_root).is_err() {
            return Err(on_err());
        };

        // Compute the new root.
        let new_root =
            path.compute_root(index.as_canonical_u64(), new_value).map_err(|_| on_err())?;

        Ok((ZERO, new_root))
    }
}

impl SystemInterface for FastProcessor {
    #[inline(always)]
    fn caller_hash(&self) -> Word {
        self.caller_hash
    }

    #[inline(always)]
    fn clk(&self) -> RowIndex {
        self.clk
    }

    #[inline(always)]
    fn ctx(&self) -> ContextId {
        self.ctx
    }
}

impl StackInterface for FastProcessor {
    #[inline(always)]
    fn top(&self) -> &[Felt] {
        self.stack_top()
    }

    #[inline(always)]
    fn get(&self, idx: usize) -> Felt {
        self.stack_get(idx)
    }

    #[inline(always)]
    fn get_mut(&mut self, idx: usize) -> &mut Felt {
        self.stack_get_mut(idx)
    }

    #[inline(always)]
    fn get_word(&self, start_idx: usize) -> Word {
        self.stack_get_word(start_idx)
    }

    #[inline(always)]
    fn depth(&self) -> u32 {
        self.stack_depth()
    }

    #[inline(always)]
    fn set(&mut self, idx: usize, element: Felt) {
        self.stack_write(idx, element)
    }

    #[inline(always)]
    fn set_word(&mut self, start_idx: usize, word: &Word) {
        self.stack_write_word(start_idx, word);
    }

    #[inline(always)]
    fn swap(&mut self, idx1: usize, idx2: usize) {
        self.stack_swap(idx1, idx2)
    }

    #[inline(always)]
    fn swapw_nth(&mut self, n: usize) {
        // For example, for n=3, the stack words and variables look like:
        //    3     2     1     0
        // | ... | ... | ... | ... |
        // ^                 ^
        // nth_word       top_word
        let (rest_of_stack, top_word) = self.stack.split_at_mut(self.stack_top_idx - WORD_SIZE);
        let (_, nth_word) = rest_of_stack.split_at_mut(rest_of_stack.len() - n * WORD_SIZE);

        nth_word[0..WORD_SIZE].swap_with_slice(&mut top_word[0..WORD_SIZE]);
    }

    #[inline(always)]
    fn rotate_left(&mut self, n: usize) {
        let rotation_bot_index = self.stack_top_idx - n;
        let new_stack_top_element = self.stack[rotation_bot_index];

        // shift the top n elements down by 1, starting from the bottom of the rotation.
        for i in 0..n - 1 {
            self.stack[rotation_bot_index + i] = self.stack[rotation_bot_index + i + 1];
        }

        // Set the top element (which comes from the bottom of the rotation).
        self.stack_write(0, new_stack_top_element);
    }

    #[inline(always)]
    fn rotate_right(&mut self, n: usize) {
        let rotation_bot_index = self.stack_top_idx - n;
        let new_stack_bot_element = self.stack[self.stack_top_idx - 1];

        // shift the top n elements up by 1, starting from the top of the rotation.
        for i in 1..n {
            self.stack[self.stack_top_idx - i] = self.stack[self.stack_top_idx - i - 1];
        }

        // Set the bot element (which comes from the top of the rotation).
        self.stack[rotation_bot_index] = new_stack_bot_element;
    }

    #[inline(always)]
    fn increment_size(&mut self, tracer: &mut impl Tracer) -> Result<(), ExecutionError> {
        if self.stack_top_idx < STACK_BUFFER_SIZE - 1 {
            self.increment_stack_size(tracer);
            Ok(())
        } else {
            Err(ExecutionError::Internal("stack overflow"))
        }
    }

    #[inline(always)]
    fn decrement_size(&mut self, tracer: &mut impl Tracer) {
        self.decrement_stack_size(tracer)
    }
}

pub struct NoopHelperRegisters;

/// Dummy helpers implementation used in the fast processor, where we don't compute the helper
/// registers. These are expected to be ignored.
const DEFAULT_HELPERS: [Felt; NUM_USER_OP_HELPERS] = [ZERO; NUM_USER_OP_HELPERS];

impl OperationHelperRegisters for NoopHelperRegisters {
    #[inline(always)]
    fn op_eq_registers(_a: Felt, _b: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }

    #[inline(always)]
    fn op_u32split_registers(_hi: Felt, _lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }

    #[inline(always)]
    fn op_eqz_registers(_top: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }

    #[inline(always)]
    fn op_expacc_registers(_acc_update_val: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }

    #[inline(always)]
    fn op_fri_ext2fold4_registers(
        _ev: QuadFelt,
        _es: QuadFelt,
        _x: Felt,
        _x_inv: Felt,
    ) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }

    #[inline(always)]
    fn op_u32add_registers(_hi: Felt, _lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }

    #[inline(always)]
    fn op_u32add3_registers(_hi: Felt, _lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }

    #[inline(always)]
    fn op_u32sub_registers(_second_new: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }

    #[inline(always)]
    fn op_u32mul_registers(_hi: Felt, _lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }

    #[inline(always)]
    fn op_u32madd_registers(_hi: Felt, _lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }

    #[inline(always)]
    fn op_u32div_registers(_hi: Felt, _lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }

    #[inline(always)]
    fn op_u32assert2_registers(_first: Felt, _second: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }

    #[inline(always)]
    fn op_hperm_registers(_addr: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }

    #[inline(always)]
    fn op_log_precompile_registers(_addr: Felt, _cap_prev: Word) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }

    #[inline(always)]
    fn op_merkle_path_registers(_addr: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }

    #[inline(always)]
    fn op_horner_eval_base_registers(
        _alpha: QuadFelt,
        _tmp0: QuadFelt,
        _tmp1: QuadFelt,
    ) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }

    #[inline(always)]
    fn op_horner_eval_ext_registers(
        _alpha: QuadFelt,
        _k0: Felt,
        _k1: Felt,
        _acc_tmp: QuadFelt,
    ) -> [Felt; NUM_USER_OP_HELPERS] {
        DEFAULT_HELPERS
    }
}

// HELPERS
// ================================================================================================

/// Identical to `[chiplets::ace::eval_circuit]` but adapted for use with `[FastProcessor]`.
pub fn eval_circuit_fast_(
    ctx: ContextId,
    ptr: Felt,
    clk: RowIndex,
    num_vars: Felt,
    num_eval: Felt,
    mem: &mut impl MemoryInterface,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<CircuitEvaluation, ExecutionError> {
    let num_vars = num_vars.as_canonical_u64();
    let num_eval = num_eval.as_canonical_u64();

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

    let mut evaluation_context = CircuitEvaluation::new(ctx, clk, num_read_rows, num_eval_rows);

    let mut ptr = ptr;
    // perform READ operations
    // Note: we pass in a `NoopTracer`, because the parallel trace generation skips the circuit
    // evaluation completely
    for _ in 0..num_read_rows {
        let word = mem.read_word(ctx, ptr, clk, err_ctx).map_err(ExecutionError::MemoryError)?;
        tracer.record_memory_read_word(word, ptr, ctx, clk);
        evaluation_context.do_read(ptr, word)?;
        ptr += PTR_OFFSET_WORD;
    }
    // perform EVAL operations
    for _ in 0..num_eval_rows {
        let instruction =
            mem.read_element(ctx, ptr, err_ctx).map_err(ExecutionError::MemoryError)?;
        tracer.record_memory_read_element(instruction, ptr, ctx, clk);
        evaluation_context.do_eval(ptr, instruction, err_ctx)?;
        ptr += PTR_OFFSET_ELEM;
    }

    // Ensure the circuit evaluated to zero.
    if evaluation_context.output_value().is_none_or(|eval| eval != QuadFelt::ZERO) {
        return Err(ExecutionError::failed_arithmetic_evaluation(
            err_ctx,
            AceError::CircuitNotEvaluateZero,
        ));
    }

    Ok(evaluation_context)
}
