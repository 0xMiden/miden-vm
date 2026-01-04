use alloc::sync::Arc;

use miden_air::trace::{RowIndex, chiplets::hasher::STATE_WIDTH};
use miden_core::{
    Felt, Word,
    crypto::merkle::MerklePath,
    mast::{MastForest, MastNodeId},
};

use crate::{
    chiplets::CircuitEvaluation,
    continuation_stack::ContinuationStack,
    fast::{FastProcessor, trace_state::NodeExecutionState},
    system::ContextId,
};

/// A trait for tracing the execution of a [FastProcessor].
pub trait Tracer {
    /// Signals the start of a new clock cycle.
    ///
    /// This is guaranteed to be called before executing the operation at the given clock cycle.
    /// Additionally, [miden_core::mast::ExternalNode] nodes are guaranteed to be resolved before
    /// this method is called.
    fn start_clock_cycle(
        &mut self,
        processor: &FastProcessor,
        execution_state: NodeExecutionState,
        continuation_stack: &ContinuationStack,
        current_forest: &Arc<MastForest>,
    );

    /// Records and replays the resolutions of [crate::host::AsyncHost::get_mast_forest] or
    /// [crate::host::SyncHost::get_mast_forest].
    ///
    /// Note that when execution encounters a [miden_core::mast::ExternalNode], the external node
    /// gets resolved to the MAST node it refers to in the new MAST forest, without consuming the
    /// clock cycle (or writing anything to the trace). Hence, a clock cycle where execution
    /// encounters an external node effectively has 2 nodes associated with it.
    /// [Tracer::start_clock_cycle] is called on the resolved node (i.e. *not* the external node).
    /// This method is called on the external node before it is resolved, and hence is guaranteed to
    /// be called before [Tracer::start_clock_cycle] for clock cycles involving an external node.
    fn record_mast_forest_resolution(&mut self, node_id: MastNodeId, forest: &Arc<MastForest>);

    // HASHER METHODS
    // -----------------------------------------------

    /// Records the result of a call to `Hasher::permute()`.
    fn record_hasher_permute(
        &mut self,
        input_state: [Felt; STATE_WIDTH],
        output_state: [Felt; STATE_WIDTH],
    );

    /// Records the result of a call to `Hasher::build_merkle_root()`.
    ///
    /// The `path` is an `Option` to support environments where the `Hasher` is not present, such as
    /// in the context of parallel trace generation.
    fn record_hasher_build_merkle_root(
        &mut self,
        node: Word,
        path: Option<&MerklePath>,
        index: Felt,
        output_root: Word,
    );

    /// Records the result of a call to `Hasher::update_merkle_root()`.
    ///
    /// The `path` is an `Option` to support environments where the `Hasher` is not present, such as
    /// in the context of parallel trace generation.
    fn record_hasher_update_merkle_root(
        &mut self,
        old_value: Word,
        new_value: Word,
        path: Option<&MerklePath>,
        index: Felt,
        old_root: Word,
        new_root: Word,
    );

    // MEMORY METHODS
    // -----------------------------------------------

    /// Records the element read from memory at the given address.
    fn record_memory_read_element(
        &mut self,
        element: Felt,
        addr: Felt,
        ctx: ContextId,
        clk: RowIndex,
    );

    /// Records the word read from memory at the given address.
    fn record_memory_read_word(&mut self, word: Word, addr: Felt, ctx: ContextId, clk: RowIndex);

    /// Records the element written to memory at the given address.
    fn record_memory_write_element(
        &mut self,
        element: Felt,
        addr: Felt,
        ctx: ContextId,
        clk: RowIndex,
    );

    /// Records the word written to memory at the given address.
    fn record_memory_write_word(&mut self, word: Word, addr: Felt, ctx: ContextId, clk: RowIndex);

    // ADVICE PROVIDER METHODS
    // -----------------------------------------------

    /// Records the value returned by a [crate::host::advice::AdviceProvider::pop_stack] operation.
    fn record_advice_pop_stack(&mut self, value: Felt);
    /// Records the value returned by a [crate::host::advice::AdviceProvider::pop_stack_word]
    /// operation.
    fn record_advice_pop_stack_word(&mut self, word: Word);
    /// Records the value returned by a [crate::host::advice::AdviceProvider::pop_stack_dword]
    /// operation.
    fn record_advice_pop_stack_dword(&mut self, words: [Word; 2]);

    // U32 METHODS
    // -----------------------------------------------

    /// Records the operands of a u32and operation.
    fn record_u32and(&mut self, a: Felt, b: Felt);

    /// Records the operands of a u32xor operation.
    fn record_u32xor(&mut self, a: Felt, b: Felt);

    /// Records the high and low 32-bit limbs of the result of a u32 operation for the purposes of
    /// the range checker. This is expected to result in four 16-bit range checks.
    fn record_u32_range_checks(&mut self, clk: RowIndex, u32_lo: Felt, u32_hi: Felt);

    // KERNEL METHODS
    // -----------------------------------------------

    /// Records the procedure hash of a syscall.
    fn record_kernel_proc_access(&mut self, proc_hash: Word);

    // ACE CHIPLET METHODS
    // -----------------------------------------------

    /// Records the evaluation of a circuit.
    fn record_circuit_evaluation(&mut self, clk: RowIndex, circuit_eval: CircuitEvaluation);

    // MISCELLANEOUS
    // -----------------------------------------------

    /// Signals that the processor clock is being incremented.
    fn increment_clk(&mut self);

    /// Signals that the stack depth is incremented as a result of pushing a new element.
    fn increment_stack_size(&mut self, processor: &FastProcessor);

    /// Signals that the stack depth is decremented as a result of popping an element off the stack.
    ///
    /// Note that if the stack depth is already [miden_core::stack::MIN_STACK_DEPTH], then the stack
    /// depth is unchanged; the top element is popped off, and a ZERO is shifted in at the bottom.
    fn decrement_stack_size(&mut self);

    /// Signals the start of a new execution context, as a result of a CALL, SYSCALL or DYNCALL
    /// operation being executed.
    fn start_context(&mut self);

    /// Signals the end of an execution context, as a result of an END operation associated with a
    /// CALL, SYSCALL or DYNCALL.
    fn restore_context(&mut self);
}

/// A [Tracer] that does nothing.
pub struct NoopTracer;

impl Tracer for NoopTracer {
    #[inline(always)]
    fn start_clock_cycle(
        &mut self,
        _processor: &FastProcessor,
        _execution_state: NodeExecutionState,
        _continuation_stack: &ContinuationStack,
        _current_forest: &Arc<MastForest>,
    ) {
        // do nothing
    }

    #[inline(always)]
    fn record_mast_forest_resolution(&mut self, _node_id: MastNodeId, _forest: &Arc<MastForest>) {
        // do nothing
    }

    #[inline(always)]
    fn record_hasher_permute(
        &mut self,
        _input_state: [Felt; STATE_WIDTH],
        _output_state: [Felt; STATE_WIDTH],
    ) {
        // do nothing
    }

    #[inline(always)]
    fn record_hasher_build_merkle_root(
        &mut self,
        _node: Word,
        _path: Option<&MerklePath>,
        _index: Felt,
        _output_root: Word,
    ) {
        // do nothing
    }

    #[inline(always)]
    fn record_hasher_update_merkle_root(
        &mut self,
        _old_node: Word,
        _new_node: Word,
        _path: Option<&MerklePath>,
        _index: Felt,
        _old_root: Word,
        _new_root: Word,
    ) {
        // do nothing
    }

    #[inline(always)]
    fn record_memory_read_element(
        &mut self,
        _element: Felt,
        _addr: Felt,
        _ctx: ContextId,
        _clk: RowIndex,
    ) {
        // do nothing
    }

    #[inline(always)]
    fn record_memory_read_word(
        &mut self,
        _word: Word,
        _addr: Felt,
        _ctx: ContextId,
        _clk: RowIndex,
    ) {
        // do nothing
    }

    #[inline(always)]
    fn record_memory_write_element(
        &mut self,
        _element: Felt,
        _addr: Felt,
        _ctx: ContextId,
        _clk: RowIndex,
    ) {
        // do nothing
    }

    #[inline(always)]
    fn record_memory_write_word(
        &mut self,
        _word: Word,
        _addr: Felt,
        _ctx: ContextId,
        _clk: RowIndex,
    ) {
        // do nothing
    }

    #[inline(always)]
    fn record_advice_pop_stack(&mut self, _value: Felt) {
        // do nothing
    }

    #[inline(always)]
    fn record_advice_pop_stack_word(&mut self, _word: Word) {
        // do nothing
    }

    #[inline(always)]
    fn record_advice_pop_stack_dword(&mut self, _words: [Word; 2]) {
        // do nothing
    }

    #[inline(always)]
    fn record_u32and(&mut self, _a: Felt, _b: Felt) {
        // do nothing
    }

    #[inline(always)]
    fn record_u32xor(&mut self, _a: Felt, _b: Felt) {
        // do nothing
    }

    #[inline(always)]
    fn record_u32_range_checks(&mut self, _clk: RowIndex, _u32_lo: Felt, _u32_hi: Felt) {
        // do nothing
    }

    #[inline(always)]
    fn record_kernel_proc_access(&mut self, _proc_hash: Word) {
        // do nothing
    }

    #[inline(always)]
    fn record_circuit_evaluation(&mut self, _clk: RowIndex, _circuit_eval: CircuitEvaluation) {
        // do nothing
    }

    #[inline(always)]
    fn increment_clk(&mut self) {
        // do nothing
    }

    #[inline(always)]
    fn increment_stack_size(&mut self, _processor: &FastProcessor) {
        // do nothing
    }

    #[inline(always)]
    fn decrement_stack_size(&mut self) {
        // do nothing
    }

    #[inline(always)]
    fn start_context(&mut self) {
        // do nothing
    }

    #[inline(always)]
    fn restore_context(&mut self) {
        // do nothing
    }
}
