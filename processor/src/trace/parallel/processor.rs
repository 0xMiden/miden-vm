use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_air::{Felt, trace::RowIndex};
use miden_core::{
    WORD_SIZE, Word, ZERO,
    field::PrimeField64,
    mast::{BasicBlockNode, MastForest, MastNodeId},
    precompile::PrecompileTranscriptState,
    program::{Kernel, MIN_STACK_DEPTH},
    utils::range,
};

use super::super::trace_state::{
    AdviceReplay, ExecutionContextReplay, HasherResponseReplay, MastForestResolutionReplay,
    MemoryReadsReplay, StackOverflowReplay, StackState, SystemState,
};
use crate::{
    BreakReason, ContextId, ExecutionError, Host, Stopper,
    continuation_stack::{Continuation, ContinuationStack},
    errors::{AceEvalError, OperationError},
    execution::{
        InternalBreakReason, execute_impl, finish_emit_op_execution,
        finish_load_mast_forest_from_dyn_start, finish_load_mast_forest_from_external,
    },
    host::default::NoopHost,
    processor::{Processor, StackInterface, SystemInterface},
    trace::parallel::core_trace_fragment::eval_circuit_parallel_,
    tracer::Tracer,
};

// REPLAY PROCESSOR
// ================================================================================================

/// A processor implementation used in conjunction with the [`CoreTraceGenerationTracer`] in
/// [`super::build_trace`] to replay the execution of a fragment of execution for a predetermined
/// number of clock cycles.
///
/// This processor uses various "replay" structures to provide the necessary state during execution,
/// such as stack overflows, memory reads, advice provider values, hasher responses, execution
/// contexts, and MAST forest resolutions. The processor executes until it reaches the specified
/// maximum clock cycle, at which point it stops execution (due to the [`ReplayStopper`]).
///
/// The replay structures and initial system and stack state are built by the
/// [`crate::execution_tracer::ExecutionTracer`] in conjunction with
/// [`crate::FastProcessor::execute_for_trace`].
#[derive(Debug)]
pub(crate) struct ReplayProcessor {
    pub system: SystemState,
    pub stack: StackState,
    pub stack_overflow_replay: StackOverflowReplay,
    pub execution_context_replay: ExecutionContextReplay,
    pub advice_replay: AdviceReplay,
    pub memory_reads_replay: MemoryReadsReplay,
    pub hasher_response_replay: HasherResponseReplay,
    pub mast_forest_resolution_replay: MastForestResolutionReplay,

    /// The maximum clock cycle at which this processor should stop execution.
    pub maximum_clock: RowIndex,
}

impl ReplayProcessor {
    /// Creates a new instance of the [`ReplayProcessor`].
    ///
    /// The parameters are expected to be built by the
    /// [`crate::execution_tracer::ExecutionTracer`] when used in conjunction with
    /// [`crate::FastProcessor::execute_for_trace`].
    pub fn new(
        initial_system: SystemState,
        initial_stack: StackState,
        stack_overflow_replay: StackOverflowReplay,
        execution_context_replay: ExecutionContextReplay,
        advice_replay: AdviceReplay,
        memory_reads_replay: MemoryReadsReplay,
        hasher_response_replay: HasherResponseReplay,
        mast_forest_resolution_replay: MastForestResolutionReplay,
        num_clocks_to_execute: RowIndex,
    ) -> Self {
        let maximum_clock = initial_system.clk + num_clocks_to_execute.as_usize();

        Self {
            system: initial_system,
            stack: initial_stack,
            stack_overflow_replay,
            execution_context_replay,
            advice_replay,
            memory_reads_replay,
            hasher_response_replay,
            mast_forest_resolution_replay,
            maximum_clock,
        }
    }

    /// Executes the processor until it reaches the end of the fragment, or until an error occurs.
    pub fn execute<T>(
        &mut self,
        continuation_stack: &mut ContinuationStack,
        current_forest: &mut Arc<MastForest>,
        kernel: &Kernel,
        tracer: &mut T,
    ) -> Result<(), ExecutionError>
    where
        T: Tracer<Processor = Self>,
    {
        match self.execute_impl(continuation_stack, current_forest, kernel, tracer) {
            ControlFlow::Continue(_) => {
                // End of program reached - i.e. the execution loop exited without the end of
                // fragment being reached (and thus the stopper breaking).
                Ok(())
            },
            ControlFlow::Break(break_reason) => match break_reason {
                BreakReason::Err(err) => Err(err),
                BreakReason::Stopped(_continuation) => {
                    // Our ReplayStopper stopped us because we reached the end of the fragment.
                    // Hence, this is expected, and we can just return Ok.
                    Ok(())
                },
            },
        }
    }

    /// Core execution loop implementation for the replay processor.
    ///
    /// This method uses the [`crate::execution::execute_impl`] function to perform the core
    /// execution loop. See its documentation for more details.
    fn execute_impl<T>(
        &mut self,
        continuation_stack: &mut ContinuationStack,
        current_forest: &mut Arc<MastForest>,
        kernel: &Kernel,
        tracer: &mut T,
    ) -> ControlFlow<BreakReason>
    where
        T: Tracer<Processor = Self>,
    {
        let host = &mut NoopHost;
        let stopper = &ReplayStopper;

        while let ControlFlow::Break(internal_break_reason) =
            execute_impl(self, continuation_stack, current_forest, kernel, host, tracer, stopper)
        {
            match internal_break_reason {
                InternalBreakReason::User(break_reason) => return ControlFlow::Break(break_reason),
                InternalBreakReason::Emit { basic_block_node_id: _, continuation } => {
                    // do nothing - in replay processor we don't need to emit anything

                    // Call `finish_emit_op_execution()`, as per the sans-IO contract.
                    finish_emit_op_execution(
                        continuation,
                        self,
                        continuation_stack,
                        current_forest,
                        tracer,
                        stopper,
                    )?;
                },
                InternalBreakReason::LoadMastForestFromDyn { .. } => {
                    // load mast forest from replay
                    let (root_id, new_forest) =
                        self.mast_forest_resolution_replay.replay_resolution();

                    // Finish loading the MAST forest from the Dyn node, as per the sans-IO
                    // contract.
                    finish_load_mast_forest_from_dyn_start(
                        root_id,
                        new_forest,
                        self,
                        current_forest,
                        continuation_stack,
                        tracer,
                        stopper,
                    )?;
                },
                InternalBreakReason::LoadMastForestFromExternal {
                    external_node_id,
                    procedure_hash: _,
                } => {
                    // load mast forest from replay
                    let (root_id, new_forest) =
                        self.mast_forest_resolution_replay.replay_resolution();

                    // Finish loading the MAST forest from the External node, as per the sans-IO
                    // contract.
                    finish_load_mast_forest_from_external(
                        root_id,
                        new_forest,
                        external_node_id,
                        current_forest,
                        continuation_stack,
                        host,
                        tracer,
                    )?;
                },
            }
        }

        // End of program reached (since loop exited without the stopper breaking)
        ControlFlow::Continue(())
    }
}

impl SystemInterface for ReplayProcessor {
    fn caller_hash(&self) -> Word {
        self.system.fn_hash
    }

    fn clock(&self) -> RowIndex {
        self.system.clk
    }

    fn ctx(&self) -> ContextId {
        self.system.ctx
    }

    fn set_caller_hash(&mut self, caller_hash: Word) {
        self.system.fn_hash = caller_hash;
    }

    fn set_ctx(&mut self, ctx: ContextId) {
        self.system.ctx = ctx;
    }

    fn increment_clock(&mut self) {
        self.system.clk += 1_u32;
    }
}

impl StackInterface for ReplayProcessor {
    type Processor = Self;

    fn top(&self) -> &[Felt] {
        &self.stack.stack_top
    }

    fn get(&self, idx: usize) -> Felt {
        debug_assert!(idx < MIN_STACK_DEPTH);
        self.stack.stack_top[MIN_STACK_DEPTH - idx - 1]
    }

    fn get_mut(&mut self, idx: usize) -> &mut Felt {
        debug_assert!(idx < MIN_STACK_DEPTH);

        &mut self.stack.stack_top[MIN_STACK_DEPTH - idx - 1]
    }

    fn get_word(&self, start_idx: usize) -> Word {
        debug_assert!(start_idx < MIN_STACK_DEPTH - 4);

        let word_start_idx = MIN_STACK_DEPTH - start_idx - 4;
        let mut result: [Felt; WORD_SIZE] =
            self.top()[range(word_start_idx, WORD_SIZE)].try_into().unwrap();
        // Reverse so top of stack (idx 0) goes to word[0]
        result.reverse();
        result.into()
    }

    fn depth(&self) -> u32 {
        (MIN_STACK_DEPTH + self.stack.num_overflow_elements_in_current_ctx()) as u32
    }

    fn set(&mut self, idx: usize, element: Felt) {
        *self.get_mut(idx) = element;
    }

    fn set_word(&mut self, start_idx: usize, word: &Word) {
        debug_assert!(start_idx < MIN_STACK_DEPTH - 4);
        let word_start_idx = MIN_STACK_DEPTH - start_idx - 4;

        // Reverse so word[0] ends up at the top of stack (highest internal index)
        let mut source: [Felt; WORD_SIZE] = (*word).into();
        source.reverse();

        let word_on_stack = &mut self.stack.stack_top[range(word_start_idx, WORD_SIZE)];
        word_on_stack.copy_from_slice(&source);
    }

    fn swap(&mut self, idx1: usize, idx2: usize) {
        let a = self.get(idx1);
        let b = self.get(idx2);
        self.set(idx1, b);
        self.set(idx2, a);
    }

    fn swapw_nth(&mut self, n: usize) {
        // For example, for n=3, the stack words and variables look like:
        //    3     2     1     0
        // | ... | ... | ... | ... |
        // ^                 ^
        // nth_word       top_word
        let (rest_of_stack, top_word) =
            self.stack.stack_top.split_at_mut(MIN_STACK_DEPTH - WORD_SIZE);
        let (_, nth_word) = rest_of_stack.split_at_mut(rest_of_stack.len() - n * WORD_SIZE);

        nth_word[0..WORD_SIZE].swap_with_slice(&mut top_word[0..WORD_SIZE]);
    }

    fn rotate_left(&mut self, n: usize) {
        let rotation_bot_index = MIN_STACK_DEPTH - n;
        let new_stack_top_element = self.stack.stack_top[rotation_bot_index];

        // shift the top n elements down by 1, starting from the bottom of the rotation.
        for i in 0..n - 1 {
            self.stack.stack_top[rotation_bot_index + i] =
                self.stack.stack_top[rotation_bot_index + i + 1];
        }

        // Set the top element (which comes from the bottom of the rotation).
        self.set(0, new_stack_top_element);
    }

    fn rotate_right(&mut self, n: usize) {
        let rotation_bot_index = MIN_STACK_DEPTH - n;
        let new_stack_bot_element = self.stack.stack_top[MIN_STACK_DEPTH - 1];

        // shift the top n elements up by 1, starting from the top of the rotation.
        for i in 1..n {
            self.stack.stack_top[MIN_STACK_DEPTH - i] =
                self.stack.stack_top[MIN_STACK_DEPTH - i - 1];
        }

        // Set the bot element (which comes from the top of the rotation).
        self.stack.stack_top[rotation_bot_index] = new_stack_bot_element;
    }

    fn increment_size<T>(&mut self, _tracer: &mut T) -> Result<(), ExecutionError>
    where
        T: Tracer<Processor = Self>,
    {
        const SENTINEL_VALUE: Felt = Felt::new(Felt::ORDER_U64 - 1);

        // push the last element on the overflow table
        {
            let last_element = self.get(MIN_STACK_DEPTH - 1);
            self.stack.push_overflow(last_element, self.clock());
        }

        // Shift all other elements down
        for write_idx in (1..MIN_STACK_DEPTH).rev() {
            let read_idx = write_idx - 1;
            self.set(write_idx, self.get(read_idx));
        }

        // Set the top element to SENTINEL_VALUE to help in debugging. Per the method docs, this
        // value will be overwritten
        self.set(0, SENTINEL_VALUE);

        Ok(())
    }

    fn decrement_size<T>(&mut self, _tracer: &mut T)
    where
        T: Tracer<Processor = Self>,
    {
        // Shift all other elements up
        for write_idx in 0..(MIN_STACK_DEPTH - 1) {
            let read_idx = write_idx + 1;
            self.set(write_idx, self.get(read_idx));
        }

        // Pop the last element from the overflow table
        if let Some(last_element) = self.stack.pop_overflow(&mut self.stack_overflow_replay) {
            // Write the last element to the bottom of the stack
            self.set(MIN_STACK_DEPTH - 1, last_element);
        } else {
            // If overflow table is empty, set the bottom element to zero
            self.set(MIN_STACK_DEPTH - 1, ZERO);
        }
    }
}

impl Processor for ReplayProcessor {
    type System = Self;
    type Stack = Self;
    type AdviceProvider = AdviceReplay;
    type Memory = MemoryReadsReplay;
    type Hasher = HasherResponseReplay;

    fn stack(&self) -> &Self::Stack {
        self
    }

    fn stack_mut(&mut self) -> &mut Self::Stack {
        self
    }

    fn system(&self) -> &Self::System {
        self
    }

    fn system_mut(&mut self) -> &mut Self::System {
        self
    }

    fn advice_provider(&self) -> &Self::AdviceProvider {
        &self.advice_replay
    }

    fn advice_provider_mut(&mut self) -> &mut Self::AdviceProvider {
        &mut self.advice_replay
    }

    fn memory_mut(&mut self) -> &mut Self::Memory {
        &mut self.memory_reads_replay
    }

    fn hasher(&mut self) -> &mut Self::Hasher {
        &mut self.hasher_response_replay
    }

    fn save_context_and_truncate_stack(&mut self, tracer: &mut impl Tracer) {
        self.stack.start_context();
        tracer.start_context();
    }

    fn restore_context(&mut self, tracer: &mut impl Tracer) -> Result<(), OperationError> {
        let ctx_info = self.execution_context_replay.replay_execution_context();

        // Restore system state
        self.system_mut().set_ctx(ctx_info.parent_ctx);
        self.system_mut().set_caller_hash(ctx_info.parent_fn_hash);

        // Restore stack state
        self.stack.restore_context(&mut self.stack_overflow_replay);

        // Update tracer
        tracer.restore_context();

        Ok(())
    }

    fn precompile_transcript_state(&self) -> PrecompileTranscriptState {
        self.system.pc_transcript_state
    }

    fn set_precompile_transcript_state(&mut self, state: PrecompileTranscriptState) {
        self.system.pc_transcript_state = state;
    }

    fn op_eval_circuit(&mut self, tracer: &mut impl Tracer) -> Result<(), AceEvalError> {
        let num_eval = self.stack().get(2);
        let num_read = self.stack().get(1);
        let ptr = self.stack().get(0);
        let ctx = self.system().ctx();

        let _circuit_evaluation = eval_circuit_parallel_(
            ctx,
            ptr,
            self.system().clock(),
            num_read,
            num_eval,
            self.memory_mut(),
            tracer,
        )?;

        Ok(())
    }

    fn execute_before_enter_decorators(
        &mut self,
        _node_id: MastNodeId,
        _current_forest: &MastForest,
        _host: &mut impl Host,
    ) -> ControlFlow<BreakReason> {
        // do nothing - we don't execute decorators in this processor
        ControlFlow::Continue(())
    }

    fn execute_after_exit_decorators(
        &mut self,
        _node_id: MastNodeId,
        _current_forest: &MastForest,
        _host: &mut impl Host,
    ) -> ControlFlow<BreakReason> {
        // do nothing - we don't execute decorators in this processor
        ControlFlow::Continue(())
    }

    fn execute_decorators_for_op(
        &mut self,
        _node_id: MastNodeId,
        _op_idx_in_block: usize,
        _current_forest: &MastForest,
        _host: &mut impl Host,
    ) -> ControlFlow<BreakReason> {
        // do nothing - we don't execute decorators in this processor
        ControlFlow::Continue(())
    }

    fn execute_end_of_block_decorators(
        &mut self,
        _basic_block_node: &BasicBlockNode,
        _node_id: MastNodeId,
        _current_forest: &Arc<MastForest>,
        _host: &mut impl Host,
    ) -> ControlFlow<BreakReason> {
        // do nothing - we don't execute decorators in this processor
        ControlFlow::Continue(())
    }
}

// REPLAY STOPPER
// ================================================================================================

/// A stopper implementation used with the [`ReplayProcessor`] to stop execution when the end of the
/// fragment is reached.
#[derive(Debug)]
pub(crate) struct ReplayStopper;

impl Stopper for ReplayStopper {
    type Processor = ReplayProcessor;

    fn should_stop(
        &self,
        processor: &ReplayProcessor,
        continuation_after_stop: impl FnOnce() -> Option<Continuation>,
    ) -> ControlFlow<BreakReason> {
        if processor.system().clock() >= processor.maximum_clock {
            ControlFlow::Break(BreakReason::Stopped(continuation_after_stop()))
        } else {
            ControlFlow::Continue(())
        }
    }
}
