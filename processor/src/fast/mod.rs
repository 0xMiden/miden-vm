#[cfg(test)]
use alloc::rc::Rc;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
#[cfg(test)]
use core::cell::Cell;
use core::{cmp::min, ops::ControlFlow};

use miden_air::{Felt, trace::RowIndex};
use miden_core::{
    EMPTY_WORD, WORD_SIZE, Word, ZERO,
    mast::{MastForest, MastNodeExt, MastNodeId},
    operations::Decorator,
    precompile::PrecompileTranscript,
    program::{Kernel, Program},
    stack::{MIN_STACK_DEPTH, StackInputs, StackOutputs},
    utils::range,
};
use tracing::instrument;

use crate::{
    AdviceInputs, AdviceProvider, ContextId, ExecutionError, ExecutionOptions, Host,
    ProcessorState, Stopper,
    chiplets::Ace,
    continuation_stack::ContinuationStack,
    errors::{MapExecErr, MapExecErrNoCtx, OperationError},
    execution::{
        InternalBreakReason, execute_impl, finish_emit_op_execution,
        finish_load_mast_forest_from_dyn_start, finish_load_mast_forest_from_external,
    },
    fast::{
        execution_tracer::{ExecutionTracer, TraceGenerationContext},
        external::maybe_use_caller_error_context,
        step::{BreakReason, NeverStopper, StepStopper},
    },
    tracer::{NoopTracer, Tracer},
};

pub mod execution_tracer;
mod memory;
pub use memory::Memory;

mod operation;
pub use operation::eval_circuit_fast_;

pub(crate) mod step;
pub use step::ResumeContext;

pub mod trace_state;

mod basic_block;
mod call_and_dyn;
mod external;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// The size of the stack buffer.
///
/// Note: This value is much larger than it needs to be for the majority of programs. However, some
/// existing programs need it, so we're forced to push it up (though this should be double-checked).
/// At this high a value, we're starting to see some performance degradation on benchmarks. For
/// example, the blake3 benchmark went from 285 MHz to 250 MHz (~10% degradation). Perhaps a better
/// solution would be to make this value much smaller (~1000), and then fallback to a `Vec` if the
/// stack overflows.
const STACK_BUFFER_SIZE: usize = 6850;

/// The initial position of the top of the stack in the stack buffer.
///
/// We place this value close to 0 because if a program hits the limit, it's much more likely to hit
/// the upper bound than the lower bound, since hitting the lower bound only occurs when you drop
/// 0's that were generated automatically to keep the stack depth at 16. In practice, if this
/// occurs, it is most likely a bug.
const INITIAL_STACK_TOP_IDX: usize = 250;

// FAST PROCESSOR
// ================================================================================================

/// A fast processor which doesn't generate any trace.
///
/// This processor is designed to be as fast as possible. Hence, it only keeps track of the current
/// state of the processor (i.e. the stack, current clock cycle, current memory context, and free
/// memory pointer).
///
/// # Stack Management
/// A few key points about how the stack was designed for maximum performance:
///
/// - The stack has a fixed buffer size defined by `STACK_BUFFER_SIZE`.
///     - This was observed to increase performance by at least 2x compared to using a `Vec` with
///       `push()` & `pop()`.
///     - We track the stack top and bottom using indices `stack_top_idx` and `stack_bot_idx`,
///       respectively.
/// - Since we are using a fixed-size buffer, we need to ensure that stack buffer accesses are not
///   out of bounds. Naively, we could check for this on every access. However, every operation
///   alters the stack depth by a predetermined amount, allowing us to precisely determine the
///   minimum number of operations required to reach a stack buffer boundary, whether at the top or
///   bottom.
///     - For example, if the stack top is 10 elements away from the top boundary, and the stack
///       bottom is 15 elements away from the bottom boundary, then we can safely execute 10
///       operations that modify the stack depth with no bounds check.
/// - When switching contexts (e.g., during a call or syscall), all elements past the first 16 are
///   stored in an `ExecutionContextInfo` struct, and the stack is truncated to 16 elements. This
///   will be restored when returning from the call or syscall.
///
/// # Clock Cycle Management
/// - The clock cycle (`clk`) is managed in the same way as in `Process`. That is, it is incremented
///   by 1 for every row that `Process` adds to the main trace.
///     - It is important to do so because the clock cycle is used to determine the context ID for
///       new execution contexts when using `call` or `dyncall`.
#[derive(Debug)]
pub struct FastProcessor {
    /// The stack is stored in reverse order, so that the last element is at the top of the stack.
    stack: Box<[Felt; STACK_BUFFER_SIZE]>,
    /// The index of the top of the stack.
    stack_top_idx: usize,
    /// The index of the bottom of the stack.
    stack_bot_idx: usize,

    /// The current clock cycle.
    clk: RowIndex,

    /// The current context ID.
    ctx: ContextId,

    /// The hash of the function that called into the current context, or `[ZERO, ZERO, ZERO,
    /// ZERO]` if we are in the first context (i.e. when `call_stack` is empty).
    caller_hash: Word,

    /// The advice provider to be used during execution.
    advice: AdviceProvider,

    /// A map from (context_id, word_address) to the word stored starting at that memory location.
    memory: Memory,

    /// A map storing metadata per call to the ACE chiplet.
    ace: Ace,

    /// The call stack is used when starting a new execution context (from a `call`, `syscall` or
    /// `dyncall`) to keep track of the information needed to return to the previous context upon
    /// return. It is a stack since calls can be nested.
    call_stack: Vec<ExecutionContextInfo>,

    /// Options for execution, including but not limited to whether debug or tracing is enabled,
    /// the size of core trace fragments during execution, etc.
    options: ExecutionOptions,

    /// Transcript used to record commitments via `log_precompile` instruction (implemented via
    /// Poseidon2 sponge).
    pc_transcript: PrecompileTranscript,

    /// Tracks decorator retrieval calls for testing.
    #[cfg(test)]
    pub decorator_retrieval_count: Rc<Cell<usize>>,
}

impl FastProcessor {
    // CONSTRUCTORS
    // ----------------------------------------------------------------------------------------------

    /// Creates a new `FastProcessor` instance with the given stack inputs, where debug and tracing
    /// are disabled.
    pub fn new(stack_inputs: StackInputs) -> Self {
        Self::new_with_options(stack_inputs, AdviceInputs::default(), ExecutionOptions::default())
    }

    /// Creates a new `FastProcessor` instance with the given stack and advice inputs, where debug
    /// and tracing are disabled.
    pub fn new_with_advice_inputs(stack_inputs: StackInputs, advice_inputs: AdviceInputs) -> Self {
        Self::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
    }

    /// Creates a new `FastProcessor` instance with the given stack and advice inputs, where
    /// debugging and tracing are enabled.
    pub fn new_debug(stack_inputs: StackInputs, advice_inputs: AdviceInputs) -> Self {
        Self::new_with_options(
            stack_inputs,
            advice_inputs,
            ExecutionOptions::default().with_debugging(true).with_tracing(true),
        )
    }

    /// Most general constructor unifying all the other ones.
    pub fn new_with_options(
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        options: ExecutionOptions,
    ) -> Self {
        let stack_top_idx = INITIAL_STACK_TOP_IDX;
        let stack = {
            // Note: we use `Vec::into_boxed_slice()` here, since `Box::new([T; N])` first allocates
            // the array on the stack, and then moves it to the heap. This might cause a
            // stack overflow on some systems.
            let mut stack: Box<[Felt; STACK_BUFFER_SIZE]> =
                vec![ZERO; STACK_BUFFER_SIZE].into_boxed_slice().try_into().unwrap();

            // Copy inputs in reverse order so first element ends up at top of stack
            for (i, &input) in stack_inputs.iter().enumerate() {
                stack[stack_top_idx - 1 - i] = input;
            }
            stack
        };

        Self {
            advice: advice_inputs.into(),
            stack,
            stack_top_idx,
            stack_bot_idx: stack_top_idx - MIN_STACK_DEPTH,
            clk: 0_u32.into(),
            ctx: 0_u32.into(),
            caller_hash: EMPTY_WORD,
            memory: Memory::new(),
            call_stack: Vec::new(),
            ace: Ace::default(),
            options,
            pc_transcript: PrecompileTranscript::new(),
            #[cfg(test)]
            decorator_retrieval_count: Rc::new(Cell::new(0)),
        }
    }

    /// Returns the resume context to be used with the first call to `step()`.
    pub fn get_initial_resume_context(
        &mut self,
        program: &Program,
    ) -> Result<ResumeContext, ExecutionError> {
        self.advice
            .extend_map(program.mast_forest().advice_map())
            .map_exec_err_no_ctx()?;

        Ok(ResumeContext {
            current_forest: program.mast_forest().clone(),
            continuation_stack: ContinuationStack::new(program),
            kernel: program.kernel().clone(),
        })
    }

    // ACCESSORS
    // -------------------------------------------------------------------------------------------

    /// Returns whether the processor is executing in debug mode.
    #[inline(always)]
    pub fn in_debug_mode(&self) -> bool {
        self.options.enable_debugging()
    }

    /// Returns true if decorators should be executed.
    ///
    /// This corresponds to either being in debug mode (for debug decorators) or having tracing
    /// enabled (for trace decorators).
    #[inline(always)]
    fn should_execute_decorators(&self) -> bool {
        self.in_debug_mode() || self.options.enable_tracing()
    }

    #[cfg(test)]
    #[inline(always)]
    fn record_decorator_retrieval(&self) {
        self.decorator_retrieval_count.set(self.decorator_retrieval_count.get() + 1);
    }

    /// Returns the size of the stack.
    #[inline(always)]
    fn stack_size(&self) -> usize {
        self.stack_top_idx - self.stack_bot_idx
    }

    /// Returns the stack, such that the top of the stack is at the last index of the returned
    /// slice.
    pub fn stack(&self) -> &[Felt] {
        &self.stack[self.stack_bot_idx..self.stack_top_idx]
    }

    /// Returns the top 16 elements of the stack.
    pub fn stack_top(&self) -> &[Felt] {
        &self.stack[self.stack_top_idx - MIN_STACK_DEPTH..self.stack_top_idx]
    }

    /// Returns a mutable reference to the top 16 elements of the stack.
    pub fn stack_top_mut(&mut self) -> &mut [Felt] {
        &mut self.stack[self.stack_top_idx - MIN_STACK_DEPTH..self.stack_top_idx]
    }

    /// Returns the element on the stack at index `idx`.
    #[inline(always)]
    pub fn stack_get(&self, idx: usize) -> Felt {
        self.stack[self.stack_top_idx - idx - 1]
    }

    /// Mutable variant of `stack_get()`.
    #[inline(always)]
    pub fn stack_get_mut(&mut self, idx: usize) -> &mut Felt {
        &mut self.stack[self.stack_top_idx - idx - 1]
    }

    /// Returns the word on the stack starting at index `start_idx` in "stack order".
    ///
    /// For `start_idx=0` the top element of the stack will be at position 0 in the word.
    ///
    /// For example, if the stack looks like this:
    ///
    /// top                                                       bottom
    /// v                                                           v
    /// a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p
    ///
    /// Then
    /// - `stack_get_word(0)` returns `[a, b, c, d]`,
    /// - `stack_get_word(1)` returns `[b, c, d, e]`,
    /// - etc.
    #[inline(always)]
    pub fn stack_get_word(&self, start_idx: usize) -> Word {
        // Ensure we have enough elements to form a complete word
        debug_assert!(
            start_idx + WORD_SIZE <= self.stack_depth() as usize,
            "Not enough elements on stack to read word starting at index {start_idx}"
        );

        let word_start_idx = self.stack_top_idx - start_idx - 4;
        let mut result: [Felt; WORD_SIZE] =
            self.stack[range(word_start_idx, WORD_SIZE)].try_into().unwrap();
        // Reverse so top of stack (idx 0) goes to word[0]
        result.reverse();
        result.into()
    }

    /// Returns the number of elements on the stack in the current context.
    #[inline(always)]
    pub fn stack_depth(&self) -> u32 {
        (self.stack_top_idx - self.stack_bot_idx) as u32
    }

    /// Returns a reference to the processor's memory.
    pub fn memory(&self) -> &Memory {
        &self.memory
    }

    /// Returns a narrowed interface for reading and updating the processor state.
    #[inline(always)]
    pub fn state(&mut self) -> ProcessorState<'_> {
        ProcessorState { processor: self }
    }

    // MUTATORS
    // -------------------------------------------------------------------------------------------

    /// Writes an element to the stack at the given index.
    #[inline(always)]
    pub fn stack_write(&mut self, idx: usize, element: Felt) {
        self.stack[self.stack_top_idx - idx - 1] = element
    }

    /// Writes a word to the stack starting at the given index.
    ///
    /// `word[0]` goes to stack position start_idx (top), `word[1]` to start_idx+1, etc.
    #[inline(always)]
    pub fn stack_write_word(&mut self, start_idx: usize, word: &Word) {
        debug_assert!(start_idx < MIN_STACK_DEPTH);

        let word_start_idx = self.stack_top_idx - start_idx - 4;
        let mut source: [Felt; WORD_SIZE] = (*word).into();
        // Reverse so word[0] ends up at the top of stack (highest internal index)
        source.reverse();
        self.stack[range(word_start_idx, WORD_SIZE)].copy_from_slice(&source)
    }

    /// Swaps the elements at the given indices on the stack.
    #[inline(always)]
    pub fn stack_swap(&mut self, idx1: usize, idx2: usize) {
        let a = self.stack_get(idx1);
        let b = self.stack_get(idx2);
        self.stack_write(idx1, b);
        self.stack_write(idx2, a);
    }

    // EXECUTE
    // -------------------------------------------------------------------------------------------

    /// Executes the given program and returns the stack outputs as well as the advice provider.
    pub async fn execute(
        self,
        program: &Program,
        host: &mut impl Host,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.execute_with_tracer(program, host, &mut NoopTracer).await
    }

    /// Executes the given program and returns the stack outputs, the advice provider, and
    /// context necessary to build the trace.
    #[instrument(name = "execute_for_trace", skip_all)]
    pub async fn execute_for_trace(
        self,
        program: &Program,
        host: &mut impl Host,
    ) -> Result<(ExecutionOutput, TraceGenerationContext), ExecutionError> {
        let mut tracer = ExecutionTracer::new(self.options.core_trace_fragment_size());
        let execution_output = self.execute_with_tracer(program, host, &mut tracer).await?;

        // Pass the final precompile transcript from execution output to the trace generation
        // context
        let context = tracer.into_trace_generation_context(execution_output.final_pc_transcript);

        Ok((execution_output, context))
    }

    /// Executes the given program with the provided tracer and returns the stack outputs, and the
    /// advice provider.
    pub async fn execute_with_tracer(
        mut self,
        program: &Program,
        host: &mut impl Host,
        tracer: &mut impl Tracer,
    ) -> Result<ExecutionOutput, ExecutionError> {
        let mut continuation_stack = ContinuationStack::new(program);
        let mut current_forest = program.mast_forest().clone();

        // Merge the program's advice map into the advice provider
        self.advice.extend_map(current_forest.advice_map()).map_exec_err_no_ctx()?;

        match self
            .execute_impl(
                &mut continuation_stack,
                &mut current_forest,
                program.kernel(),
                host,
                tracer,
                &NeverStopper,
            )
            .await
        {
            ControlFlow::Continue(stack_outputs) => Ok(ExecutionOutput {
                stack: stack_outputs,
                advice: self.advice,
                memory: self.memory,
                final_pc_transcript: self.pc_transcript,
            }),
            ControlFlow::Break(break_reason) => match break_reason {
                BreakReason::Err(err) => Err(err),
                BreakReason::Stopped(_) => {
                    unreachable!("Execution never stops prematurely with NeverStopper")
                },
            },
        }
    }

    /// Executes a single clock cycle
    pub async fn step(
        &mut self,
        host: &mut impl Host,
        resume_ctx: ResumeContext,
    ) -> Result<Option<ResumeContext>, ExecutionError> {
        let ResumeContext {
            mut current_forest,
            mut continuation_stack,
            kernel,
        } = resume_ctx;

        match self
            .execute_impl(
                &mut continuation_stack,
                &mut current_forest,
                &kernel,
                host,
                &mut NoopTracer,
                &StepStopper,
            )
            .await
        {
            ControlFlow::Continue(_) => Ok(None),
            ControlFlow::Break(break_reason) => match break_reason {
                BreakReason::Err(err) => Err(err),
                BreakReason::Stopped(maybe_continuation) => {
                    if let Some(continuation) = maybe_continuation {
                        continuation_stack.push_continuation(continuation);
                    }

                    Ok(Some(ResumeContext {
                        current_forest,
                        continuation_stack,
                        kernel,
                    }))
                },
            },
        }
    }

    /// Executes the given program with the provided tracer and returns the stack outputs.
    ///
    /// This function takes a `&mut self` (compared to `self` for the public execute functions) so
    /// that the processor state may be accessed after execution. It is incorrect to execute a
    /// second program using the same processor. This is mainly meant to be used in tests.
    async fn execute_impl<S>(
        &mut self,
        continuation_stack: &mut ContinuationStack,
        current_forest: &mut Arc<MastForest>,
        kernel: &Kernel,
        host: &mut impl Host,
        tracer: &mut impl Tracer,
        stopper: &S,
    ) -> ControlFlow<BreakReason, StackOutputs>
    where
        S: Stopper<Processor = Self>,
    {
        while let ControlFlow::Break(internal_break_reason) =
            execute_impl(self, continuation_stack, current_forest, kernel, host, tracer, stopper)
        {
            match internal_break_reason {
                InternalBreakReason::User(break_reason) => return ControlFlow::Break(break_reason),
                InternalBreakReason::Emit { basic_block_node_id, continuation } => {
                    self.op_emit(host, current_forest, basic_block_node_id).await?;

                    // Call `finish_emit_op_execution()`, as per the sans-IO contract.
                    finish_emit_op_execution(
                        continuation,
                        self,
                        continuation_stack,
                        tracer,
                        stopper,
                    )?;
                },
                InternalBreakReason::LoadMastForestFromDyn { dyn_node_id, callee_hash } => {
                    // load mast forest asynchronously
                    let (root_id, new_forest) = match self
                        .load_mast_forest(
                            callee_hash,
                            host,
                            |digest| OperationError::DynamicNodeNotFound { digest },
                            current_forest,
                            dyn_node_id,
                        )
                        .await
                    {
                        Ok(result) => result,
                        Err(err) => return ControlFlow::Break(BreakReason::Err(err)),
                    };

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
                    procedure_hash,
                } => {
                    // load mast forest asynchronously
                    let (root_id, new_forest) = match self
                        .load_mast_forest(
                            procedure_hash,
                            host,
                            |root_digest| OperationError::NoMastForestWithProcedure { root_digest },
                            current_forest,
                            external_node_id,
                        )
                        .await
                    {
                        Ok(result) => result,
                        Err(err) => {
                            let maybe_enriched_err = maybe_use_caller_error_context(
                                err,
                                current_forest,
                                continuation_stack,
                                host,
                            );

                            return ControlFlow::Break(BreakReason::Err(maybe_enriched_err));
                        },
                    };

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

        match StackOutputs::new(
            &self.stack[self.stack_bot_idx..self.stack_top_idx]
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>(),
        ) {
            Ok(stack_outputs) => ControlFlow::Continue(stack_outputs),
            Err(_) => ControlFlow::Break(BreakReason::Err(ExecutionError::OutputStackOverflow(
                self.stack_top_idx - self.stack_bot_idx - MIN_STACK_DEPTH,
            ))),
        }
    }

    // DECORATOR EXECUTORS
    // --------------------------------------------------------------------------------------------

    /// Executes the decorators that should be executed before entering a node.
    fn execute_before_enter_decorators(
        &mut self,
        node_id: MastNodeId,
        current_forest: &MastForest,
        host: &mut impl Host,
    ) -> ControlFlow<BreakReason> {
        if !self.should_execute_decorators() {
            return ControlFlow::Continue(());
        }

        #[cfg(test)]
        self.record_decorator_retrieval();

        let node = current_forest
            .get_node_by_id(node_id)
            .expect("internal error: node id {node_id} not found in current forest");

        for &decorator_id in node.before_enter(current_forest) {
            self.execute_decorator(&current_forest[decorator_id], host)?;
        }

        ControlFlow::Continue(())
    }

    /// Executes the decorators that should be executed after exiting a node.
    fn execute_after_exit_decorators(
        &mut self,
        node_id: MastNodeId,
        current_forest: &MastForest,
        host: &mut impl Host,
    ) -> ControlFlow<BreakReason> {
        if !self.in_debug_mode() {
            return ControlFlow::Continue(());
        }

        #[cfg(test)]
        self.record_decorator_retrieval();

        let node = current_forest
            .get_node_by_id(node_id)
            .expect("internal error: node id {node_id} not found in current forest");

        for &decorator_id in node.after_exit(current_forest) {
            self.execute_decorator(&current_forest[decorator_id], host)?;
        }

        ControlFlow::Continue(())
    }

    /// Executes the specified decorator
    fn execute_decorator(
        &mut self,
        decorator: &Decorator,
        host: &mut impl Host,
    ) -> ControlFlow<BreakReason> {
        match decorator {
            Decorator::Debug(options) => {
                if self.in_debug_mode() {
                    let process = &mut self.state();
                    if let Err(err) = host.on_debug(process, options) {
                        return ControlFlow::Break(BreakReason::Err(
                            ExecutionError::DebugHandlerError { err },
                        ));
                    }
                }
            },
            Decorator::Trace(id) => {
                if self.options.enable_tracing() {
                    let process = &mut self.state();
                    if let Err(err) = host.on_trace(process, *id) {
                        return ControlFlow::Break(BreakReason::Err(
                            ExecutionError::TraceHandlerError { trace_id: *id, err },
                        ));
                    }
                }
            },
        };
        ControlFlow::Continue(())
    }

    // HELPERS
    // ----------------------------------------------------------------------------------------------

    async fn load_mast_forest(
        &mut self,
        node_digest: Word,
        host: &mut impl Host,
        get_mast_forest_failed: impl Fn(Word) -> OperationError,
        current_forest: &MastForest,
        node_id: MastNodeId,
    ) -> Result<(MastNodeId, Arc<MastForest>), ExecutionError> {
        let mast_forest = host
            .get_mast_forest(&node_digest)
            .await
            .ok_or_else(|| get_mast_forest_failed(node_digest))
            .map_exec_err(current_forest, node_id, host)?;

        // We limit the parts of the program that can be called externally to procedure
        // roots, even though MAST doesn't have that restriction.
        let root_id = mast_forest.find_procedure_root(node_digest).ok_or_else(|| {
            Err::<(), _>(OperationError::MalformedMastForestInHost { root_digest: node_digest })
                .map_exec_err(current_forest, node_id, host)
                .unwrap_err()
        })?;

        // Merge the advice map of this forest into the advice provider.
        // Note that the map may be merged multiple times if a different procedure from the same
        // forest is called.
        // For now, only compiled libraries contain non-empty advice maps, so for most cases,
        // this call will be cheap.
        self.advice.extend_map(mast_forest.advice_map()).map_exec_err(
            current_forest,
            node_id,
            host,
        )?;

        Ok((root_id, mast_forest))
    }

    /// Increments the stack top pointer by 1.
    ///
    /// The bottom of the stack is never affected by this operation.
    #[inline(always)]
    fn increment_stack_size(&mut self, tracer: &mut impl Tracer) {
        tracer.increment_stack_size(self);

        self.stack_top_idx += 1;
    }

    /// Decrements the stack top pointer by 1.
    ///
    /// The bottom of the stack is only decremented in cases where the stack depth would become less
    /// than 16.
    #[inline(always)]
    fn decrement_stack_size(&mut self, tracer: &mut impl Tracer) {
        if self.stack_top_idx == MIN_STACK_DEPTH {
            // We no longer have any room in the stack buffer to decrement the stack size (which
            // would cause the `stack_bot_idx` to go below 0). We therefore reset the stack to its
            // original position.
            self.reset_stack_in_buffer(INITIAL_STACK_TOP_IDX);
        }

        self.stack_top_idx -= 1;
        self.stack_bot_idx = min(self.stack_bot_idx, self.stack_top_idx - MIN_STACK_DEPTH);

        tracer.decrement_stack_size();
    }

    /// Resets the stack in the buffer to a new position, preserving the top 16 elements of the
    /// stack.
    ///
    /// # Preconditions
    /// - The stack is expected to have exactly 16 elements.
    #[inline(always)]
    fn reset_stack_in_buffer(&mut self, new_stack_top_idx: usize) {
        debug_assert_eq!(self.stack_depth(), MIN_STACK_DEPTH as u32);

        let new_stack_bot_idx = new_stack_top_idx - MIN_STACK_DEPTH;

        // Copy stack to its new position
        self.stack
            .copy_within(self.stack_bot_idx..self.stack_top_idx, new_stack_bot_idx);

        // Zero out stack below the new new_stack_bot_idx, since this is where overflow values
        // come from, and are guaranteed to be ZERO. We don't need to zero out above
        // `stack_top_idx`, since values there are never read before being written.
        self.stack[0..new_stack_bot_idx].fill(ZERO);

        // Update indices.
        self.stack_bot_idx = new_stack_bot_idx;
        self.stack_top_idx = new_stack_top_idx;
    }

    // SYNC WRAPPERS
    // ----------------------------------------------------------------------------------------------

    /// Convenience sync wrapper to [Self::step].
    pub fn step_sync(
        &mut self,
        host: &mut impl Host,
        resume_ctx: ResumeContext,
    ) -> Result<Option<ResumeContext>, ExecutionError> {
        // Create a new Tokio runtime and block on the async execution
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();

        let execution_output = rt.block_on(self.step(host, resume_ctx))?;

        Ok(execution_output)
    }

    /// Executes the given program step by step (calling [`Self::step`] repeatedly) and returns the
    /// stack outputs.
    pub fn execute_by_step_sync(
        mut self,
        program: &Program,
        host: &mut impl Host,
    ) -> Result<StackOutputs, ExecutionError> {
        // Create a new Tokio runtime and block on the async execution
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let mut current_resume_ctx = self.get_initial_resume_context(program).unwrap();

        rt.block_on(async {
            loop {
                match self.step(host, current_resume_ctx).await {
                    Ok(maybe_resume_ctx) => match maybe_resume_ctx {
                        Some(next_resume_ctx) => {
                            current_resume_ctx = next_resume_ctx;
                        },
                        None => {
                            // End of program was reached
                            break Ok(StackOutputs::new(
                                &self.stack[self.stack_bot_idx..self.stack_top_idx]
                                    .iter()
                                    .rev()
                                    .copied()
                                    .collect::<Vec<_>>(),
                            )
                            .unwrap());
                        },
                    },
                    Err(err) => {
                        break Err(err);
                    },
                }
            }
        })
    }

    /// Convenience sync wrapper to [Self::execute].
    ///
    /// This method is only available on non-wasm32 targets. On wasm32, use the
    /// async `execute()` method directly since wasm32 runs in the browser's event loop.
    ///
    /// # Panics
    /// Panics if called from within an existing Tokio runtime. Use the async `execute()`
    /// method instead in async contexts.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn execute_sync(
        self,
        program: &Program,
        host: &mut impl Host,
    ) -> Result<ExecutionOutput, ExecutionError> {
        match tokio::runtime::Handle::try_current() {
            Ok(_handle) => {
                // We're already inside a Tokio runtime - this is not supported
                // because we cannot safely create a nested runtime or move the
                // non-Send host reference to another thread
                panic!(
                    "Cannot call execute_sync from within a Tokio runtime. \
                     Use the async execute() method instead."
                )
            },
            Err(_) => {
                // No runtime exists - create one and use it
                let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
                rt.block_on(self.execute(program, host))
            },
        }
    }

    /// Convenience sync wrapper to [Self::execute_for_trace].
    ///
    /// This method is only available on non-wasm32 targets. On wasm32, use the
    /// async `execute_for_trace()` method directly since wasm32 runs in the browser's event loop.
    ///
    /// # Panics
    /// Panics if called from within an existing Tokio runtime. Use the async `execute_for_trace()`
    /// method instead in async contexts.
    #[cfg(not(target_arch = "wasm32"))]
    #[instrument(name = "execute_for_trace_sync", skip_all)]
    pub fn execute_for_trace_sync(
        self,
        program: &Program,
        host: &mut impl Host,
    ) -> Result<(ExecutionOutput, TraceGenerationContext), ExecutionError> {
        match tokio::runtime::Handle::try_current() {
            Ok(_handle) => {
                // We're already inside a Tokio runtime - this is not supported
                // because we cannot safely create a nested runtime or move the
                // non-Send host reference to another thread
                panic!(
                    "Cannot call execute_for_trace_sync from within a Tokio runtime. \
                     Use the async execute_for_trace() method instead."
                )
            },
            Err(_) => {
                // No runtime exists - create one and use it
                let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
                rt.block_on(self.execute_for_trace(program, host))
            },
        }
    }

    /// Similar to [Self::execute_sync], but allows mutable access to the processor.
    ///
    /// This method is only available on non-wasm32 targets for testing. On wasm32, use
    /// async execution methods directly since wasm32 runs in the browser's event loop.
    ///
    /// # Panics
    /// Panics if called from within an existing Tokio runtime. Use async execution
    /// methods instead in async contexts.
    #[cfg(all(any(test, feature = "testing"), not(target_arch = "wasm32")))]
    pub fn execute_sync_mut(
        &mut self,
        program: &Program,
        host: &mut impl Host,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut continuation_stack = ContinuationStack::new(program);
        let mut current_forest = program.mast_forest().clone();

        // Merge the program's advice map into the advice provider
        self.advice.extend_map(current_forest.advice_map()).map_exec_err_no_ctx()?;

        let execute_fut = async {
            match self
                .execute_impl(
                    &mut continuation_stack,
                    &mut current_forest,
                    program.kernel(),
                    host,
                    &mut NoopTracer,
                    &NeverStopper,
                )
                .await
            {
                ControlFlow::Continue(stack_outputs) => Ok(stack_outputs),
                ControlFlow::Break(break_reason) => match break_reason {
                    BreakReason::Err(err) => Err(err),
                    BreakReason::Stopped(_) => {
                        unreachable!("Execution never stops prematurely with NeverStopper")
                    },
                },
            }
        };

        match tokio::runtime::Handle::try_current() {
            Ok(_handle) => {
                // We're already inside a Tokio runtime - this is not supported
                // because we cannot safely create a nested runtime or move the
                // non-Send host reference to another thread
                panic!(
                    "Cannot call execute_sync_mut from within a Tokio runtime. \
                     Use async execution methods instead."
                )
            },
            Err(_) => {
                // No runtime exists - create one and use it
                let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
                rt.block_on(execute_fut)
            },
        }
    }
}

// EXECUTION OUTPUT
// ===============================================================================================

/// The output of a program execution, containing the state of the stack, advice provider,
/// memory, and final precompile transcript at the end of execution.
#[derive(Debug)]
pub struct ExecutionOutput {
    pub stack: StackOutputs,
    pub advice: AdviceProvider,
    pub memory: Memory,
    pub final_pc_transcript: PrecompileTranscript,
}

// EXECUTION CONTEXT INFO
// ===============================================================================================

/// Information about the execution context.
///
/// This struct is used to keep track of the information needed to return to the previous context
/// upon return from a `call`, `syscall` or `dyncall`.
#[derive(Debug)]
struct ExecutionContextInfo {
    /// This stores all the elements on the stack at the call site, excluding the top 16 elements.
    /// This corresponds to the overflow table in [crate::Process].
    overflow_stack: Vec<Felt>,
    ctx: ContextId,
    fn_hash: Word,
}
