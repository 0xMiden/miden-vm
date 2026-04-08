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
    program::{MIN_STACK_DEPTH, Program, StackInputs, StackOutputs},
    utils::range,
};

use crate::{
    AdviceInputs, AdviceProvider, BaseHost, ContextId, ExecutionError, ExecutionOptions,
    ProcessorState,
    continuation_stack::{Continuation, ContinuationStack},
    errors::MapExecErrNoCtx,
    tracer::{OperationHelperRegisters, Tracer},
};

mod basic_block;
mod call_and_dyn;
mod execution_api;
mod external;
mod memory;
mod operation;
mod step;

pub use basic_block::SystemEventError;
pub use memory::Memory;
pub use step::{BreakReason, ResumeContext};

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
    /// Packages the processor state after successful execution into a public result type.
    #[inline(always)]
    fn into_execution_output(self, stack: StackOutputs) -> ExecutionOutput {
        ExecutionOutput {
            stack,
            advice: self.advice,
            memory: self.memory,
            final_precompile_transcript: self.pc_transcript,
        }
    }

    /// Converts the terminal result of a full execution run into [`ExecutionOutput`].
    #[inline(always)]
    fn execution_result_from_flow(
        flow: ControlFlow<BreakReason, StackOutputs>,
        processor: Self,
    ) -> Result<ExecutionOutput, ExecutionError> {
        match flow {
            ControlFlow::Continue(stack_outputs) => {
                Ok(processor.into_execution_output(stack_outputs))
            },
            ControlFlow::Break(break_reason) => match break_reason {
                BreakReason::Err(err) => Err(err),
                BreakReason::Stopped(_) => {
                    unreachable!("Execution never stops prematurely with NeverStopper")
                },
            },
        }
    }

    /// Converts a testing-only execution result into stack outputs.
    #[cfg(any(test, feature = "testing"))]
    #[inline(always)]
    fn stack_result_from_flow(
        flow: ControlFlow<BreakReason, StackOutputs>,
    ) -> Result<StackOutputs, ExecutionError> {
        match flow {
            ControlFlow::Continue(stack_outputs) => Ok(stack_outputs),
            ControlFlow::Break(break_reason) => match break_reason {
                BreakReason::Err(err) => Err(err),
                BreakReason::Stopped(_) => {
                    unreachable!("Execution never stops prematurely with NeverStopper")
                },
            },
        }
    }

    // CONSTRUCTORS
    // ----------------------------------------------------------------------------------------------

    /// Creates a new `FastProcessor` instance with the given stack inputs.
    ///
    /// By default, advice inputs are empty and execution options use their defaults
    /// (debugging and tracing disabled).
    ///
    /// # Example
    /// ```ignore
    /// use miden_processor::FastProcessor;
    ///
    /// let processor = FastProcessor::new(stack_inputs)
    ///     .with_advice(advice_inputs)
    ///     .with_debugging(true)
    ///     .with_tracing(true);
    /// ```
    pub fn new(stack_inputs: StackInputs) -> Self {
        Self::new_with_options(stack_inputs, AdviceInputs::default(), ExecutionOptions::default())
    }

    /// Sets the advice inputs for the processor.
    pub fn with_advice(mut self, advice_inputs: AdviceInputs) -> Self {
        self.advice = advice_inputs.into();
        self
    }

    /// Sets the execution options for the processor.
    ///
    /// This will override any previously set debugging or tracing settings.
    pub fn with_options(mut self, options: ExecutionOptions) -> Self {
        self.options = options;
        self
    }

    /// Enables or disables debugging mode.
    ///
    /// When debugging is enabled, debug decorators will be executed during program execution.
    pub fn with_debugging(mut self, enabled: bool) -> Self {
        self.options = self.options.with_debugging(enabled);
        self
    }

    /// Enables or disables tracing mode.
    ///
    /// When tracing is enabled, trace decorators will be executed during program execution.
    pub fn with_tracing(mut self, enabled: bool) -> Self {
        self.options = self.options.with_tracing(enabled);
        self
    }

    /// Constructor for creating a `FastProcessor` with all options specified at once.
    ///
    /// For a more fluent API, consider using `FastProcessor::new()` with builder methods.
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
            options,
            pc_transcript: PrecompileTranscript::new(),
            #[cfg(test)]
            decorator_retrieval_count: Rc::new(Cell::new(0)),
        }
    }

    /// Returns the resume context to be used with the first call to `step_sync()`.
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
    ///
    /// This method is only meant to be used to access the stack top by operation handlers, and
    /// system event handlers.
    ///
    /// # Preconditions
    /// - `idx` must be less than or equal to 15.
    #[inline(always)]
    pub fn stack_get(&self, idx: usize) -> Felt {
        self.stack[self.stack_top_idx - idx - 1]
    }

    /// Same as [`Self::stack_get()`], but returns [`ZERO`] if `idx` falls below index 0 in the
    /// stack buffer.
    ///
    /// Use this instead of `stack_get()` when `idx` may exceed 15.
    #[inline(always)]
    pub fn stack_get_safe(&self, idx: usize) -> Felt {
        if idx < self.stack_top_idx {
            self.stack[self.stack_top_idx - idx - 1]
        } else {
            ZERO
        }
    }

    /// Mutable variant of `stack_get()`.
    ///
    /// This method is only meant to be used to access the stack top by operation handlers, and
    /// system event handlers.
    ///
    /// # Preconditions
    /// - `idx` must be less than or equal to 15.
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
    ///
    /// This method is only meant to be used to access the stack top by operation handlers, and
    /// system event handlers.
    ///
    /// # Preconditions
    /// - `start_idx` must be less than or equal to 12.
    #[inline(always)]
    pub fn stack_get_word(&self, start_idx: usize) -> Word {
        // Ensure we have enough elements to form a complete word
        debug_assert!(
            start_idx + WORD_SIZE <= self.stack_depth() as usize,
            "Not enough elements on stack to read word starting at index {start_idx}"
        );

        let word_start_idx = self.stack_top_idx - start_idx - WORD_SIZE;
        let mut result: [Felt; WORD_SIZE] =
            self.stack[range(word_start_idx, WORD_SIZE)].try_into().unwrap();
        // Reverse so top of stack (idx 0) goes to word[0]
        result.reverse();
        result.into()
    }

    /// Same as [`Self::stack_get_word()`], but returns [`ZERO`] for any element that falls below
    /// index 0 in the stack buffer.
    ///
    /// Use this instead of `stack_get_word()` when `start_idx + WORD_SIZE` may exceed
    /// `stack_top_idx`.
    #[inline(always)]
    pub fn stack_get_word_safe(&self, start_idx: usize) -> Word {
        let buf_end = self.stack_top_idx.saturating_sub(start_idx);
        let buf_start = self.stack_top_idx.saturating_sub(start_idx.saturating_add(WORD_SIZE));
        let num_elements_to_read_from_buf = buf_end - buf_start;

        let mut result = [ZERO; WORD_SIZE];
        if num_elements_to_read_from_buf == WORD_SIZE {
            result.copy_from_slice(&self.stack[range(buf_start, WORD_SIZE)]);
        } else if num_elements_to_read_from_buf > 0 {
            let offset = WORD_SIZE - num_elements_to_read_from_buf;
            result[offset..]
                .copy_from_slice(&self.stack[range(buf_start, num_elements_to_read_from_buf)]);
        }
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

    /// Returns a reference to the execution options.
    pub fn execution_options(&self) -> &ExecutionOptions {
        &self.options
    }

    /// Returns a narrowed interface for reading and updating the processor state.
    #[inline(always)]
    pub fn state(&self) -> ProcessorState<'_> {
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
        debug_assert!(start_idx <= MIN_STACK_DEPTH - WORD_SIZE);

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

    // DECORATOR EXECUTORS
    // --------------------------------------------------------------------------------------------

    /// Executes the decorators that should be executed before entering a node.
    fn execute_before_enter_decorators(
        &self,
        node_id: MastNodeId,
        current_forest: &MastForest,
        host: &mut impl BaseHost,
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
        &self,
        node_id: MastNodeId,
        current_forest: &MastForest,
        host: &mut impl BaseHost,
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
        &self,
        decorator: &Decorator,
        host: &mut impl BaseHost,
    ) -> ControlFlow<BreakReason> {
        match decorator {
            Decorator::Debug(options) => {
                if self.in_debug_mode() {
                    let processor_state = self.state();
                    if let Err(err) = host.on_debug(&processor_state, options) {
                        return ControlFlow::Break(BreakReason::Err(
                            crate::errors::HostError::DebugHandlerError { err }.into(),
                        ));
                    }
                }
            },
            Decorator::Trace(id) => {
                if self.options.enable_tracing() {
                    let processor_state = self.state();
                    if let Err(err) = host.on_trace(&processor_state, *id) {
                        return ControlFlow::Break(BreakReason::Err(
                            crate::errors::HostError::TraceHandlerError { trace_id: *id, err }
                                .into(),
                        ));
                    }
                }
            },
        };
        ControlFlow::Continue(())
    }

    /// Increments the stack top pointer by 1.
    ///
    /// The bottom of the stack is never affected by this operation.
    #[inline(always)]
    fn increment_stack_size(&mut self) {
        self.stack_top_idx += 1;
    }

    /// Decrements the stack top pointer by 1.
    ///
    /// The bottom of the stack is only decremented in cases where the stack depth would become less
    /// than 16.
    #[inline(always)]
    fn decrement_stack_size(&mut self) {
        if self.stack_top_idx == MIN_STACK_DEPTH {
            // We no longer have any room in the stack buffer to decrement the stack size (which
            // would cause the `stack_bot_idx` to go below 0). We therefore reset the stack to its
            // original position.
            self.reset_stack_in_buffer(INITIAL_STACK_TOP_IDX);
        }

        self.stack_top_idx -= 1;
        self.stack_bot_idx = min(self.stack_bot_idx, self.stack_top_idx - MIN_STACK_DEPTH);
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
    pub final_precompile_transcript: PrecompileTranscript,
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

// NOOP TRACER
// ================================================================================================

/// A [Tracer] that does nothing.
pub struct NoopTracer;

impl Tracer for NoopTracer {
    type Processor = FastProcessor;

    #[inline(always)]
    fn start_clock_cycle(
        &mut self,
        _processor: &FastProcessor,
        _continuation: Continuation,
        _continuation_stack: &ContinuationStack,
        _current_forest: &Arc<MastForest>,
    ) {
        // do nothing
    }

    #[inline(always)]
    fn finalize_clock_cycle(
        &mut self,
        _processor: &FastProcessor,
        _op_helper_registers: OperationHelperRegisters,
        _current_forest: &Arc<MastForest>,
    ) {
        // do nothing
    }
}
