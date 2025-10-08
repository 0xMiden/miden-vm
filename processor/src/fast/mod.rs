use alloc::{sync::Arc, vec::Vec};
use core::cmp::min;

use memory::Memory;
use miden_air::{Felt, RowIndex};
use miden_core::{
    Decorator, EMPTY_WORD, Program, StackOutputs, WORD_SIZE, Word, ZERO,
    mast::{MastForest, MastNode, MastNodeExt, MastNodeId},
    stack::MIN_STACK_DEPTH,
    utils::range,
};

use crate::{
    AdviceInputs, AdviceProvider, AsyncHost, ContextId, ErrorContext, ExecutionError, FMP_MIN,
    ProcessState,
    chiplets::Ace,
    continuation_stack::{Continuation, ContinuationStack},
    fast::execution_tracer::{ExecutionTracer, TraceFragmentContexts},
};

pub mod execution_tracer;
mod memory;
mod operation;
pub mod trace_state;
mod tracer;
pub use tracer::{NoopTracer, Tracer};

mod basic_block;
mod call_and_dyn;
mod external;
mod join;
mod r#loop;
mod split;

#[cfg(test)]
mod tests;

/// The size of the stack buffer.
///
/// Note: This value is much larger than it needs to be for the majority of programs. However, some
/// existing programs need it (e.g. `std::math::secp256k1::group::gen_mul`), so we're forced to push
/// it up. At this high a value, we're starting to see some performance degradation on benchmarks.
/// For example, the blake3 benchmark went from 285 MHz to 250 MHz (~10% degradation). Perhaps a
/// better solution would be to make this value much smaller (~1000), and then fallback to a `Vec`
/// if the stack overflows.
const STACK_BUFFER_SIZE: usize = 6850;

/// The initial position of the top of the stack in the stack buffer.
///
/// We place this value close to 0 because if a program hits the limit, it's much more likely to hit
/// the upper bound than the lower bound, since hitting the lower bound only occurs when you drop
/// 0's that were generated automatically to keep the stack depth at 16. In practice, if this
/// occurs, it is most likely a bug.
const INITIAL_STACK_TOP_IDX: usize = 250;

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
    pub(super) stack: [Felt; STACK_BUFFER_SIZE],
    /// The index of the top of the stack.
    stack_top_idx: usize,
    /// The index of the bottom of the stack.
    stack_bot_idx: usize,

    /// The current clock cycle.
    pub(super) clk: RowIndex,

    /// The current context ID.
    pub(super) ctx: ContextId,

    /// The free memory pointer.
    pub(super) fmp: Felt,

    /// Whether we are currently in a syscall.
    in_syscall: bool,

    /// The hash of the function that called into the current context, or `[ZERO, ZERO, ZERO,
    /// ZERO]` if we are in the first context (i.e. when `call_stack` is empty).
    pub(super) caller_hash: Word,

    /// The advice provider to be used during execution.
    pub(super) advice: AdviceProvider,

    /// A map from (context_id, word_address) to the word stored starting at that memory location.
    pub(super) memory: Memory,

    /// A map storing metadata per call to the ACE chiplet.
    pub(super) ace: Ace,

    /// The call stack is used when starting a new execution context (from a `call`, `syscall` or
    /// `dyncall`) to keep track of the information needed to return to the previous context upon
    /// return. It is a stack since calls can be nested.
    call_stack: Vec<ExecutionContextInfo>,

    /// Whether to enable debug statements and tracing.
    in_debug_mode: bool,
}

impl FastProcessor {
    // CONSTRUCTORS
    // ----------------------------------------------------------------------------------------------

    /// Creates a new `FastProcessor` instance with the given stack inputs.
    ///
    /// # Panics
    /// - Panics if the length of `stack_inputs` is greater than `MIN_STACK_DEPTH`.
    pub fn new(stack_inputs: &[Felt]) -> Self {
        Self::initialize(stack_inputs, AdviceInputs::default(), false)
    }

    /// Creates a new `FastProcessor` instance with the given stack and advice inputs.
    ///
    /// # Panics
    /// - Panics if the length of `stack_inputs` is greater than `MIN_STACK_DEPTH`.
    pub fn new_with_advice_inputs(stack_inputs: &[Felt], advice_inputs: AdviceInputs) -> Self {
        Self::initialize(stack_inputs, advice_inputs, false)
    }

    /// Creates a new `FastProcessor` instance, set to debug mode, with the given stack
    /// and advice inputs.
    ///
    /// # Panics
    /// - Panics if the length of `stack_inputs` is greater than `MIN_STACK_DEPTH`.
    pub fn new_debug(stack_inputs: &[Felt], advice_inputs: AdviceInputs) -> Self {
        Self::initialize(stack_inputs, advice_inputs, true)
    }

    /// Generic constructor unifying the above public ones.
    ///
    /// The stack inputs are expected to be stored in reverse order. For example, if `stack_inputs =
    /// [1,2,3]`, then the stack will be initialized as `[3,2,1,0,0,...]`, with `3` being on
    /// top.
    fn initialize(stack_inputs: &[Felt], advice_inputs: AdviceInputs, in_debug_mode: bool) -> Self {
        assert!(stack_inputs.len() <= MIN_STACK_DEPTH);

        let stack_top_idx = INITIAL_STACK_TOP_IDX;
        let stack = {
            let mut stack = [ZERO; STACK_BUFFER_SIZE];
            let bottom_idx = stack_top_idx - stack_inputs.len();

            stack[bottom_idx..stack_top_idx].copy_from_slice(stack_inputs);
            stack
        };

        Self {
            advice: advice_inputs.into(),
            stack,
            stack_top_idx,
            stack_bot_idx: stack_top_idx - MIN_STACK_DEPTH,
            clk: 0_u32.into(),
            ctx: 0_u32.into(),
            fmp: Felt::new(FMP_MIN),
            in_syscall: false,
            caller_hash: EMPTY_WORD,
            memory: Memory::new(),
            call_stack: Vec::new(),
            ace: Ace::default(),
            in_debug_mode,
        }
    }

    // ACCESSORS
    // -------------------------------------------------------------------------------------------

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
    /// That is, for `start_idx=0` the top element of the stack will be at the last position in the
    /// word.
    ///
    /// For example, if the stack looks like this:
    ///
    /// top                                                       bottom
    /// v                                                           v
    /// a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p
    ///
    /// Then
    /// - `stack_get_word(0)` returns `[d, c, b, a]`,
    /// - `stack_get_word(1)` returns `[e, d, c ,b]`,
    /// - etc.
    #[inline(always)]
    pub fn stack_get_word(&self, start_idx: usize) -> Word {
        // Ensure we have enough elements to form a complete word
        debug_assert!(
            start_idx + WORD_SIZE <= self.stack_depth() as usize,
            "Not enough elements on stack to read word starting at index {start_idx}"
        );

        let word_start_idx = self.stack_top_idx - start_idx - 4;
        let result: [Felt; WORD_SIZE] =
            self.stack[range(word_start_idx, WORD_SIZE)].try_into().unwrap();
        result.into()
    }

    /// Returns the number of elements on the stack in the current context.
    #[inline(always)]
    pub fn stack_depth(&self) -> u32 {
        (self.stack_top_idx - self.stack_bot_idx) as u32
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
    /// The index is the index of the first element of the word, and the word is written in reverse
    /// order.
    #[inline(always)]
    pub fn stack_write_word(&mut self, start_idx: usize, word: &Word) {
        debug_assert!(start_idx < MIN_STACK_DEPTH);

        let word_start_idx = self.stack_top_idx - start_idx - 4;
        let source: [Felt; WORD_SIZE] = (*word).into();
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
        host: &mut impl AsyncHost,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.execute_with_tracer(program, host, &mut NoopTracer).await
    }

    /// Executes the given program and returns the stack outputs, the advice provider, and
    /// information for building the trace.
    pub async fn execute_for_trace(
        self,
        program: &Program,
        host: &mut impl AsyncHost,
        fragment_size: usize,
    ) -> Result<(ExecutionOutput, TraceFragmentContexts), ExecutionError> {
        let mut tracer = ExecutionTracer::new(fragment_size);
        let execution_output = self.execute_with_tracer(program, host, &mut tracer).await?;

        Ok((execution_output, tracer.into_fragment_contexts()))
    }

    /// Executes the given program with the provided tracer and returns the stack outputs, and the
    /// advice provider.
    pub async fn execute_with_tracer(
        mut self,
        program: &Program,
        host: &mut impl AsyncHost,
        tracer: &mut impl Tracer,
    ) -> Result<ExecutionOutput, ExecutionError> {
        let stack_outputs = self.execute_impl(program, host, tracer).await?;

        Ok(ExecutionOutput {
            stack: stack_outputs,
            advice: self.advice,
            memory: self.memory,
        })
    }

    /// Executes the given program with the provided tracer and returns the stack outputs.
    ///
    /// This function takes a `&mut self` (compared to `self` for the public execute functions) so
    /// that the processor state may be accessed after execution. It is incorrect to execute a
    /// second program using the same processor. This is mainly meant to be used in tests.
    async fn execute_impl(
        &mut self,
        program: &Program,
        host: &mut impl AsyncHost,
        tracer: &mut impl Tracer,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut continuation_stack = ContinuationStack::new(program);
        let mut current_forest = program.mast_forest().clone();

        // Merge the program's advice map into the advice provider
        self.advice
            .extend_map(current_forest.advice_map())
            .map_err(|err| ExecutionError::advice_error(err, self.clk, &()))?;

        while let Some(continuation) = continuation_stack.pop_continuation() {
            match continuation {
                Continuation::StartNode(node_id) => {
                    let node = current_forest.get_node_by_id(node_id).unwrap();

                    match node {
                        MastNode::Block(basic_block_node) => {
                            self.execute_basic_block_node(
                                basic_block_node,
                                node_id,
                                &current_forest,
                                host,
                                &mut continuation_stack,
                                &current_forest,
                                tracer,
                            )
                            .await?
                        },
                        MastNode::Join(join_node) => self.start_join_node(
                            join_node,
                            node_id,
                            &current_forest,
                            &mut continuation_stack,
                            host,
                            tracer,
                        )?,
                        MastNode::Split(split_node) => self.start_split_node(
                            split_node,
                            node_id,
                            &current_forest,
                            &mut continuation_stack,
                            host,
                            tracer,
                        )?,
                        MastNode::Loop(loop_node) => self.start_loop_node(
                            loop_node,
                            node_id,
                            &current_forest,
                            &mut continuation_stack,
                            host,
                            tracer,
                        )?,
                        MastNode::Call(call_node) => self.start_call_node(
                            call_node,
                            node_id,
                            program,
                            &current_forest,
                            &mut continuation_stack,
                            host,
                            tracer,
                        )?,
                        MastNode::Dyn(_) => {
                            self.start_dyn_node(
                                node_id,
                                &mut current_forest,
                                &mut continuation_stack,
                                host,
                                tracer,
                            )
                            .await?
                        },
                        MastNode::External(_external_node) => {
                            self.execute_external_node(
                                node_id,
                                &mut current_forest,
                                &mut continuation_stack,
                                host,
                                tracer,
                            )
                            .await?
                        },
                    }
                },
                Continuation::FinishJoin(node_id) => self.finish_join_node(
                    node_id,
                    &current_forest,
                    &mut continuation_stack,
                    host,
                    tracer,
                )?,
                Continuation::FinishSplit(node_id) => self.finish_split_node(
                    node_id,
                    &current_forest,
                    &mut continuation_stack,
                    host,
                    tracer,
                )?,
                Continuation::FinishLoop(node_id) => self.finish_loop_node(
                    node_id,
                    &current_forest,
                    &mut continuation_stack,
                    host,
                    tracer,
                )?,
                Continuation::FinishCall(node_id) => self.finish_call_node(
                    node_id,
                    &current_forest,
                    &mut continuation_stack,
                    host,
                    tracer,
                )?,
                Continuation::FinishDyn(node_id) => self.finish_dyn_node(
                    node_id,
                    &current_forest,
                    &mut continuation_stack,
                    host,
                    tracer,
                )?,
                Continuation::EnterForest(previous_forest) => {
                    // Restore the previous forest
                    current_forest = previous_forest;
                },
            }
        }

        StackOutputs::new(
            self.stack[self.stack_bot_idx..self.stack_top_idx]
                .iter()
                .rev()
                .copied()
                .collect(),
        )
        .map_err(|_| {
            ExecutionError::OutputStackOverflow(
                self.stack_top_idx - self.stack_bot_idx - MIN_STACK_DEPTH,
            )
        })
    }

    // DECORATOR EXECUTORS
    // --------------------------------------------------------------------------------------------

    /// Executes the decorators that should be executed before entering a node.
    fn execute_before_enter_decorators(
        &mut self,
        node_id: MastNodeId,
        current_forest: &MastForest,
        host: &mut impl AsyncHost,
    ) -> Result<(), ExecutionError> {
        let node = current_forest
            .get_node_by_id(node_id)
            .expect("internal error: node id {node_id} not found in current forest");

        for &decorator_id in node.before_enter() {
            self.execute_decorator(&current_forest[decorator_id], host)?;
        }

        Ok(())
    }

    /// Executes the decorators that should be executed after exiting a node.
    fn execute_after_exit_decorators(
        &mut self,
        node_id: MastNodeId,
        current_forest: &MastForest,
        host: &mut impl AsyncHost,
    ) -> Result<(), ExecutionError> {
        let node = current_forest
            .get_node_by_id(node_id)
            .expect("internal error: node id {node_id} not found in current forest");

        for &decorator_id in node.after_exit() {
            self.execute_decorator(&current_forest[decorator_id], host)?;
        }

        Ok(())
    }

    /// Executes the specified decorator
    fn execute_decorator(
        &mut self,
        decorator: &Decorator,
        host: &mut impl AsyncHost,
    ) -> Result<(), ExecutionError> {
        match decorator {
            Decorator::Debug(options) => {
                if self.in_debug_mode {
                    let process = &mut self.state();
                    host.on_debug(process, options)?;
                }
            },
            Decorator::AsmOp(_assembly_op) => {
                // do nothing
            },
            Decorator::Trace(id) => {
                let process = &mut self.state();
                host.on_trace(process, *id)?;
            },
        };
        Ok(())
    }

    // HELPERS
    // ----------------------------------------------------------------------------------------------

    /// Increments the clock by 1.
    #[inline(always)]
    fn increment_clk(&mut self, tracer: &mut impl Tracer) {
        self.clk += 1_u32;

        tracer.increment_clk();
    }

    async fn load_mast_forest<E>(
        &mut self,
        node_digest: Word,
        host: &mut impl AsyncHost,
        get_mast_forest_failed: impl Fn(Word, &E) -> ExecutionError,
        err_ctx: &E,
    ) -> Result<(MastNodeId, Arc<MastForest>), ExecutionError>
    where
        E: ErrorContext,
    {
        let mast_forest = host
            .get_mast_forest(&node_digest)
            .await
            .ok_or_else(|| get_mast_forest_failed(node_digest, err_ctx))?;

        // We limit the parts of the program that can be called externally to procedure
        // roots, even though MAST doesn't have that restriction.
        let root_id = mast_forest
            .find_procedure_root(node_digest)
            .ok_or(ExecutionError::malfored_mast_forest_in_host(node_digest, err_ctx))?;

        // Merge the advice map of this forest into the advice provider.
        // Note that the map may be merged multiple times if a different procedure from the same
        // forest is called.
        // For now, only compiled libraries contain non-empty advice maps, so for most cases,
        // this call will be cheap.
        self.advice
            .extend_map(mast_forest.advice_map())
            .map_err(|err| ExecutionError::advice_error(err, self.clk, err_ctx))?;

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

    // TESTING
    // ----------------------------------------------------------------------------------------------

    /// Convenience sync wrapper to [Self::execute] for testing purposes.
    #[cfg(any(test, feature = "testing"))]
    pub fn execute_sync(
        self,
        program: &Program,
        host: &mut impl AsyncHost,
    ) -> Result<StackOutputs, ExecutionError> {
        // Create a new Tokio runtime and block on the async execution
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();

        let execution_output = rt.block_on(self.execute(program, host))?;

        Ok(execution_output.stack)
    }

    /// Convenience sync wrapper to [Self::execute_for_trace] for testing purposes.
    #[cfg(any(test, feature = "testing"))]
    pub fn execute_for_trace_sync(
        self,
        program: &Program,
        host: &mut impl AsyncHost,
        fragment_size: usize,
    ) -> Result<(ExecutionOutput, TraceFragmentContexts), ExecutionError> {
        // Create a new Tokio runtime and block on the async execution
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();

        rt.block_on(self.execute_for_trace(program, host, fragment_size))
    }

    /// Similar to [Self::execute_sync], but allows mutable access to the processor.
    #[cfg(any(test, feature = "testing"))]
    pub fn execute_sync_mut(
        &mut self,
        program: &Program,
        host: &mut impl AsyncHost,
    ) -> Result<StackOutputs, ExecutionError> {
        // Create a new Tokio runtime and block on the async execution
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();

        rt.block_on(self.execute_impl(program, host, &mut NoopTracer))
    }
}

// EXECUTION OUTPUT
// ===============================================================================================

/// The output of a program execution, containing the state of the stack, advice provider, and
/// memory at the end of the execution.
#[derive(Debug)]
pub struct ExecutionOutput {
    pub stack: StackOutputs,
    pub advice: AdviceProvider,
    pub memory: Memory,
}

// FAST PROCESS STATE
// ===============================================================================================

#[derive(Debug)]
pub struct FastProcessState<'a> {
    pub(super) processor: &'a mut FastProcessor,
}

impl FastProcessor {
    #[inline(always)]
    pub fn state(&mut self) -> ProcessState<'_> {
        ProcessState::Fast(FastProcessState { processor: self })
    }
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
    fmp: Felt,
}
