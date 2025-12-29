use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{cmp::min, ops::ControlFlow};

use miden_air::{Felt, RowIndex};
use miden_core::{
    Decorator, EMPTY_WORD, Kernel, Program, StackOutputs, WORD_SIZE, Word, ZERO,
    mast::{MastForest, MastNode, MastNodeExt, MastNodeId},
    precompile::PrecompileTranscript,
    stack::MIN_STACK_DEPTH,
    utils::range,
};

use crate::{
    AdviceInputs, AdviceProvider, AsyncHost, ContextId, ErrorContext, ExecutionError, ProcessState,
    chiplets::Ace,
    continuation_stack::{Continuation, ContinuationStack},
    fast::{
        execution_tracer::{ExecutionTracer, TraceGenerationContext},
        step::{BreakReason, NeverStopper, StepStopper, Stopper},
    },
};

pub mod execution_tracer;
mod memory;
pub use memory::Memory;

mod operation;
pub use operation::eval_circuit_fast_;

pub(crate) mod step;
pub use step::ResumeContext;

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

/// The default size of core trace fragments when generating execution traces.
pub const DEFAULT_CORE_TRACE_FRAGMENT_SIZE: usize = 1 << 12; // 4096

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
    pub(super) stack: Box<[Felt; STACK_BUFFER_SIZE]>,
    /// The index of the top of the stack.
    stack_top_idx: usize,
    /// The index of the bottom of the stack.
    stack_bot_idx: usize,

    /// The current clock cycle.
    pub(super) clk: RowIndex,

    /// The current context ID.
    pub(super) ctx: ContextId,

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

    /// Transcript used to record commitments via `log_precompile` instruction (implemented via RPO
    /// sponge).
    pc_transcript: PrecompileTranscript,
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
            // Note: we use `Vec::into_boxed_slice()` here, since `Box::new([T; N])` first allocates
            // the array on the stack, and then moves it to the heap. This might cause a
            // stack overflow on some systems.
            let mut stack: Box<[Felt; STACK_BUFFER_SIZE]> =
                vec![ZERO; STACK_BUFFER_SIZE].into_boxed_slice().try_into().unwrap();
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
            caller_hash: EMPTY_WORD,
            memory: Memory::new(),
            call_stack: Vec::new(),
            ace: Ace::default(),
            in_debug_mode,
            pc_transcript: PrecompileTranscript::new(),
        }
    }

    /// Returns the resume context to be used with the first call to `step()`.
    pub fn get_initial_resume_context(
        &mut self,
        program: &Program,
    ) -> Result<ResumeContext, ExecutionError> {
        self.advice
            .extend_map(program.mast_forest().advice_map())
            .map_err(|err| ExecutionError::advice_error(err, self.clk, &()))?;

        Ok(ResumeContext {
            current_forest: program.mast_forest().clone(),
            continuation_stack: ContinuationStack::new(program),
            kernel: program.kernel().clone(),
        })
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

    /// Returns a reference to the processor's memory.
    pub fn memory(&self) -> &Memory {
        &self.memory
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
    /// context necessary to build the trace.
    pub async fn execute_for_trace(
        self,
        program: &Program,
        host: &mut impl AsyncHost,
        fragment_size: usize,
    ) -> Result<(ExecutionOutput, TraceGenerationContext), ExecutionError> {
        let mut tracer = ExecutionTracer::new(fragment_size);
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
        host: &mut impl AsyncHost,
        tracer: &mut impl Tracer,
    ) -> Result<ExecutionOutput, ExecutionError> {
        let mut continuation_stack = ContinuationStack::new(program);
        let mut current_forest = program.mast_forest().clone();

        // Merge the program's advice map into the advice provider
        self.advice
            .extend_map(current_forest.advice_map())
            .map_err(|err| ExecutionError::advice_error(err, self.clk, &()))?;

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
        host: &mut impl AsyncHost,
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
    async fn execute_impl(
        &mut self,
        continuation_stack: &mut ContinuationStack,
        current_forest: &mut Arc<MastForest>,
        kernel: &Kernel,
        host: &mut impl AsyncHost,
        tracer: &mut impl Tracer,
        stopper: &impl Stopper,
    ) -> ControlFlow<BreakReason, StackOutputs> {
        while let Some(continuation) = continuation_stack.pop_continuation() {
            match continuation {
                Continuation::StartNode(node_id) => {
                    let node = current_forest.get_node_by_id(node_id).unwrap();

                    match node {
                        MastNode::Block(basic_block_node) => {
                            self.execute_basic_block_node_from_start(
                                basic_block_node,
                                node_id,
                                host,
                                continuation_stack,
                                current_forest,
                                tracer,
                                stopper,
                            )
                            .await?
                        },
                        MastNode::Join(join_node) => self.start_join_node(
                            join_node,
                            node_id,
                            current_forest,
                            continuation_stack,
                            host,
                            tracer,
                            stopper,
                        )?,
                        MastNode::Split(split_node) => self.start_split_node(
                            split_node,
                            node_id,
                            current_forest,
                            continuation_stack,
                            host,
                            tracer,
                            stopper,
                        )?,
                        MastNode::Loop(loop_node) => self.start_loop_node(
                            loop_node,
                            node_id,
                            current_forest,
                            continuation_stack,
                            host,
                            tracer,
                            stopper,
                        )?,
                        MastNode::Call(call_node) => self.start_call_node(
                            call_node,
                            node_id,
                            kernel,
                            current_forest,
                            continuation_stack,
                            host,
                            tracer,
                            stopper,
                        )?,
                        MastNode::Dyn(_) => {
                            self.start_dyn_node(
                                node_id,
                                current_forest,
                                continuation_stack,
                                host,
                                tracer,
                                stopper,
                            )
                            .await?
                        },
                        MastNode::External(_external_node) => {
                            self.execute_external_node(
                                node_id,
                                current_forest,
                                continuation_stack,
                                host,
                                tracer,
                            )
                            .await?
                        },
                    }
                },
                Continuation::FinishJoin(node_id) => self.finish_join_node(
                    node_id,
                    current_forest,
                    continuation_stack,
                    host,
                    tracer,
                    stopper,
                )?,
                Continuation::FinishSplit(node_id) => self.finish_split_node(
                    node_id,
                    current_forest,
                    continuation_stack,
                    host,
                    tracer,
                    stopper,
                )?,
                Continuation::FinishLoop(node_id) => self.finish_loop_node(
                    node_id,
                    current_forest,
                    continuation_stack,
                    host,
                    tracer,
                    stopper,
                )?,
                Continuation::FinishLoopUnentered(node_id) => self.finish_loop_node_unentered(
                    node_id,
                    current_forest,
                    continuation_stack,
                    host,
                    tracer,
                    stopper,
                )?,
                Continuation::FinishCall(node_id) => self.finish_call_node(
                    node_id,
                    current_forest,
                    continuation_stack,
                    host,
                    tracer,
                    stopper,
                )?,
                Continuation::FinishDyn(node_id) => self.finish_dyn_node(
                    node_id,
                    current_forest,
                    continuation_stack,
                    host,
                    tracer,
                    stopper,
                )?,
                Continuation::FinishExternal(node_id) => {
                    // Execute after_exit decorators when returning from an external node
                    // Note: current_forest should already be restored by EnterForest continuation
                    self.execute_after_exit_decorators(node_id, current_forest, host)?;
                },
                Continuation::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } => {
                    let basic_block_node =
                        current_forest.get_node_by_id(node_id).unwrap().unwrap_basic_block();
                    self.execute_basic_block_node_from_op_idx(
                        basic_block_node,
                        node_id,
                        batch_index,
                        op_idx_in_batch,
                        host,
                        continuation_stack,
                        current_forest,
                        tracer,
                        stopper,
                    )
                    .await?
                },
                Continuation::Respan { node_id, batch_index } => {
                    let basic_block_node =
                        current_forest.get_node_by_id(node_id).unwrap().unwrap_basic_block();

                    self.execute_basic_block_node_from_batch(
                        basic_block_node,
                        node_id,
                        batch_index,
                        host,
                        continuation_stack,
                        current_forest,
                        tracer,
                        stopper,
                    )
                    .await?
                },
                Continuation::FinishBasicBlock(node_id) => {
                    let basic_block_node =
                        current_forest.get_node_by_id(node_id).unwrap().unwrap_basic_block();

                    self.finish_basic_block(
                        basic_block_node,
                        node_id,
                        current_forest,
                        host,
                        continuation_stack,
                        tracer,
                        stopper,
                    )?
                },
                Continuation::EnterForest(previous_forest) => {
                    // Restore the previous forest
                    *current_forest = previous_forest;
                },
                Continuation::AfterExitDecorators(node_id) => {
                    self.execute_after_exit_decorators(node_id, current_forest, host)?
                },
                Continuation::AfterExitDecoratorsBasicBlock(node_id) => {
                    let basic_block_node =
                        current_forest.get_node_by_id(node_id).unwrap().unwrap_basic_block();

                    self.execute_end_of_block_decorators(
                        basic_block_node,
                        node_id,
                        current_forest,
                        host,
                    )?;
                    self.execute_after_exit_decorators(node_id, current_forest, host)?
                },
            }
        }

        match StackOutputs::new(
            self.stack[self.stack_bot_idx..self.stack_top_idx]
                .iter()
                .rev()
                .copied()
                .collect(),
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
        host: &mut impl AsyncHost,
    ) -> ControlFlow<BreakReason> {
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
        host: &mut impl AsyncHost,
    ) -> ControlFlow<BreakReason> {
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
        host: &mut impl AsyncHost,
    ) -> ControlFlow<BreakReason> {
        match decorator {
            Decorator::Debug(options) => {
                if self.in_debug_mode {
                    let clk = self.clk;
                    let process = &mut self.state();
                    if let Err(err) = host.on_debug(process, options) {
                        return ControlFlow::Break(BreakReason::Err(
                            ExecutionError::DebugHandlerError { clk, err },
                        ));
                    }
                }
            },
            Decorator::AsmOp(_assembly_op) => {
                // do nothing
            },
            Decorator::Trace(id) => {
                let clk = self.clk;
                let process = &mut self.state();
                if let Err(err) = host.on_trace(process, *id) {
                    return ControlFlow::Break(BreakReason::Err(
                        ExecutionError::TraceHandlerError { clk, trace_id: *id, err },
                    ));
                }
            },
        };
        ControlFlow::Continue(())
    }

    // HELPERS
    // ----------------------------------------------------------------------------------------------

    /// Increments the clock by 1.
    #[inline(always)]
    pub(crate) fn increment_clk(
        &mut self,
        tracer: &mut impl Tracer,
        stopper: &impl Stopper,
    ) -> ControlFlow<()> {
        self.clk += 1_u32;

        tracer.increment_clk();

        if stopper.should_stop(self) {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
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

    // SYNC WRAPPERS
    // ----------------------------------------------------------------------------------------------

    /// Convenience sync wrapper to [Self::step].
    pub fn step_sync(
        &mut self,
        host: &mut impl AsyncHost,
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
        host: &mut impl AsyncHost,
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
                                self.stack[self.stack_bot_idx..self.stack_top_idx]
                                    .iter()
                                    .rev()
                                    .copied()
                                    .collect(),
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
    pub fn execute_sync(
        self,
        program: &Program,
        host: &mut impl AsyncHost,
    ) -> Result<ExecutionOutput, ExecutionError> {
        // Create a new Tokio runtime and block on the async execution
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();

        rt.block_on(self.execute(program, host))
    }

    /// Convenience sync wrapper to [Self::execute_for_trace].
    pub fn execute_for_trace_sync(
        self,
        program: &Program,
        host: &mut impl AsyncHost,
        fragment_size: usize,
    ) -> Result<(ExecutionOutput, TraceGenerationContext), ExecutionError> {
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
        let mut continuation_stack = ContinuationStack::new(program);
        let mut current_forest = program.mast_forest().clone();

        // Merge the program's advice map into the advice provider
        self.advice
            .extend_map(current_forest.advice_map())
            .map_err(|err| ExecutionError::advice_error(err, self.clk, &()))?;

        rt.block_on(async {
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
        })
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
}
