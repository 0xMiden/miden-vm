use alloc::{sync::Arc, vec::Vec};
use core::cmp::min;

use memory::Memory;
use miden_air::RowIndex;
use miden_core::{
    Decorator, DecoratorIterator, EMPTY_WORD, Felt, ONE, Operation, Program, StackOutputs,
    WORD_SIZE, Word, ZERO,
    mast::{
        BasicBlockNode, CallNode, ExternalNode, JoinNode, LoopNode, MastForest, MastNode,
        MastNodeId, OP_GROUP_SIZE, OpBatch, SplitNode,
    },
    stack::MIN_STACK_DEPTH,
    utils::range,
};

use crate::{
    AdviceInputs, AdviceProvider, AsyncHost, ContextId, ErrorContext, ExecutionError, FMP_MIN,
    ProcessState, SYSCALL_FMP_MIN,
    chiplets::Ace,
    continuation_stack::{Continuation, ContinuationStack},
    decoder::block_stack::{self, BlockType},
    err_ctx,
    fast::{
        trace_state::{
            CoreTraceState, DecoderState, ExecutionContextSystemInfo, NodeExecutionState,
            SystemState,
        },
        trace_state_builder::CoreTraceStateBuilder,
    },
};

mod memory;
pub mod trace_state;
mod trace_state_builder;

// Ops
mod circuit_eval;
mod crypto_ops;
mod field_ops;
mod fri_ops;
mod horner_ops;
mod io_ops;
mod stack_ops;
mod sys_ops;
mod u32_ops;

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

/// WORD_SIZE, but as a `Felt`.
const WORD_SIZE_FELT: Felt = Felt::new(4);

/// The size of a double-word.
const DOUBLE_WORD_SIZE: Felt = Felt::new(8);

/// The number of rows per core trace fragment.
pub const NUM_ROWS_PER_CORE_FRAGMENT: usize = 1024;

/// The number of rows in the execution trace required to compute a permutation of Rescue Prime
/// Optimized.
const HASH_CYCLE_LEN: Felt = Felt::new(miden_air::trace::chiplets::hasher::HASH_CYCLE_LEN as u64);

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
    /// The counter which keeps track of the number of instructions that we can execute without
    /// hitting the bounds of `stack`.
    bounds_check_counter: usize,

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

    /// Builder of [CoreTraceState]s, used for generating corresponding trace fragments.
    trace_state_builder: Option<CoreTraceStateBuilder>,
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

        let stack_bot_idx = stack_top_idx - MIN_STACK_DEPTH;

        let bounds_check_counter = stack_bot_idx;
        Self {
            advice: advice_inputs.into(),
            stack,
            stack_top_idx,
            stack_bot_idx,
            bounds_check_counter,
            clk: 0_u32.into(),
            ctx: 0_u32.into(),
            fmp: Felt::new(FMP_MIN),
            in_syscall: false,
            caller_hash: EMPTY_WORD,
            memory: Memory::new(),
            call_stack: Vec::new(),
            ace: Ace::default(),
            in_debug_mode,
            trace_state_builder: None,
        }
    }

    // ACCESSORS
    // -------------------------------------------------------------------------------------------

    /// Returns the stack, such that the top of the stack is at the last index of the returned
    /// slice.
    pub fn stack(&self) -> &[Felt] {
        &self.stack[self.stack_bot_idx..self.stack_top_idx]
    }

    /// Returns the top 16 elements of the stack.
    pub fn stack_top(&self) -> &[Felt] {
        &self.stack[self.stack_top_idx - MIN_STACK_DEPTH..self.stack_top_idx]
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
        debug_assert!(start_idx < MIN_STACK_DEPTH);

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
        mut self,
        program: &Program,
        host: &mut impl AsyncHost,
    ) -> Result<(StackOutputs, AdviceProvider), ExecutionError> {
        let stack_outputs = self.execute_impl(program, host).await?;

        Ok((stack_outputs, self.advice))
    }

    /// Executes the given program and returns the stack outputs, the advice provider, and
    /// information for building the trace.
    pub async fn execute_for_trace(
        mut self,
        program: &Program,
        host: &mut impl AsyncHost,
    ) -> Result<(StackOutputs, AdviceProvider, Vec<CoreTraceState>), ExecutionError> {
        self.trace_state_builder = Some(CoreTraceStateBuilder::default());
        let stack_outputs = self.execute_impl(program, host).await?;

        Ok((
            stack_outputs,
            self.advice,
            self.trace_state_builder
                .expect("Trace state builder expected to be initialized when executing for trace")
                .into_core_trace_states(),
        ))
    }

    async fn execute_impl(
        &mut self,
        program: &Program,
        host: &mut impl AsyncHost,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut continuation_stack = ContinuationStack::new(program);
        let mut current_forest = program.mast_forest().clone();

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
                            )
                            .await?
                        },
                        MastNode::Join(join_node) => self.start_join_node(
                            join_node,
                            node_id,
                            &current_forest,
                            &mut continuation_stack,
                            host,
                        )?,
                        MastNode::Split(split_node) => self.start_split_node(
                            split_node,
                            node_id,
                            &current_forest,
                            &mut continuation_stack,
                            host,
                        )?,
                        MastNode::Loop(loop_node) => self.start_loop_node(
                            loop_node,
                            node_id,
                            &current_forest,
                            &mut continuation_stack,
                            host,
                        )?,
                        MastNode::Call(call_node) => self.start_call_node(
                            call_node,
                            node_id,
                            program,
                            &current_forest,
                            &mut continuation_stack,
                            host,
                        )?,
                        MastNode::Dyn(dyn_node) => {
                            self.start_dyn_node(
                                dyn_node.is_dyncall(),
                                node_id,
                                &mut current_forest,
                                &mut continuation_stack,
                                host,
                            )
                            .await?
                        },
                        MastNode::External(_external_node) => {
                            self.execute_external_node(
                                node_id,
                                &mut current_forest,
                                &mut continuation_stack,
                                host,
                            )
                            .await?
                        },
                    }
                },
                Continuation::FinishJoin(node_id) => {
                    self.finish_join_node(node_id, &current_forest, &mut continuation_stack, host)?
                },
                Continuation::FinishSplit(node_id) => {
                    self.finish_split_node(node_id, &current_forest, &mut continuation_stack, host)?
                },
                Continuation::FinishLoop(node_id) => {
                    self.finish_loop_node(node_id, &current_forest, &mut continuation_stack, host)?
                },
                Continuation::FinishCall(node_id) => {
                    self.finish_call_node(node_id, &current_forest, &mut continuation_stack, host)?
                },
                Continuation::FinishDyn(node_id) => {
                    self.finish_dyn_node(node_id, &current_forest, &mut continuation_stack, host)?
                },
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

    // NODE EXECUTORS
    // --------------------------------------------------------------------------------------------

    /// Executes a Join node from the start.
    #[inline(always)]
    fn start_join_node(
        &mut self,
        join_node: &JoinNode,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
    ) -> Result<(), ExecutionError> {
        self.check_extract_trace_state(
            NodeExecutionState::Start(node_id),
            continuation_stack,
            current_forest,
        );

        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(node_id, current_forest, host)?;

        continuation_stack.push_finish_join(node_id);
        continuation_stack.push_start_node(join_node.second());
        continuation_stack.push_start_node(join_node.first());

        // In tracing mode, record the control block on the block stack
        if let Some(ref mut trace_state_builder) = self.trace_state_builder {
            let block_addr = trace_state_builder.hasher.record_hash_control_block();
            let parent_addr =
                trace_state_builder.block_stack.push(block_addr, BlockType::Join(false), None);
            trace_state_builder.block_stack_replay.record_node_start(parent_addr);
        }

        // Corresponds to the row inserted for the JOIN operation added
        // to the trace.
        self.increment_clk();

        Ok(())
    }

    /// Executes the finish phase of a Join node.
    #[inline(always)]
    fn finish_join_node(
        &mut self,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
    ) -> Result<(), ExecutionError> {
        self.check_extract_trace_state(
            NodeExecutionState::End(node_id),
            continuation_stack,
            current_forest,
        );

        if let Some(ref mut trace_state_builder) = self.trace_state_builder {
            let block_info = trace_state_builder.block_stack.pop();
            trace_state_builder.record_node_end(&block_info);
        }

        // Corresponds to the row inserted for the END operation added
        // to the trace.
        self.increment_clk();

        self.execute_after_exit_decorators(node_id, current_forest, host)
    }

    /// Executes a Split node from the start.
    #[inline(always)]
    fn start_split_node(
        &mut self,
        split_node: &SplitNode,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
    ) -> Result<(), ExecutionError> {
        self.check_extract_trace_state(
            NodeExecutionState::Start(node_id),
            continuation_stack,
            current_forest,
        );

        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(node_id, current_forest, host)?;

        let condition = self.stack_get(0);

        // drop the condition from the stack
        self.decrement_stack_size();

        // execute the appropriate branch
        continuation_stack.push_finish_split(node_id);
        if condition == ONE {
            continuation_stack.push_start_node(split_node.on_true());
        } else if condition == ZERO {
            continuation_stack.push_start_node(split_node.on_false());
        } else {
            let err_ctx = err_ctx!(current_forest, split_node, host);
            return Err(ExecutionError::not_binary_value_if(condition, &err_ctx));
        };

        // In tracing mode, record the control block on the block stack
        if let Some(ref mut trace_state_builder) = self.trace_state_builder {
            let block_addr = trace_state_builder.hasher.record_hash_control_block();
            let parent_addr =
                trace_state_builder.block_stack.push(block_addr, BlockType::Split, None);
            trace_state_builder.block_stack_replay.record_node_start(parent_addr);
        }

        // Corresponds to the row inserted for the SPLIT operation added
        // to the trace.
        self.increment_clk();

        Ok(())
    }

    /// Executes the finish phase of a Split node.
    #[inline(always)]
    fn finish_split_node(
        &mut self,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
    ) -> Result<(), ExecutionError> {
        self.check_extract_trace_state(
            NodeExecutionState::End(node_id),
            continuation_stack,
            current_forest,
        );
        if let Some(ref mut trace_state_builder) = self.trace_state_builder {
            let block_info = trace_state_builder.block_stack.pop();
            trace_state_builder.record_node_end(&block_info);
        }

        // Corresponds to the row inserted for the END operation added
        // to the trace.
        self.increment_clk();

        self.execute_after_exit_decorators(node_id, current_forest, host)
    }

    /// Executes a Loop node from the start.
    #[inline(always)]
    fn start_loop_node(
        &mut self,
        loop_node: &LoopNode,
        current_node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
    ) -> Result<(), ExecutionError> {
        self.check_extract_trace_state(
            NodeExecutionState::Start(current_node_id),
            continuation_stack,
            current_forest,
        );

        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(current_node_id, current_forest, host)?;

        let condition = self.stack_get(0);

        // drop the condition from the stack
        self.decrement_stack_size();

        // execute the loop body as long as the condition is true
        if condition == ONE {
            // Push the loop to check condition again after body
            // executes
            continuation_stack.push_finish_loop(current_node_id);
            continuation_stack.push_start_node(loop_node.body());

            // In tracing mode, record the control block on the block stack
            if let Some(ref mut trace_state_builder) = self.trace_state_builder {
                let block_addr = trace_state_builder.hasher.record_hash_control_block();
                let enter_loop = true;
                let parent_addr = trace_state_builder.block_stack.push(
                    block_addr,
                    BlockType::Loop(enter_loop),
                    None,
                );
                trace_state_builder.block_stack_replay.record_node_start(parent_addr);
            }

            // Corresponds to the row inserted for the LOOP operation added
            // to the trace.
            self.increment_clk();
        } else if condition == ZERO {
            // Start and exit the loop immediately - corresponding to adding a LOOP and END row
            // immediately since there is no body to execute.

            // In tracing mode, record the control block on the block stack
            if let Some(ref mut trace_state_builder) = self.trace_state_builder {
                let block_addr = trace_state_builder.hasher.record_hash_control_block();
                let enter_loop = false;
                let parent_addr = trace_state_builder.block_stack.push(
                    block_addr,
                    BlockType::Loop(enter_loop),
                    None,
                );
                trace_state_builder.block_stack_replay.record_node_start(parent_addr);
            }

            // Increment the clock, corresponding to the LOOP operation
            self.increment_clk();

            self.check_extract_trace_state(
                NodeExecutionState::End(current_node_id),
                continuation_stack,
                current_forest,
            );

            if let Some(ref mut trace_state_builder) = self.trace_state_builder {
                let block_info = trace_state_builder.block_stack.pop();
                trace_state_builder.record_node_end(&block_info);
            }

            // Increment the clock, corresponding to the END operation added to the trace.
            self.increment_clk();
        } else {
            let err_ctx = err_ctx!(current_forest, loop_node, host);
            return Err(ExecutionError::not_binary_value_loop(condition, &err_ctx));
        }
        Ok(())
    }

    /// Executes the finish phase of a Loop node.
    #[inline(always)]
    fn finish_loop_node(
        &mut self,
        current_node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
    ) -> Result<(), ExecutionError> {
        // This happens after loop body execution
        // Check condition again to see if we should continue looping
        let condition = self.stack_get(0);
        let loop_node = current_forest[current_node_id].unwrap_loop();

        if condition == ONE {
            // Add REPEAT row and continue looping
            self.check_extract_trace_state(
                NodeExecutionState::LoopRepeat(current_node_id),
                continuation_stack,
                current_forest,
            );

            // Drop the condition from the stack (on the REPEAT instruction)
            self.decrement_stack_size();

            continuation_stack.push_finish_loop(current_node_id);
            continuation_stack.push_start_node(loop_node.body());

            // Corresponds to the REPEAT operation added to the trace.
            self.increment_clk();
        } else if condition == ZERO {
            // Exit the loop - add END row
            self.check_extract_trace_state(
                NodeExecutionState::End(current_node_id),
                continuation_stack,
                current_forest,
            );
            self.decrement_stack_size();

            if let Some(ref mut trace_state_builder) = self.trace_state_builder {
                let block_info = trace_state_builder.block_stack.pop();
                trace_state_builder.record_node_end(&block_info);
            }

            // Corresponds to the END operation added to the trace.
            self.increment_clk();
            self.execute_after_exit_decorators(current_node_id, current_forest, host)?;
        } else {
            let err_ctx = err_ctx!(current_forest, loop_node, host);
            return Err(ExecutionError::not_binary_value_loop(condition, &err_ctx));
        }
        Ok(())
    }

    /// Executes a Call node from the start.
    #[inline(always)]
    fn start_call_node(
        &mut self,
        call_node: &CallNode,
        current_node_id: MastNodeId,
        program: &Program,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
    ) -> Result<(), ExecutionError> {
        self.check_extract_trace_state(
            NodeExecutionState::Start(current_node_id),
            continuation_stack,
            current_forest,
        );

        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(current_node_id, current_forest, host)?;

        let err_ctx = err_ctx!(current_forest, call_node, host);

        // call or syscall are not allowed inside a syscall
        if self.in_syscall {
            let instruction = if call_node.is_syscall() { "syscall" } else { "call" };
            return Err(ExecutionError::CallInSyscall(instruction));
        }

        // In tracing mode, record the control block on the block stack
        if self.trace_state_builder.is_some() {
            let overflow_addr = self
                .trace_state_builder
                .as_ref()
                .unwrap()
                .overflow_table
                .last_update_clk_in_current_ctx();
            let ctx_info = block_stack::ExecutionContextInfo::new(
                self.ctx,
                self.caller_hash,
                self.fmp,
                self.stack_depth(),
                overflow_addr,
            );

            let trace_state_builder = self.trace_state_builder.as_mut().unwrap();
            let block_addr = trace_state_builder.hasher.record_hash_control_block();
            if call_node.is_syscall() {
                let parent_addr = trace_state_builder.block_stack.push(
                    block_addr,
                    BlockType::SysCall,
                    Some(ctx_info),
                );
                trace_state_builder.block_stack_replay.record_node_start(parent_addr);
            } else {
                let parent_addr = trace_state_builder.block_stack.push(
                    block_addr,
                    BlockType::Call,
                    Some(ctx_info),
                );
                trace_state_builder.block_stack_replay.record_node_start(parent_addr);
            }
        }

        let callee_hash = current_forest
            .get_node_by_id(call_node.callee())
            .ok_or(ExecutionError::MastNodeNotFoundInForest { node_id: call_node.callee() })?
            .digest();

        self.save_context_and_truncate_stack();

        if call_node.is_syscall() {
            // check if the callee is in the kernel
            if !program.kernel().contains_proc(callee_hash) {
                return Err(ExecutionError::syscall_target_not_in_kernel(callee_hash, &err_ctx));
            }

            // set the system registers to the syscall context
            self.ctx = ContextId::root();
            self.fmp = SYSCALL_FMP_MIN.into();
            self.in_syscall = true;
        } else {
            // set the system registers to the callee context. The value for the new context is
            // defined to be the value of the clock cycle for the following operation.
            self.ctx = (self.clk + 1).into();
            self.fmp = Felt::new(FMP_MIN);
            self.caller_hash = callee_hash;
        }

        // push the callee onto the continuation stack, and increment the clock (corresponding to
        // the row inserted for the CALL or SYSCALL operation added to the trace).
        continuation_stack.push_finish_call(current_node_id);
        continuation_stack.push_start_node(call_node.callee());

        // Corresponds to the CALL or SYSCALL operation added to the trace.
        self.increment_clk();

        Ok(())
    }

    /// Executes the finish phase of a Call node.
    #[inline(always)]
    fn finish_call_node(
        &mut self,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
    ) -> Result<(), ExecutionError> {
        self.check_extract_trace_state(
            NodeExecutionState::End(node_id),
            continuation_stack,
            current_forest,
        );

        let call_node = current_forest[node_id].unwrap_call();
        let err_ctx = err_ctx!(current_forest, call_node, host);
        // when returning from a function call or a syscall, restore the
        // context of the
        // system registers and the operand stack to what it was prior
        // to the call.
        self.restore_context(&err_ctx)?;

        if let Some(ref mut trace_state_builder) = self.trace_state_builder {
            let block_info = trace_state_builder.block_stack.pop();
            trace_state_builder.record_node_end(&block_info);

            let exec_ctx = block_info.ctx_info.unwrap();
            trace_state_builder.record_execution_context(ExecutionContextSystemInfo {
                parent_ctx: exec_ctx.parent_ctx,
                parent_fn_hash: exec_ctx.parent_fn_hash,
                parent_fmp: exec_ctx.parent_fmp,
            });
        }

        // Corresponds to the row inserted for the END operation added to the trace.
        self.increment_clk();
        self.execute_after_exit_decorators(node_id, current_forest, host)
    }

    /// Executes a Dyn node from the start.
    #[inline(always)]
    async fn start_dyn_node(
        &mut self,
        is_dyncall: bool,
        current_node_id: MastNodeId,
        current_forest: &mut Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
    ) -> Result<(), ExecutionError> {
        self.check_extract_trace_state(
            NodeExecutionState::Start(current_node_id),
            continuation_stack,
            current_forest,
        );

        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(current_node_id, current_forest, host)?;

        // In tracing mode, record the control block on the block stack
        if self.trace_state_builder.is_some() {
            let block_addr =
                self.trace_state_builder.as_mut().unwrap().hasher.record_hash_control_block();

            if is_dyncall {
                let overflow_addr = self
                    .trace_state_builder
                    .as_ref()
                    .unwrap()
                    .overflow_table
                    .last_update_clk_in_current_ctx();
                // Note: the stack depth to record is the `current_stack_depth - 1` due to the
                // semantics of DYNCALL. That is, the top of the stack contains the memory address
                // to where the address to dynamically call is located. Then, the DYNCALL operation
                // performs a drop, and records the stack depth after the drop as the beginning of
                // the new context. For more information, look at the docs for how the constraints
                // are designed; it's a bit tricky but it works.
                let stack_depth_after_drop = self.stack_depth() - 1;
                let ctx_info = block_stack::ExecutionContextInfo::new(
                    self.ctx,
                    self.caller_hash,
                    self.fmp,
                    stack_depth_after_drop,
                    overflow_addr,
                );

                let parent_addr = self.trace_state_builder.as_mut().unwrap().block_stack.push(
                    block_addr,
                    BlockType::Dyncall,
                    Some(ctx_info),
                );
                self.trace_state_builder
                    .as_mut()
                    .unwrap()
                    .block_stack_replay
                    .record_node_start(parent_addr);
            } else {
                let parent_addr = self.trace_state_builder.as_mut().unwrap().block_stack.push(
                    block_addr,
                    BlockType::Dyn,
                    None,
                );
                self.trace_state_builder
                    .as_mut()
                    .unwrap()
                    .block_stack_replay
                    .record_node_start(parent_addr);
            }
        }

        // Corresponds to the row inserted for the DYN or DYNCALL operation
        // added to the trace.
        let dyn_node = current_forest[current_node_id].unwrap_dyn();

        // dyn calls are not allowed inside a syscall
        if dyn_node.is_dyncall() && self.in_syscall {
            return Err(ExecutionError::CallInSyscall("dyncall"));
        }

        let err_ctx = err_ctx!(&current_forest, dyn_node, host);

        // Retrieve callee hash from memory, using stack top as the memory
        // address.
        let callee_hash = {
            let mem_addr = self.stack_get(0);
            self.memory
                .read_word(self.ctx, mem_addr, self.clk, &err_ctx, &mut self.trace_state_builder)
                .map_err(ExecutionError::MemoryError)?
        };

        // Drop the memory address from the stack. This needs to be done before saving the context.
        self.decrement_stack_size();

        // For dyncall, save the context and reset it.
        if dyn_node.is_dyncall() {
            self.save_context_and_truncate_stack();
            // The value for the new context is defined to be the value of the clock cycle for the
            // following operation.
            self.ctx = (self.clk + 1).into();
            self.fmp = Felt::new(FMP_MIN);
            self.caller_hash = callee_hash;
        };

        // Update continuation stack
        // -----------------------------
        continuation_stack.push_finish_dyn(current_node_id);

        // if the callee is not in the program's MAST forest, try to find a MAST forest for it in
        // the host (corresponding to an external library loaded in the host); if none are found,
        // return an error.
        match current_forest.find_procedure_root(callee_hash) {
            Some(callee_id) => {
                continuation_stack.push_start_node(callee_id);
            },
            None => {
                let (root_id, new_forest) = self
                    .load_mast_forest(
                        callee_hash,
                        host,
                        ExecutionError::dynamic_node_not_found,
                        &err_ctx,
                    )
                    .await?;

                // Push current forest to the continuation stack so that we can return to it
                continuation_stack.push_enter_forest(current_forest.clone());

                // Push the root node of the external MAST forest onto the continuation stack.
                continuation_stack.push_start_node(root_id);

                // Set the new MAST forest as current
                *current_forest = new_forest;
            },
        }

        // Increment the clock, corresponding to the row inserted for the DYN or DYNCALL operation
        // added to the trace.
        self.increment_clk();

        Ok(())
    }

    /// Executes the finish phase of a Dyn node.
    #[inline(always)]
    fn finish_dyn_node(
        &mut self,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
    ) -> Result<(), ExecutionError> {
        self.check_extract_trace_state(
            NodeExecutionState::End(node_id),
            continuation_stack,
            current_forest,
        );

        let dyn_node = current_forest[node_id].unwrap_dyn();
        let err_ctx = err_ctx!(current_forest, dyn_node, host);
        // For dyncall, restore the context.
        if dyn_node.is_dyncall() {
            self.restore_context(&err_ctx)?;
        }

        if let Some(ref mut trace_state_builder) = self.trace_state_builder {
            let block_info = trace_state_builder.block_stack.pop();
            trace_state_builder.record_node_end(&block_info);

            if dyn_node.is_dyncall() {
                let exec_ctx = block_info.ctx_info.unwrap();
                trace_state_builder.record_execution_context(ExecutionContextSystemInfo {
                    parent_ctx: exec_ctx.parent_ctx,
                    parent_fn_hash: exec_ctx.parent_fn_hash,
                    parent_fmp: exec_ctx.parent_fmp,
                });
            }
        }

        // Corresponds to the row inserted for the END operation added to
        // the trace.
        self.increment_clk();
        self.execute_after_exit_decorators(node_id, current_forest, host)
    }

    /// Executes an External node.
    #[inline(always)]
    async fn execute_external_node(
        &mut self,
        node_id: MastNodeId,
        current_forest: &mut Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
    ) -> Result<(), ExecutionError> {
        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(node_id, current_forest, host)?;

        let external_node = current_forest[node_id].unwrap_external();
        let (root_id, new_mast_forest) = self.resolve_external_node(external_node, host).await?;

        if let Some(ref mut trace_state_builder) = self.trace_state_builder {
            trace_state_builder.external.record_resolution(root_id, new_mast_forest.clone());
        }

        // Push current forest to the continuation stack so that we can return to it
        continuation_stack.push_enter_forest(current_forest.clone());

        // Push the root node of the external MAST forest onto the continuation stack.
        continuation_stack.push_start_node(root_id);

        self.execute_after_exit_decorators(node_id, current_forest, host)?;

        // Update the current forest to the new MAST forest.
        *current_forest = new_mast_forest;

        Ok(())
    }

    // Note: when executing individual ops, we do not increment the clock by 1 at every iteration
    // for performance reasons (~25% performance drop). Hence, `self.clk` cannot be used directly to
    // determine the number of operations executed in a program.
    #[inline(always)]
    async fn execute_basic_block_node(
        &mut self,
        basic_block_node: &BasicBlockNode,
        node_id: MastNodeId,
        program: &MastForest,
        host: &mut impl AsyncHost,
        continuation_stack: &mut ContinuationStack,
        current_forest: &Arc<MastForest>,
    ) -> Result<(), ExecutionError> {
        self.check_extract_trace_state(
            NodeExecutionState::Start(node_id),
            continuation_stack,
            current_forest,
        );

        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(node_id, program, host)?;

        // In tracing mode, record the basic block on the block stack
        if let Some(ref mut trace_state_builder) = self.trace_state_builder {
            let block_addr = trace_state_builder.hasher.record_hash_basic_block(basic_block_node);
            let parent_addr =
                trace_state_builder.block_stack.push(block_addr, BlockType::Span, None);
            trace_state_builder.block_stack_replay.record_node_start(parent_addr);
        }

        // Corresponds to the row inserted for the SPAN operation added to the trace.
        self.increment_clk();

        let mut batch_offset_in_block = 0;
        let mut op_batches = basic_block_node.op_batches().iter();
        let mut decorator_ids = basic_block_node.decorator_iter();

        // execute first op batch
        if let Some(first_op_batch) = op_batches.next() {
            self.execute_op_batch(
                basic_block_node,
                node_id,
                first_op_batch,
                0,
                &mut decorator_ids,
                batch_offset_in_block,
                program,
                host,
                continuation_stack,
                current_forest,
            )
            .await?;
            batch_offset_in_block += first_op_batch.ops().len();
        }

        // execute the rest of the op batches
        for (batch_index_minus_1, op_batch) in op_batches.enumerate() {
            // RESPAN
            {
                self.check_extract_trace_state(
                    NodeExecutionState::Respan {
                        node_id,
                        batch_index: batch_index_minus_1 + 1,
                    },
                    continuation_stack,
                    current_forest,
                );

                if let Some(ref mut trace_state_builder) = self.trace_state_builder {
                    trace_state_builder.block_stack.peek_mut().addr += HASH_CYCLE_LEN;
                }

                // Corresponds to the RESPAN operation added to the trace.
                self.increment_clk();
            }

            self.execute_op_batch(
                basic_block_node,
                node_id,
                op_batch,
                batch_index_minus_1 + 1,
                &mut decorator_ids,
                batch_offset_in_block,
                program,
                host,
                continuation_stack,
                current_forest,
            )
            .await?;
            batch_offset_in_block += op_batch.ops().len();
        }

        self.check_extract_trace_state(
            NodeExecutionState::End(node_id),
            continuation_stack,
            current_forest,
        );

        if let Some(ref mut trace_state_builder) = self.trace_state_builder {
            let block_info = trace_state_builder.block_stack.pop();
            trace_state_builder.record_node_end(&block_info);
        }

        // Corresponds to the row inserted for the END operation added to the trace.
        self.increment_clk();

        // execute any decorators which have not been executed during span ops execution; this can
        // happen for decorators appearing after all operations in a block. these decorators are
        // executed after SPAN block is closed to make sure the VM clock cycle advances beyond the
        // last clock cycle of the SPAN block ops.
        for &decorator_id in decorator_ids {
            let decorator = program
                .get_decorator_by_id(decorator_id)
                .ok_or(ExecutionError::DecoratorNotFoundInForest { decorator_id })?;
            self.execute_decorator(decorator, host)?;
        }

        self.execute_after_exit_decorators(node_id, program, host)
    }

    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    async fn execute_op_batch(
        &mut self,
        basic_block: &BasicBlockNode,
        node_id: MastNodeId,
        batch: &OpBatch,
        batch_index: usize,
        decorators: &mut DecoratorIterator<'_>,
        batch_offset_in_block: usize,
        program: &MastForest,
        host: &mut impl AsyncHost,
        continuation_stack: &mut ContinuationStack,
        current_forest: &Arc<MastForest>,
    ) -> Result<(), ExecutionError> {
        let op_counts = batch.op_counts();
        let mut op_idx_in_group = 0;
        let mut group_idx = 0;
        let mut next_group_idx = 1;

        // round up the number of groups to be processed to the next power of two; we do this
        // because the processor requires the number of groups to be either 1, 2, 4, or 8; if
        // the actual number of groups is smaller, we'll pad the batch with NOOPs at the end
        let num_batch_groups = batch.num_groups().next_power_of_two();

        let mut num_noops_inserted_in_batch = 0;

        // execute operations in the batch one by one
        for (op_idx_in_batch_without_noops, op) in batch.ops().iter().enumerate() {
            while let Some(&decorator_id) =
                decorators.next_filtered(batch_offset_in_block + op_idx_in_batch_without_noops)
            {
                let decorator = program
                    .get_decorator_by_id(decorator_id)
                    .ok_or(ExecutionError::DecoratorNotFoundInForest { decorator_id })?;
                self.execute_decorator(decorator, host)?;
            }

            // decode and execute the operation
            let op_idx_in_block = batch_offset_in_block + op_idx_in_batch_without_noops;
            let err_ctx = err_ctx!(program, basic_block, host, op_idx_in_block);

            // if in trace mode, check if we need to record a trace state before executing the
            // operation
            self.check_extract_trace_state(
                NodeExecutionState::BasicBlock {
                    node_id,
                    batch_index,
                    op_idx_in_batch: op_idx_in_batch_without_noops + num_noops_inserted_in_batch,
                },
                continuation_stack,
                current_forest,
            );

            // Execute the operation.
            //
            // Note: we handle the `Emit` operation separately, because it is an async operation,
            // whereas all the other operations are synchronous (resulting in a significant
            // performance improvement).
            match op {
                Operation::Emit(event_id) => {
                    if self.bounds_check_counter == 0 {
                        let err_str = if self.stack_top_idx - MIN_STACK_DEPTH == 0 {
                            "stack underflow"
                        } else {
                            "stack overflow"
                        };
                        return Err(ExecutionError::FailedToExecuteProgram(err_str));
                    }

                    self.op_emit(*event_id, host, &err_ctx).await?
                },
                _ => {
                    // if the operation is not an Emit, we execute it normally
                    self.execute_op(op, op_idx_in_block, program, host, &err_ctx)?;
                },
            }

            // Increment clock after executing the operation
            self.increment_clk();

            // if the operation carries an immediate value, the value is stored at the next group
            // pointer; so, we advance the pointer to the following group
            let has_imm = op.imm_value().is_some();
            if has_imm {
                next_group_idx += 1;
            }

            // determine if we've executed all operations in a group
            if op_idx_in_group == op_counts[group_idx] - 1 {
                // if we are at the end of the group, first check if the operation carries an
                // immediate value
                if has_imm {
                    // an operation with an immediate value cannot be the last operation in a group
                    // so, we need execute a NOOP after it.
                    debug_assert!(op_idx_in_group < OP_GROUP_SIZE - 1, "invalid op index");

                    num_noops_inserted_in_batch += 1;

                    // If in tracing mode, check if we need to record a trace state.
                    self.check_extract_trace_state(
                        NodeExecutionState::BasicBlock {
                            node_id,
                            batch_index,
                            op_idx_in_batch: op_idx_in_batch_without_noops
                                + num_noops_inserted_in_batch,
                        },
                        continuation_stack,
                        current_forest,
                    );

                    // Increment the clk to account for the NOOP inserted at runtime
                    self.increment_clk();
                }

                // then, move to the next group and reset operation index
                group_idx = next_group_idx;
                next_group_idx += 1;
                op_idx_in_group = 0;
            } else {
                op_idx_in_group += 1;
            }
        }

        // make sure we execute the required number of operation groups; this would happen when the
        // actual number of operation groups was not a power of two. In this processor, this
        // corresponds to incrementing the clock by the number of empty op groups (i.e. 1 NOOP
        // executed per missing op group).
        let num_noops_to_execute = num_batch_groups - group_idx;
        if self.trace_state_builder.is_some() {
            // In tracing mode, we need to call `increment_clk()` once for each NOOP, in case
            // we need to extract a batch after one of the NOOPs.
            let num_ops_in_batch = batch.ops().len() + num_noops_inserted_in_batch;

            for noop_idx in 0..num_noops_to_execute {
                self.check_extract_trace_state(
                    NodeExecutionState::BasicBlock {
                        node_id,
                        batch_index,
                        op_idx_in_batch: num_ops_in_batch + noop_idx,
                    },
                    continuation_stack,
                    current_forest,
                );

                self.increment_clk();
            }
        } else {
            // Note: it is safe to increment `clk` here directly instead of through
            // `increment_clk()`, since we checked that we are not in tracing mode.
            self.clk += num_noops_to_execute as u32;
        }

        Ok(())
    }

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

    /// Executes the given operation.
    ///
    /// # Panics
    /// - if the operation is a control flow operation, as these are never executed,
    /// - if the operation is an `Emit` operation, as this requires async execution.
    #[inline(always)]
    fn execute_op(
        &mut self,
        operation: &Operation,
        op_idx: usize,
        program: &MastForest,
        host: &mut impl AsyncHost,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        if self.bounds_check_counter == 0 {
            let err_str = if self.stack_top_idx - MIN_STACK_DEPTH == 0 {
                "stack underflow"
            } else {
                "stack overflow"
            };
            return Err(ExecutionError::FailedToExecuteProgram(err_str));
        }

        match operation {
            // ----- system operations ------------------------------------------------------------
            Operation::Noop => {
                // do nothing
            },
            Operation::Assert(err_code) => self.op_assert(*err_code, host, program, err_ctx)?,
            Operation::FmpAdd => self.op_fmpadd(),
            Operation::FmpUpdate => self.op_fmpupdate()?,
            Operation::SDepth => self.op_sdepth(),
            Operation::Caller => self.op_caller()?,
            Operation::Clk => self.op_clk()?,
            Operation::Emit(_event_id) => {
                panic!("emit instruction requires async, so is not supported by execute_op()")
            },

            // ----- flow control operations ------------------------------------------------------
            // control flow operations are never executed directly
            Operation::Join => unreachable!("control flow operation"),
            Operation::Split => unreachable!("control flow operation"),
            Operation::Loop => unreachable!("control flow operation"),
            Operation::Call => unreachable!("control flow operation"),
            Operation::SysCall => unreachable!("control flow operation"),
            Operation::Dyn => unreachable!("control flow operation"),
            Operation::Dyncall => unreachable!("control flow operation"),
            Operation::Span => unreachable!("control flow operation"),
            Operation::Repeat => unreachable!("control flow operation"),
            Operation::Respan => unreachable!("control flow operation"),
            Operation::End => unreachable!("control flow operation"),
            Operation::Halt => unreachable!("control flow operation"),

            // ----- field operations -------------------------------------------------------------
            Operation::Add => self.op_add()?,
            Operation::Neg => self.op_neg()?,
            Operation::Mul => self.op_mul()?,
            Operation::Inv => self.op_inv(err_ctx)?,
            Operation::Incr => self.op_incr()?,
            Operation::And => self.op_and(err_ctx)?,
            Operation::Or => self.op_or(err_ctx)?,
            Operation::Not => self.op_not(err_ctx)?,
            Operation::Eq => self.op_eq()?,
            Operation::Eqz => self.op_eqz()?,
            Operation::Expacc => self.op_expacc(),
            Operation::Ext2Mul => self.op_ext2mul(),

            // ----- u32 operations ---------------------------------------------------------------
            Operation::U32split => self.op_u32split(),
            Operation::U32add => self.op_u32add(err_ctx)?,
            Operation::U32add3 => self.op_u32add3(err_ctx)?,
            Operation::U32sub => self.op_u32sub(op_idx, err_ctx)?,
            Operation::U32mul => self.op_u32mul(err_ctx)?,
            Operation::U32madd => self.op_u32madd(err_ctx)?,
            Operation::U32div => self.op_u32div(err_ctx)?,
            Operation::U32and => self.op_u32and(err_ctx)?,
            Operation::U32xor => self.op_u32xor(err_ctx)?,
            Operation::U32assert2(err_code) => self.op_u32assert2(*err_code, err_ctx)?,

            // ----- stack manipulation -----------------------------------------------------------
            Operation::Pad => self.op_pad(),
            Operation::Drop => self.decrement_stack_size(),
            Operation::Dup0 => self.dup_nth(0),
            Operation::Dup1 => self.dup_nth(1),
            Operation::Dup2 => self.dup_nth(2),
            Operation::Dup3 => self.dup_nth(3),
            Operation::Dup4 => self.dup_nth(4),
            Operation::Dup5 => self.dup_nth(5),
            Operation::Dup6 => self.dup_nth(6),
            Operation::Dup7 => self.dup_nth(7),
            Operation::Dup9 => self.dup_nth(9),
            Operation::Dup11 => self.dup_nth(11),
            Operation::Dup13 => self.dup_nth(13),
            Operation::Dup15 => self.dup_nth(15),
            Operation::Swap => self.op_swap(),
            Operation::SwapW => self.swapw_nth(1),
            Operation::SwapW2 => self.swapw_nth(2),
            Operation::SwapW3 => self.swapw_nth(3),
            Operation::SwapDW => self.op_swap_double_word(),
            Operation::MovUp2 => self.rotate_left(3),
            Operation::MovUp3 => self.rotate_left(4),
            Operation::MovUp4 => self.rotate_left(5),
            Operation::MovUp5 => self.rotate_left(6),
            Operation::MovUp6 => self.rotate_left(7),
            Operation::MovUp7 => self.rotate_left(8),
            Operation::MovUp8 => self.rotate_left(9),
            Operation::MovDn2 => self.rotate_right(3),
            Operation::MovDn3 => self.rotate_right(4),
            Operation::MovDn4 => self.rotate_right(5),
            Operation::MovDn5 => self.rotate_right(6),
            Operation::MovDn6 => self.rotate_right(7),
            Operation::MovDn7 => self.rotate_right(8),
            Operation::MovDn8 => self.rotate_right(9),
            Operation::CSwap => self.op_cswap(err_ctx)?,
            Operation::CSwapW => self.op_cswapw(err_ctx)?,

            // ----- input / output ---------------------------------------------------------------
            Operation::Push(element) => self.op_push(*element),
            Operation::AdvPop => self.op_advpop(err_ctx)?,
            Operation::AdvPopW => self.op_advpopw(err_ctx)?,
            Operation::MLoadW => self.op_mloadw(err_ctx)?,
            Operation::MStoreW => self.op_mstorew(err_ctx)?,
            Operation::MLoad => self.op_mload(err_ctx)?,
            Operation::MStore => self.op_mstore(err_ctx)?,
            Operation::MStream => self.op_mstream(err_ctx)?,
            Operation::Pipe => self.op_pipe(err_ctx)?,

            // ----- cryptographic operations -----------------------------------------------------
            Operation::HPerm => self.op_hperm(),
            Operation::MpVerify(err_code) => self.op_mpverify(*err_code, program, err_ctx)?,
            Operation::MrUpdate => self.op_mrupdate(err_ctx)?,
            Operation::FriE2F4 => self.op_fri_ext2fold4()?,
            Operation::HornerBase => self.op_horner_eval_base(err_ctx)?,
            Operation::HornerExt => self.op_horner_eval_ext(err_ctx)?,
            Operation::EvalCircuit => self.op_eval_circuit(err_ctx)?,
        }

        Ok(())
    }

    // HELPERS
    // ----------------------------------------------------------------------------------------------

    /// Increments the clock by 1.
    #[inline(always)]
    fn increment_clk(&mut self) {
        self.clk += 1_u32;

        if let Some(ref mut trace_state_builder) = self.trace_state_builder {
            trace_state_builder.overflow_table.advance_clock();
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

    /// Analogous to [`Process::resolve_external_node`](crate::Process::resolve_external_node), but
    /// for asynchronous execution.
    async fn resolve_external_node(
        &mut self,
        external_node: &ExternalNode,
        host: &mut impl AsyncHost,
    ) -> Result<(MastNodeId, Arc<MastForest>), ExecutionError> {
        let (root_id, mast_forest) = self
            .load_mast_forest(
                external_node.digest(),
                host,
                ExecutionError::no_mast_forest_with_procedure,
                &(),
            )
            .await?;

        // if the node that we got by looking up an external reference is also an External
        // node, we are about to enter into an infinite loop - so, return an error
        if mast_forest[root_id].is_external() {
            return Err(ExecutionError::CircularExternalNode(external_node.digest()));
        }

        Ok((root_id, mast_forest))
    }

    /// Increments the stack top pointer by 1.
    ///
    /// The bottom of the stack is never affected by this operation.
    #[inline(always)]
    fn increment_stack_size(&mut self) {
        {
            // Get around the borrow checker by using a temporary variable.
            let overflow_value = if self.trace_state_builder.is_some() {
                Some(self.stack_get(15))
            } else {
                None
            };

            if let Some(ref mut trace_state_builder) = self.trace_state_builder {
                trace_state_builder.overflow_table.push(overflow_value.unwrap());
            }
        }

        self.stack_top_idx += 1;
        self.update_bounds_check_counter();
    }

    /// Decrements the stack top pointer by 1.
    ///
    /// The bottom of the stack is only decremented in cases where the stack depth would become less
    /// than 16.
    #[inline(always)]
    fn decrement_stack_size(&mut self) {
        if let Some(ref mut trace_state_builder) = self.trace_state_builder {
            // Record the popped value for replay, if present
            if let Some(popped_value) = trace_state_builder.overflow_table.pop() {
                let new_overflow_addr =
                    trace_state_builder.overflow_table.last_update_clk_in_current_ctx();
                trace_state_builder
                    .overflow_replay
                    .record_pop_overflow(popped_value, new_overflow_addr);
            }
        }

        self.stack_top_idx -= 1;
        self.stack_bot_idx = min(self.stack_bot_idx, self.stack_top_idx - MIN_STACK_DEPTH);
        self.update_bounds_check_counter();
    }

    /// Returns the size of the stack.
    #[inline(always)]
    fn stack_size(&self) -> usize {
        self.stack_top_idx - self.stack_bot_idx
    }

    /// Updates the bounds check counter.
    ///
    /// The bounds check counter is decremented by 1. If it reaches 0, it is reset to the minimum of
    /// the stack depth from the low end and the high end of the stack buffer.
    ///
    /// The purpose of the bounds check counter is to ensure that we never access the stack buffer
    /// at an out-of-bounds index.
    #[inline(always)]
    fn update_bounds_check_counter(&mut self) {
        self.bounds_check_counter -= 1;

        if self.bounds_check_counter == 0 {
            // We will need to check the bounds either because we reach the low end or the high end
            // of the stack buffer. There are two worst cases that we are concerned about:
            // - we only execute instructions that decrease stack depth
            // - we only execute instructions that increase stack depth
            //
            // In the first case, we will hit the low end of the stack buffer; in the second case,
            // we will hit the high end of the stack buffer. We set the number of instructions that
            // is safe to execute to be the minimum of these two worst cases.

            self.bounds_check_counter =
                min(self.stack_top_idx - MIN_STACK_DEPTH, STACK_BUFFER_SIZE - self.stack_top_idx);
        }
    }

    /// Saves the current execution context and truncates the stack to 16 elements in preparation to
    /// start a new execution context.
    fn save_context_and_truncate_stack(&mut self) {
        let overflow_stack = if self.stack_size() > MIN_STACK_DEPTH {
            // save the overflow stack, and zero out the buffer.
            //
            // Note: we need to zero the overflow buffer, since the new context expects ZERO's to be
            // pulled in if they decrement the stack size (e.g. by executing a `drop`).
            let overflow_stack =
                self.stack[self.stack_bot_idx..self.stack_top_idx - MIN_STACK_DEPTH].to_vec();
            self.stack[self.stack_bot_idx..self.stack_top_idx - MIN_STACK_DEPTH].fill(ZERO);

            overflow_stack
        } else {
            Vec::new()
        };

        self.stack_bot_idx = self.stack_top_idx - MIN_STACK_DEPTH;

        self.call_stack.push(ExecutionContextInfo {
            overflow_stack,
            ctx: self.ctx,
            fn_hash: self.caller_hash,
            fmp: self.fmp,
        });

        if let Some(ref mut trace_state_builder) = self.trace_state_builder {
            trace_state_builder.overflow_table.start_context();
        }
    }

    /// Restores the execution context to the state it was in before the last `call`, `syscall` or
    /// `dyncall`.
    ///
    /// This includes restoring the overflow stack and the system parameters.
    ///
    /// # Errors
    /// - Returns an error if the overflow stack is larger than the space available in the stack
    ///   buffer.
    fn restore_context(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        // when a call/dyncall/syscall node ends, stack depth must be exactly 16.
        if self.stack_size() > MIN_STACK_DEPTH {
            return Err(ExecutionError::invalid_stack_depth_on_return(self.stack_size(), err_ctx));
        }

        let ctx_info = self
            .call_stack
            .pop()
            .expect("execution context stack should never be empty when restoring context");

        // restore the overflow stack
        {
            let overflow_len = ctx_info.overflow_stack.len();
            if overflow_len > self.stack_bot_idx {
                return Err(ExecutionError::FailedToExecuteProgram(
                    "stack underflow when restoring context",
                ));
            }

            self.stack[range(self.stack_bot_idx - overflow_len, overflow_len)]
                .copy_from_slice(&ctx_info.overflow_stack);
            self.stack_bot_idx -= overflow_len;
        }

        // restore system parameters
        self.ctx = ctx_info.ctx;
        self.fmp = ctx_info.fmp;
        self.in_syscall = false;
        self.caller_hash = ctx_info.fn_hash;

        if let Some(ref mut trace_state_builder) = self.trace_state_builder {
            trace_state_builder.overflow_table.restore_context();
            trace_state_builder.overflow_replay.record_restore_context_overflow_addr(
                MIN_STACK_DEPTH + trace_state_builder.overflow_table.num_elements_in_current_ctx(),
                trace_state_builder.overflow_table.last_update_clk_in_current_ctx(),
            );
        }

        Ok(())
    }

    /// Checks if the trace state should be extracted and stored, and does so if necessary.
    ///
    /// This method must be called at the start of each clock cycle *before* applying any mutation
    /// to the processor state.
    fn check_extract_trace_state(
        &mut self,
        execution_state: NodeExecutionState,
        continuation_stack: &mut ContinuationStack,
        current_forest: &Arc<MastForest>,
    ) {
        if self.trace_state_builder.is_some()
            && self.clk.as_usize().is_multiple_of(NUM_ROWS_PER_CORE_FRAGMENT)
        {
            let stack_top: [Felt; MIN_STACK_DEPTH] = self.stack_top().try_into().unwrap();
            let decoder_state = {
                let trace_state_builder = self.trace_state_builder.as_ref().unwrap();
                if trace_state_builder.block_stack.is_empty() {
                    DecoderState { current_addr: ZERO, parent_addr: ZERO }
                } else {
                    let block_info = trace_state_builder.block_stack.peek();

                    DecoderState {
                        current_addr: block_info.addr,
                        parent_addr: block_info.parent_addr,
                    }
                }
            };

            self.trace_state_builder.as_mut().unwrap().start_new_trace_state(
                SystemState {
                    clk: self.clk,
                    ctx: self.ctx,
                    fmp: self.fmp,
                    in_syscall: self.in_syscall,
                    fn_hash: self.caller_hash,
                },
                decoder_state,
                stack_top,
                continuation_stack.clone(),
                execution_state,
                current_forest.clone(),
            );
        }
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

        let (stack_outputs, _advice) = rt.block_on(self.execute(program, host))?;

        Ok(stack_outputs)
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn execute_for_trace_sync(
        self,
        program: &Program,
        host: &mut impl AsyncHost,
    ) -> Result<(StackOutputs, AdviceProvider, Vec<CoreTraceState>), ExecutionError> {
        // Create a new Tokio runtime and block on the async execution
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();

        rt.block_on(self.execute_for_trace(program, host))
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

        rt.block_on(self.execute_impl(program, host))
    }
}

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
