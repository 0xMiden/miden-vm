use alloc::{sync::Arc, vec::Vec};
use core::{cmp::min, ops::ControlFlow};

use memory::Memory;
use miden_air::RowIndex;
use miden_core::{
    Decorator, DecoratorIterator, EMPTY_WORD, Felt, Kernel, ONE, Operation, Program, StackOutputs,
    WORD_SIZE, Word, ZERO,
    mast::{
        BasicBlockNode, CallNode, JoinNode, LoopNode, MastForest, MastNode, MastNodeId,
        OP_GROUP_SIZE, OpBatch, SplitNode,
    },
    stack::MIN_STACK_DEPTH,
    utils::range,
};
use miden_debug_types::{DefaultSourceManager, SourceManager};

use crate::{
    chiplets::Ace, continuation_stack::{Continuation, ContinuationStack}, err_ctx, AdviceInputs, AdviceProvider, AsyncHost, ContextId, ErrorContext, ExecutionError, ProcessState, SyncHost, FMP_MIN, SYSCALL_FMP_MIN
};

mod memory;

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
const STACK_BUFFER_SIZE: usize = 6650;

/// The initial position of the top of the stack in the stack buffer.
///
/// We place this value close to 0 because if a program hits the limit, it's much more likely to hit
/// the upper bound than the lower bound, since hitting the lower bound only occurs when you drop
/// 0's that were generated automatically to keep the stack depth at 16. In practice, if this
/// occurs, it is most likely a bug.
const INITIAL_STACK_TOP_IDX: usize = 50;

/// WORD_SIZE, but as a `Felt`.
const WORD_SIZE_FELT: Felt = Felt::new(4);

/// The size of a double-word.
const DOUBLE_WORD_SIZE: Felt = Felt::new(8);

pub enum ProcessingState {
    /// When returned from `execute_sans_io()`, the caller must call `execute_sans_io()` again, this
    /// time providing a `MastForest` that contains `node_digest` as a procedure.
    ///
    /// For this experimental branch, since we only implement the `GetMastForest` continuation for
    /// the external node, this variant is assumed to come from an `ExternalNode`. In the real
    /// implementation, it could also come from a `DynNode`.
    GetMastForest {
        node_digest: Word,
    },
    OnEvent {
        event_id: u32,
    },
    /// Execution has successfully completed.
    Done(StackOutputs),
    /// An error has occurred, which terminates the execution early.
    Error(ExecutionError),
}

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
/// - When executing a basic block, the clock cycle is not incremented for every individual
///   operation for performance reasons.
///     - Rather, we use `clk + operation_index` to determine the clock cycle when needed.
///     - However this performance improvement is slightly offset by the need to parse operation
///       batches exactly the same as `Process`. We will be able to recover the performance loss by
///       redesigning the `BasicBlockNode`.
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
    ///
    /// However, when we are in a basic block, this corresponds to the clock cycle at which the
    /// basic block was entered. Hence, given an operation, we need to add its index in the
    /// block to this value to get the clock cycle.
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

    /// The source manager (providing information about the location of each instruction).
    source_manager: Arc<dyn SourceManager>,
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
        let source_manager = Arc::new(DefaultSourceManager::default());
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
            source_manager,
        }
    }

    /// Set the internal source manager to an externally initialized one.
    pub fn with_source_manager(mut self, source_manager: Arc<dyn SourceManager>) -> Self {
        self.source_manager = source_manager;
        self
    }

    // ACCESSORS
    // -------------------------------------------------------------------------------------------

    /// Returns the stack, such that the top of the stack is at the last index of the returned
    /// slice.
    pub fn stack(&self) -> &[Felt] {
        &self.stack[self.stack_bot_idx..self.stack_top_idx]
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

    /// Executes the given program and returns the stack outputs.
    pub fn execute_sync_host(
        mut self,
        program: &Program,
        host: &mut impl SyncHost,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut continuation_stack = ContinuationStack::new(program);

        let mut processing_state =
            self.execute_sans_io(&mut continuation_stack, program.mast_forest(), program.kernel());

        loop {
            match processing_state {
                ProcessingState::GetMastForest { node_digest } => {
                    let new_forest = host.get_mast_forest(&node_digest).unwrap();
                    let root_id = new_forest.find_procedure_root(node_digest).unwrap();
                    processing_state = self.execute_sans_io_finish_external(
                        &mut continuation_stack,
                        &new_forest,
                        root_id,
                        program.kernel(),
                    )
                },
                ProcessingState::OnEvent { event_id: _ } => unimplemented!(),
                ProcessingState::Done(stack_outputs) => break Ok(stack_outputs),
                ProcessingState::Error(execution_error) => break Err(execution_error),
            }
        }
    }


    /// Asynchronous variant of `execute_sync_host()`.
    pub async fn execute_async_host(
        mut self,
        program: &Program,
        host: &mut impl AsyncHost,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut continuation_stack = ContinuationStack::new(program);

        let mut processing_state =
            self.execute_sans_io(&mut continuation_stack, program.mast_forest(), program.kernel());

        loop {
            match processing_state {
                ProcessingState::GetMastForest { node_digest } => {
                    let new_forest = host.get_mast_forest(&node_digest).await.unwrap();
                    let root_id = new_forest.find_procedure_root(node_digest).unwrap();
                    processing_state = self.execute_sans_io_finish_external(
                        &mut continuation_stack,
                        &new_forest,
                        root_id,
                        program.kernel(),
                    )
                },
                ProcessingState::OnEvent { event_id: _ } => unimplemented!(),
                ProcessingState::Done(stack_outputs) => break Ok(stack_outputs),
                ProcessingState::Error(execution_error) => break Err(execution_error),
            }
        }
    }

    /// Note: ContinuationStack and MastForest currently maintained outside the processor - mainly
    /// to reduce the complexity of this exploration PR.
    ///
    /// TODO(plafer): change `Program` to just `Kernel`
    pub fn execute_sans_io(
        &mut self,
        continuation_stack: &mut ContinuationStack,
        current_forest: &Arc<MastForest>,
        kernel: &Kernel,
    ) -> ProcessingState {
        match self.execute_sans_io_impl(continuation_stack, current_forest, kernel) {
            ControlFlow::Continue(_) => panic!("should never return with a Continue"),
            ControlFlow::Break(processing_state) => processing_state,
        }
    }

    /// To be called after processing a `ProcessingState::GetMastForest`
    pub fn execute_sans_io_finish_external(
        &mut self,
        continuation_stack: &mut ContinuationStack,
        current_forest: &Arc<MastForest>,
        entrypoint: MastNodeId,
        kernel: &Kernel,
    ) -> ProcessingState {
        continuation_stack.push_finish_external(entrypoint);

        match self.execute_sans_io_impl(continuation_stack, current_forest, kernel) {
            ControlFlow::Continue(_) => panic!("should never return with a Continue"),
            ControlFlow::Break(processing_state) => processing_state,
        }
    }

    fn execute_sans_io_impl(
        &mut self,
        continuation_stack: &mut ContinuationStack,
        initial_forest: &Arc<MastForest>,
        kernel: &Kernel,
    ) -> ControlFlow<ProcessingState> {
        let mut current_forest = initial_forest.clone();

        while let Some(processing_step) = continuation_stack.pop_continuation() {
            match processing_step {
                Continuation::StartNode(node_id) => {
                    let node = current_forest.get_node_by_id(node_id).unwrap();
                    match node {
                        MastNode::Block(basic_block_node) => self.execute_basic_block_node(
                            basic_block_node,
                            node_id,
                            current_forest.as_ref(),
                        )?,
                        MastNode::Join(join_node) => self.start_join_node(
                            join_node,
                            node_id,
                            &current_forest,
                            continuation_stack,
                        )?,
                        MastNode::Split(split_node) => self.start_split_node(
                            split_node,
                            node_id,
                            &current_forest,
                            continuation_stack,
                        )?,
                        MastNode::Loop(loop_node) => self.start_loop_node(
                            loop_node,
                            node_id,
                            &current_forest,
                            continuation_stack,
                        )?,
                        MastNode::Call(call_node) => self.start_call_node(
                            call_node,
                            node_id,
                            kernel,
                            &current_forest,
                            continuation_stack,
                        )?,
                        MastNode::Dyn(_dyn_node) => {
                            self.start_dyn_node(node_id, &current_forest, continuation_stack)?
                        },
                        MastNode::External(_external_node) => {
                            self.start_external_node(node_id, &current_forest, continuation_stack)?
                        },
                    }
                },
                Continuation::FinishJoin(node_id) => {
                    self.finish_join_node(node_id, &current_forest)?
                },
                Continuation::FinishSplit(node_id) => {
                    self.finish_split_node(node_id, &current_forest)?
                },
                Continuation::FinishLoop(node_id) => {
                    self.finish_loop_node(node_id, &current_forest, continuation_stack)?
                },
                Continuation::FinishCall(node_id) => {
                    self.finish_call_node(node_id, &current_forest)?
                },
                Continuation::FinishDyn(node_id) => {
                    self.finish_dyn_node(node_id, &current_forest)?
                },
                Continuation::FinishExternal(node_id) => {
                    self.finish_external_node(node_id, &current_forest, continuation_stack)?
                },
                Continuation::EnterForest(previous_forest) => {
                    // Restore the previous forest
                    current_forest = previous_forest;
                },
            }
        }

        let stack_outputs_result = StackOutputs::new(
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
        });

        match stack_outputs_result {
            Ok(stack_outputs) => ControlFlow::Break(ProcessingState::Done(stack_outputs)),
            Err(err) => ControlFlow::Break(ProcessingState::Error(err)),
        }
    }

    // NODE EXECUTORS
    // --------------------------------------------------------------------------------------------

    /// Executes the start phase of a Join node.
    #[inline(always)]
    fn start_join_node(
        &mut self,
        join_node: &JoinNode,
        node_id: MastNodeId,
        current_forest: &MastForest,
        continuation_stack: &mut ContinuationStack,
    ) -> ControlFlow<ProcessingState> {
        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(node_id, current_forest)?;

        // Corresponds to the row inserted for the JOIN operation added
        // to the trace.
        self.clk += 1_u32;

        continuation_stack.push_finish_join(node_id);
        continuation_stack.push_start_node(join_node.second());
        continuation_stack.push_start_node(join_node.first());
        ControlFlow::Continue(())
    }

    /// Executes the finish phase of a Join node.
    #[inline(always)]
    fn finish_join_node(
        &mut self,
        node_id: MastNodeId,
        current_forest: &MastForest,
    ) -> ControlFlow<ProcessingState> {
        // Corresponds to the row inserted for the END operation added
        // to the trace.
        self.clk += 1_u32;

        self.execute_after_exit_decorators(node_id, current_forest)
    }

    /// Executes the start phase of a Split node.
    #[inline(always)]
    fn start_split_node(
        &mut self,
        split_node: &SplitNode,
        node_id: MastNodeId,
        current_forest: &MastForest,
        continuation_stack: &mut ContinuationStack,
    ) -> ControlFlow<ProcessingState> {
        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(node_id, current_forest)?;

        // Corresponds to the row inserted for the SPLIT operation added
        // to the trace.
        self.clk += 1_u32;

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
            let err_ctx = err_ctx!(current_forest, split_node, self.source_manager.clone());
            return ControlFlow::Break(ProcessingState::Error(
                ExecutionError::not_binary_value_if(condition, &err_ctx),
            ));
        };

        ControlFlow::Continue(())
    }

    /// Executes the finish phase of a Split node.
    #[inline(always)]
    fn finish_split_node(
        &mut self,
        node_id: MastNodeId,
        current_forest: &MastForest,
    ) -> ControlFlow<ProcessingState> {
        // Corresponds to the row inserted for the END operation added
        // to the trace.
        self.clk += 1_u32;

        self.execute_after_exit_decorators(node_id, current_forest)
    }

    /// Executes the start phase of a Loop node.
    #[inline(always)]
    fn start_loop_node(
        &mut self,
        loop_node: &LoopNode,
        current_node_id: MastNodeId,
        current_forest: &MastForest,
        continuation_stack: &mut ContinuationStack,
    ) -> ControlFlow<ProcessingState> {
        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(current_node_id, current_forest)?;

        // Corresponds to the row inserted for the LOOP operation added
        // to the trace.
        self.clk += 1_u32;

        let condition = self.stack_get(0);

        // drop the condition from the stack
        self.decrement_stack_size();

        // execute the loop body as long as the condition is true
        if condition == ONE {
            // Push the loop to check condition again after body
            // executes
            continuation_stack.push_finish_loop(current_node_id);
            continuation_stack.push_start_node(loop_node.body());
        } else if condition == ZERO {
            // Exit the loop - add END row immediately since no body to
            // execute
            self.clk += 1_u32;
        } else {
            let err_ctx = err_ctx!(current_forest, loop_node, self.source_manager.clone());
            return ControlFlow::Break(ProcessingState::Error(
                ExecutionError::not_binary_value_loop(condition, &err_ctx),
            ));
        }
        ControlFlow::Continue(())
    }

    /// Executes the finish phase of a Loop node.
    #[inline(always)]
    fn finish_loop_node(
        &mut self,
        current_node_id: MastNodeId,
        current_forest: &MastForest,
        continuation_stack: &mut ContinuationStack,
    ) -> ControlFlow<ProcessingState> {
        // This happens after loop body execution
        // Check condition again to see if we should continue looping
        let condition = self.stack_get(0);
        self.decrement_stack_size();

        let loop_node = current_forest[current_node_id].unwrap_loop();
        if condition == ONE {
            // Add REPEAT row and continue looping
            self.clk += 1_u32;
            continuation_stack.push_finish_loop(current_node_id);
            continuation_stack.push_start_node(loop_node.body());
        } else if condition == ZERO {
            // Exit the loop - add END row
            self.clk += 1_u32;

            self.execute_after_exit_decorators(current_node_id, current_forest)?;
        } else {
            let err_ctx = err_ctx!(current_forest, loop_node, self.source_manager.clone());
            return ControlFlow::Break(ProcessingState::Error(
                ExecutionError::not_binary_value_loop(condition, &err_ctx),
            ));
        }
        ControlFlow::Continue(())
    }

    /// Executes the start phase of a Call node.
    #[inline(always)]
    fn start_call_node(
        &mut self,
        call_node: &CallNode,
        current_node_id: MastNodeId,
        kernel: &Kernel,
        current_forest: &MastForest,
        continuation_stack: &mut ContinuationStack,
    ) -> ControlFlow<ProcessingState> {
        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(current_node_id, current_forest)?;

        let err_ctx = err_ctx!(current_forest, call_node, self.source_manager.clone());

        // Corresponds to the row inserted for the CALL or SYSCALL
        // operation added to the trace.
        self.clk += 1_u32;

        // call or syscall are not allowed inside a syscall
        if self.in_syscall {
            let instruction = if call_node.is_syscall() { "syscall" } else { "call" };
            return ControlFlow::Break(ProcessingState::Error(ExecutionError::CallInSyscall(
                instruction,
            )));
        }

        let callee_hash = current_forest
            .get_node_by_id(call_node.callee())
            .ok_or(ExecutionError::MastNodeNotFoundInForest { node_id: call_node.callee() })
            .unwrap()
            .digest();

        self.save_context_and_truncate_stack();

        if call_node.is_syscall() {
            // check if the callee is in the kernel
            if !kernel.contains_proc(callee_hash) {
                return ControlFlow::Break(ProcessingState::Error(
                    ExecutionError::syscall_target_not_in_kernel(callee_hash, &err_ctx),
                ));
            }

            // set the system registers to the syscall context
            self.ctx = ContextId::root();
            self.fmp = SYSCALL_FMP_MIN.into();
            self.in_syscall = true;
        } else {
            // set the system registers to the callee context
            self.ctx = self.clk.into();
            self.fmp = Felt::new(FMP_MIN);
            self.caller_hash = callee_hash;
        }

        // push the callee onto the continuation stack
        continuation_stack.push_finish_call(current_node_id);
        continuation_stack.push_start_node(call_node.callee());
        ControlFlow::Continue(())
    }

    /// Executes the finish phase of a Call node.
    #[inline(always)]
    fn finish_call_node(
        &mut self,
        node_id: MastNodeId,
        current_forest: &MastForest,
    ) -> ControlFlow<ProcessingState> {
        let call_node = current_forest[node_id].unwrap_call();
        let err_ctx = err_ctx!(current_forest, call_node, self.source_manager.clone());
        // when returning from a function call or a syscall, restore the
        // context of the
        // system registers and the operand stack to what it was prior
        // to the call.
        self.restore_context(&err_ctx)?;

        // Corresponds to the row inserted for the END operation added
        // to the trace.
        self.clk += 1_u32;

        self.execute_after_exit_decorators(node_id, current_forest)
    }

    /// Executes the start phase of a Dyn node.
    #[inline(always)]
    fn start_dyn_node(
        &mut self,
        _current_node_id: MastNodeId,
        _current_forest: &Arc<MastForest>,
        _continuation_stack: &mut ContinuationStack,
    ) -> ControlFlow<ProcessingState> {
        // Would be a similar solution than `ExternalNode` in the case where we need to fetch a new
        // MastForest from the Host, so leaving unimplemented in this PR for simplicity.
        //
        // Q: Does `DynNode` really have to fetch a `MastForest` ever? i.e. doesn't the digest
        // always point to an `ExternalNode` present in the current forest in the case of calling
        // into an external library?
        unimplemented!()
    }

    /// Executes the finish phase of a Dyn node.
    #[inline(always)]
    fn finish_dyn_node(
        &mut self,
        node_id: MastNodeId,
        current_forest: &MastForest,
    ) -> ControlFlow<ProcessingState> {
        let dyn_node = current_forest[node_id].unwrap_dyn();
        let err_ctx = err_ctx!(current_forest, dyn_node, self.source_manager.clone());
        // For dyncall, restore the context.
        if dyn_node.is_dyncall() {
            self.restore_context(&err_ctx)?;
        }

        // Corresponds to the row inserted for the END operation added to
        // the trace.
        self.clk += 1_u32;

        self.execute_after_exit_decorators(node_id, current_forest)
    }

    fn start_external_node(
        &mut self,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
    ) -> ControlFlow<ProcessingState> {
        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(node_id, current_forest)?;

        let external_node = current_forest[node_id].unwrap_external();

        continuation_stack.push_enter_forest(current_forest.clone());

        // NOTE: It is the responsibility of the caller to call `execute_sans_io_finish_external()`
        // and providing the new `MastForest`. There's probably a cleaner way to do this.

        ControlFlow::Break(ProcessingState::GetMastForest { node_digest: external_node.digest() })
    }

    fn finish_external_node(
        &mut self,
        root_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
    ) -> ControlFlow<ProcessingState> {
        // Merge the advice map of this forest into the advice provider.
        // Note that the map may be merged multiple times if a different procedure from the same
        // forest is called.
        // For now, only compiled libraries contain non-empty advice maps, so for most cases,
        // this call will be cheap.
        self.advice.extend_map(current_forest.advice_map()).unwrap();

        // if the node that we got by looking up an external reference is also an External
        // node, we are about to enter into an infinite loop - so, return an error
        let external_node = &current_forest[root_id];
        if external_node.is_external() {
            return ControlFlow::Break(ProcessingState::Error(
                ExecutionError::CircularExternalNode(external_node.digest()),
            ));
        }
        // Push the root node of the external MAST forest onto the continuation stack.
        continuation_stack.push_start_node(root_id);

        // TODO(plafer): execute the external node's after_exit decorators after the callee is done
        // executing.

        ControlFlow::Continue(())
    }

    // Note: when executing individual ops, we do not increment the clock by 1 at every iteration
    // for performance reasons (~25% performance drop). Hence, `self.clk` cannot be used directly to
    // determine the number of operations executed in a program.
    #[inline(always)]
    fn execute_basic_block_node(
        &mut self,
        basic_block_node: &BasicBlockNode,
        node_id: MastNodeId,
        program: &MastForest,
    ) -> ControlFlow<ProcessingState> {
        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(node_id, program)?;

        // Corresponds to the row inserted for the SPAN operation added to the trace.
        self.clk += 1_u32;

        let mut batch_offset_in_block = 0;
        let mut op_batches = basic_block_node.op_batches().iter();
        let mut decorator_ids = basic_block_node.decorator_iter();

        // execute first op batch
        if let Some(first_op_batch) = op_batches.next() {
            self.execute_op_batch(
                basic_block_node,
                first_op_batch,
                &mut decorator_ids,
                batch_offset_in_block,
                program,
            )?;
            batch_offset_in_block += first_op_batch.ops().len();
        }

        // execute the rest of the op batches
        for op_batch in op_batches {
            // increment clock to account for `RESPAN`
            self.clk += 1_u32;

            self.execute_op_batch(
                basic_block_node,
                op_batch,
                &mut decorator_ids,
                batch_offset_in_block,
                program,
            )?;
            batch_offset_in_block += op_batch.ops().len();
        }

        // update clock with all the operations that executed
        self.clk += batch_offset_in_block as u32;

        // Corresponds to the row inserted for the END operation added to the trace.
        self.clk += 1_u32;

        // execute any decorators which have not been executed during span ops execution; this can
        // happen for decorators appearing after all operations in a block. these decorators are
        // executed after SPAN block is closed to make sure the VM clock cycle advances beyond the
        // last clock cycle of the SPAN block ops.
        for &decorator_id in decorator_ids {
            let decorator = program.get_decorator_by_id(decorator_id).unwrap();
            self.execute_decorator(decorator, 0)?;
        }

        self.execute_after_exit_decorators(node_id, program)
    }

    #[inline(always)]
    fn execute_op_batch(
        &mut self,
        basic_block: &BasicBlockNode,
        batch: &OpBatch,
        decorators: &mut DecoratorIterator<'_>,
        batch_offset_in_block: usize,
        program: &MastForest,
    ) -> ControlFlow<ProcessingState> {
        let op_counts = batch.op_counts();
        let mut op_idx_in_group = 0;
        let mut group_idx = 0;
        let mut next_group_idx = 1;

        // round up the number of groups to be processed to the next power of two; we do this
        // because the processor requires the number of groups to be either 1, 2, 4, or 8; if
        // the actual number of groups is smaller, we'll pad the batch with NOOPs at the end
        let num_batch_groups = batch.num_groups().next_power_of_two();

        // execute operations in the batch one by one
        for (op_idx_in_batch, op) in batch.ops().iter().enumerate() {
            while let Some(&decorator_id) =
                decorators.next_filtered(batch_offset_in_block + op_idx_in_batch)
            {
                let decorator = program
                    .get_decorator_by_id(decorator_id)
                    .ok_or(ExecutionError::DecoratorNotFoundInForest { decorator_id })
                    .unwrap();
                self.execute_decorator(decorator, op_idx_in_batch)?;
            }

            // decode and execute the operation
            let op_idx_in_block = batch_offset_in_block + op_idx_in_batch;
            let err_ctx =
                err_ctx!(program, basic_block, self.source_manager.clone(), op_idx_in_block);

            // Execute the operation.
            //
            // Note: we handle the `Emit` operation separately, because it is an async operation,
            // whereas all the other operations are synchronous (resulting in a significant
            // performance improvement).
            match op {
                Operation::Emit(_event_id) => {
                    // Not implemented in this exploration PR for simplicity
                    unimplemented!()
                },
                _ => {
                    // if the operation is not an Emit, we execute it normally
                    self.execute_op(op, op_idx_in_block, program, &err_ctx)?;
                },
            }

            // if the operation carries an immediate value, the value is stored at the next group
            // pointer; so, we advance the pointer to the following group
            let has_imm = op.imm_value().is_some();
            if has_imm {
                next_group_idx += 1;
            }

            // determine if we've executed all non-decorator operations in a group
            if op_idx_in_group == op_counts[group_idx] - 1 {
                // if we are at the end of the group, first check if the operation carries an
                // immediate value
                if has_imm {
                    // an operation with an immediate value cannot be the last operation in a group
                    // so, we need execute a NOOP after it. In this processor, we increment the
                    // clock to account for the NOOP.
                    debug_assert!(op_idx_in_group < OP_GROUP_SIZE - 1, "invalid op index");
                    self.clk += 1_u32;
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

        self.clk += (num_batch_groups - group_idx) as u32;

        ControlFlow::Continue(())
    }

    /// Executes the decorators that should be executed before entering a node.
    fn execute_before_enter_decorators(
        &mut self,
        node_id: MastNodeId,
        current_forest: &MastForest,
    ) -> ControlFlow<ProcessingState> {
        let node = current_forest
            .get_node_by_id(node_id)
            .expect("internal error: node id {node_id} not found in current forest");

        for &decorator_id in node.before_enter() {
            self.execute_decorator(&current_forest[decorator_id], 0)?;
        }

        ControlFlow::Continue(())
    }

    /// Executes the decorators that should be executed after exiting a node.
    fn execute_after_exit_decorators(
        &mut self,
        node_id: MastNodeId,
        current_forest: &MastForest,
    ) -> ControlFlow<ProcessingState> {
        let node = current_forest
            .get_node_by_id(node_id)
            .expect("internal error: node id {node_id} not found in current forest");

        for &decorator_id in node.after_exit() {
            self.execute_decorator(&current_forest[decorator_id], 0)?;
        }

        ControlFlow::Continue(())
    }

    /// Executes the specified decorator
    fn execute_decorator(
        &mut self,
        _decorator: &Decorator,
        _op_idx_in_batch: usize,
    ) -> ControlFlow<ProcessingState> {
        // Leave unimplemented for simplicity, since these require a `BaseHost` for e.g.
        // `BaseHost::on_debug`, which in the sans-io style would be another enum variant in
        // `ProcessingState`.
        unimplemented!()
    }

    /// Executes the given operation.
    ///
    /// # Panics
    /// - if the operation is a control flow operation, as these are never executed,
    /// - if the operation is an `Emit` operation, as this requires async execution.
    #[inline(always)]
    fn execute_op(
        &mut self,
        _operation: &Operation,
        _op_idx: usize,
        _program: &MastForest,
        _err_ctx: &impl ErrorContext,
    ) -> ControlFlow<ProcessingState> {
        // This method is not interesting in this exploration PR - we basically have to convert all
        // callees to return `ControlFlow` instead of `ExecutionError`, so would only inflate the
        // diff with no relevant information.
        unimplemented!()
    }

    // HELPERS
    // ----------------------------------------------------------------------------------------------

    /// Increments the stack top pointer by 1.
    ///
    /// The bottom of the stack is never affected by this operation.
    #[inline(always)]
    fn increment_stack_size(&mut self) {
        self.stack_top_idx += 1;
        self.update_bounds_check_counter();
    }

    /// Decrements the stack top pointer by 1.
    ///
    /// The bottom of the stack is only decremented in cases where the stack depth would become less
    /// than 16.
    #[inline(always)]
    fn decrement_stack_size(&mut self) {
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
    }

    /// Restores the execution context to the state it was in before the last `call`, `syscall` or
    /// `dyncall`.
    ///
    /// This includes restoring the overflow stack and the system parameters.
    ///
    /// # Errors
    /// - Returns an error if the overflow stack is larger than the space available in the stack
    ///   buffer.
    fn restore_context(&mut self, err_ctx: &impl ErrorContext) -> ControlFlow<ProcessingState> {
        // when a call/dyncall/syscall node ends, stack depth must be exactly 16.
        if self.stack_size() > MIN_STACK_DEPTH {
            return ControlFlow::Break(ProcessingState::Error(
                ExecutionError::invalid_stack_depth_on_return(self.stack_size(), err_ctx),
            ));
        }

        let ctx_info = self
            .call_stack
            .pop()
            .expect("execution context stack should never be empty when restoring context");

        // restore the overflow stack
        {
            let overflow_len = ctx_info.overflow_stack.len();
            if overflow_len > self.stack_bot_idx {
                return ControlFlow::Break(ProcessingState::Error(
                    ExecutionError::FailedToExecuteProgram(
                        "stack underflow when restoring context",
                    ),
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

        ControlFlow::Continue(())
    }

    // TESTING
    // ----------------------------------------------------------------------------------------------

    /// Convenience sync wrapper to [Self::execute] for testing purposes.
    #[cfg(any(test, feature = "testing"))]
    pub fn execute_sync(
        self,
        _program: &Program,
        _host: &mut impl SyncHost,
    ) -> Result<StackOutputs, ExecutionError> {
        unimplemented!()
    }

    /// Similar to [Self::execute_sync], but allows mutable access to the processor.
    #[cfg(any(test, feature = "testing"))]
    pub fn execute_sync_mut(
        &mut self,
        _program: &Program,
        _host: &mut impl SyncHost,
    ) -> Result<StackOutputs, ExecutionError> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct FastProcessState<'a> {
    pub(super) processor: &'a mut FastProcessor,
    /// the index of the operation in its basic block
    pub(super) op_idx: usize,
}

impl FastProcessor {
    #[inline(always)]
    pub fn state(&mut self, op_idx: usize) -> ProcessState<'_> {
        ProcessState::Fast(FastProcessState { processor: self, op_idx })
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
