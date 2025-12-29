use core::ops::ControlFlow;

use miden_air::{
    Felt, FieldElement, RowIndex,
    trace::{
        STACK_TRACE_WIDTH, SYS_TRACE_WIDTH,
        decoder::{NUM_OP_BITS, NUM_USER_OP_HELPERS},
    },
};
use miden_core::{
    ONE, OPCODE_PUSH, Operation, QuadFelt, StarkField, WORD_SIZE, Word, ZERO,
    mast::{BasicBlockNode, MastForest, MastNode, MastNodeExt, MastNodeId, OpBatch},
    precompile::PrecompileTranscriptState,
    stack::MIN_STACK_DEPTH,
    utils::range,
};

use crate::{
    ContextId, ErrorContext, ExecutionError, ProcessState,
    chiplets::CircuitEvaluation,
    continuation_stack::Continuation,
    decoder::block_stack::ExecutionContextInfo,
    fast::{
        NoopTracer, Tracer, eval_circuit_fast_,
        trace_state::{
            AdviceReplay, CoreTraceFragmentContext, ExecutionContextSystemInfo,
            HasherResponseReplay, MemoryReadsReplay, NodeExecutionState,
        },
    },
    host::default::NoopHost,
    parallel::CORE_TRACE_WIDTH,
    processor::{OperationHelperRegisters, Processor, StackInterface, SystemInterface},
    utils::split_u32_into_u16,
};

mod execution;
mod trace_row;

#[cfg(test)]
mod tests;

// CORE TRACE FRAGMENT
// ================================================================================================

/// The columns of the main trace fragment. These consist of the system, decoder, and stack columns.
///
/// A fragment is a collection of columns of length `fragment_size` or less. Only the last fragment
/// is allowed to be shorter than `fragment_size`.
pub struct CoreTraceFragment<'a> {
    pub columns: [&'a mut [Felt]; CORE_TRACE_WIDTH],
}

// CORE TRACE FRAGMENT FILLER
// ================================================================================================

/// Fills a core trace fragment based on the provided context.
pub struct CoreTraceFragmentFiller<'a> {
    fragment_start_clk: RowIndex,
    fragment: &'a mut CoreTraceFragment<'a>,
    context: CoreTraceFragmentContext,
    stack_rows: Option<[Felt; STACK_TRACE_WIDTH]>,
    system_rows: Option<[Felt; SYS_TRACE_WIDTH]>,
}

impl<'a> CoreTraceFragmentFiller<'a> {
    /// Creates a new CoreTraceFragmentFiller with the provided context and uninitialized fragment.
    pub fn new(
        context: CoreTraceFragmentContext,
        uninit_fragment: &'a mut CoreTraceFragment<'a>,
    ) -> Self {
        Self {
            fragment_start_clk: context.state.system.clk,
            fragment: uninit_fragment,
            context,
            stack_rows: None,
            system_rows: None,
        }
    }

    /// Fills the fragment and returns the final stack rows, system rows, and number of rows built.
    pub fn fill_fragment(mut self) -> ([Felt; STACK_TRACE_WIDTH], [Felt; SYS_TRACE_WIDTH], usize) {
        let execution_state = self.context.initial_execution_state.clone();
        // Execute fragment generation and always finalize at the end
        let _ = self.fill_fragment_impl(execution_state);

        let num_rows_built = self.num_rows_built();
        let final_stack_rows = self.stack_rows.unwrap_or([ZERO; STACK_TRACE_WIDTH]);
        let final_system_rows = self.system_rows.unwrap_or([ZERO; SYS_TRACE_WIDTH]);
        (final_stack_rows, final_system_rows, num_rows_built)
    }

    /// Internal method that fills the fragment with automatic early returns
    fn fill_fragment_impl(&mut self, execution_state: NodeExecutionState) -> ControlFlow<()> {
        let initial_mast_forest = self.context.initial_mast_forest.clone();

        // Finish the current node given its execution state
        match execution_state {
            NodeExecutionState::BasicBlock { node_id, batch_index, op_idx_in_batch } => {
                let basic_block_node = initial_mast_forest
                    .get_node_by_id(node_id)
                    .expect("node should exist")
                    .unwrap_basic_block();

                let mut basic_block_context =
                    BasicBlockContext::new_at_op(basic_block_node, batch_index, op_idx_in_batch);
                self.finish_basic_block_node_from_op(
                    basic_block_node,
                    &initial_mast_forest,
                    batch_index,
                    op_idx_in_batch,
                    &mut basic_block_context,
                )?;
            },
            NodeExecutionState::Start(node_id) => {
                self.execute_mast_node(node_id, &initial_mast_forest)?;
            },
            NodeExecutionState::Respan { node_id, batch_index } => {
                let basic_block_node = initial_mast_forest
                    .get_node_by_id(node_id)
                    .expect("node should exist")
                    .unwrap_basic_block();

                let mut basic_block_context =
                    BasicBlockContext::new_at_batch_start(basic_block_node, batch_index);

                self.add_respan_trace_row(
                    &basic_block_node.op_batches()[batch_index],
                    &mut basic_block_context,
                )?;

                self.finish_basic_block_node_from_op(
                    basic_block_node,
                    &initial_mast_forest,
                    batch_index,
                    0,
                    &mut basic_block_context,
                )?;
            },
            NodeExecutionState::LoopRepeat(node_id) => {
                self.finish_loop_node(node_id, &initial_mast_forest, None)?;
            },
            NodeExecutionState::End(node_id) => {
                let mast_node =
                    initial_mast_forest.get_node_by_id(node_id).expect("node should exist");

                match mast_node {
                    MastNode::Join(join_node) => {
                        self.add_end_trace_row(join_node.digest())?;
                    },
                    MastNode::Split(split_node) => {
                        self.add_end_trace_row(split_node.digest())?;
                    },
                    MastNode::Loop(_loop_node) => {
                        self.finish_loop_node(node_id, &initial_mast_forest, None)?;
                    },
                    MastNode::Call(call_node) => {
                        self.finish_call_node(call_node)?;
                    },
                    MastNode::Dyn(dyn_node) => {
                        self.finish_dyn_node(dyn_node)?;
                    },
                    MastNode::Block(basic_block_node) => {
                        self.add_basic_block_end_trace_row(basic_block_node)?;
                    },
                    MastNode::External(_external_node) => {
                        // External nodes don't generate trace rows directly, and hence will never
                        // show up in the END execution state.
                        panic!("Unexpected external node in END execution state")
                    },
                }
            },
        }

        // Start of main execution loop.
        let mut current_forest = self.context.initial_mast_forest.clone();

        while let Some(continuation) = self.context.continuation.pop_continuation() {
            match continuation {
                Continuation::StartNode(node_id) => {
                    self.execute_mast_node(node_id, &current_forest)?;
                },
                Continuation::FinishJoin(node_id) => {
                    let mast_node =
                        current_forest.get_node_by_id(node_id).expect("node should exist");
                    self.add_end_trace_row(mast_node.digest())?;
                },
                Continuation::FinishSplit(node_id) => {
                    let mast_node =
                        current_forest.get_node_by_id(node_id).expect("node should exist");
                    self.add_end_trace_row(mast_node.digest())?;
                },
                Continuation::FinishLoop(node_id) => {
                    self.finish_loop_node(node_id, &current_forest, None)?;
                },
                Continuation::FinishLoopUnentered(_node_id) => {
                    unimplemented!("`ExecutionTracer` doesn't generate this variant yet")
                },
                Continuation::FinishCall(node_id) => {
                    let call_node = current_forest
                        .get_node_by_id(node_id)
                        .expect("node should exist")
                        .unwrap_call();

                    self.finish_call_node(call_node)?;
                },
                Continuation::FinishDyn(node_id) => {
                    let dyn_node = current_forest
                        .get_node_by_id(node_id)
                        .expect("node should exist")
                        .unwrap_dyn();
                    self.finish_dyn_node(dyn_node)?;
                },
                Continuation::FinishExternal(_node_id) => {
                    // Execute after_exit decorators when returning from an external node
                    // Note: current_forest should already be restored by EnterForest continuation
                    // External nodes don't generate END trace rows in the parallel processor
                    // as they only execute after_exit decorators
                },
                Continuation::ResumeBasicBlock {
                    node_id: _,
                    batch_index: _,
                    op_idx_in_batch: _,
                } => {
                    unimplemented!("`ExecutionTracer` doesn't generate this variant yet")
                },
                Continuation::Respan { node_id: _, batch_index: _ } => {
                    unimplemented!("`ExecutionTracer` doesn't generate this variant yet")
                },
                Continuation::FinishBasicBlock(_node_id) => {
                    unimplemented!("`ExecutionTracer` doesn't generate this variant yet")
                },
                Continuation::EnterForest(previous_forest) => {
                    // Restore the previous forest
                    current_forest = previous_forest;
                },
                Continuation::AfterExitDecorators(_node_id) => {
                    unimplemented!("`ExecutionTracer` doesn't generate this variant yet")
                },
                Continuation::AfterExitDecoratorsBasicBlock(_node_id) => {
                    unimplemented!("`ExecutionTracer` doesn't generate this variant yet")
                },
            }
        }

        // All nodes completed without filling the fragment
        ControlFlow::Continue(())
    }

    fn execute_mast_node(
        &mut self,
        node_id: MastNodeId,
        current_forest: &MastForest,
    ) -> ControlFlow<()> {
        let mast_node = current_forest.get_node_by_id(node_id).expect("node should exist");

        match mast_node {
            MastNode::Block(basic_block_node) => {
                self.context.state.decoder.replay_node_start(&mut self.context.replay);

                self.add_basic_block_start_trace_row(basic_block_node)?;

                let mut basic_block_context = BasicBlockContext::new_at_op(basic_block_node, 0, 0);
                self.finish_basic_block_node_from_op(
                    basic_block_node,
                    current_forest,
                    0,
                    0,
                    &mut basic_block_context,
                )
            },
            MastNode::Join(join_node) => {
                self.context.state.decoder.replay_node_start(&mut self.context.replay);

                self.add_join_start_trace_row(join_node, current_forest)?;

                self.execute_mast_node(join_node.first(), current_forest)?;
                self.execute_mast_node(join_node.second(), current_forest)?;

                self.add_end_trace_row(join_node.digest())
            },
            MastNode::Split(split_node) => {
                self.context.state.decoder.replay_node_start(&mut self.context.replay);

                let condition = self.get(0);
                self.decrement_size(&mut NoopTracer);

                // 1. Add "start SPLIT" row
                self.add_split_start_trace_row(split_node, current_forest)?;

                // 2. Execute the appropriate branch based on the stack top value
                if condition == ONE {
                    self.execute_mast_node(split_node.on_true(), current_forest)?;
                } else {
                    self.execute_mast_node(split_node.on_false(), current_forest)?;
                }

                // 3. Add "end SPLIT" row
                self.add_end_trace_row(split_node.digest())
            },
            MastNode::Loop(loop_node) => {
                self.context.state.decoder.replay_node_start(&mut self.context.replay);

                // Read condition from the stack and decrement stack size. This happens as part of
                // the LOOP operation, and so is done before writing that trace row.
                let mut condition = self.get(0);
                self.decrement_size(&mut NoopTracer);

                // 1. Add "start LOOP" row
                self.add_loop_start_trace_row(loop_node, current_forest)?;

                // 2. Loop while condition is true
                //
                // The first iteration is special because it doesn't insert a REPEAT trace row
                // before executing the loop body. Therefore it is done separately.
                if condition == ONE {
                    self.execute_mast_node(loop_node.body(), current_forest)?;

                    condition = self.get(0);
                    self.decrement_size(&mut NoopTracer);
                }

                self.finish_loop_node(node_id, current_forest, Some(condition))
            },
            MastNode::Call(call_node) => {
                self.context.state.decoder.replay_node_start(&mut self.context.replay);

                self.context.state.stack.start_context();

                // Set up new context for the call
                if call_node.is_syscall() {
                    self.context.state.system.ctx = ContextId::root(); // Root context for syscalls
                } else {
                    self.context.state.system.ctx =
                        ContextId::from(self.context.state.system.clk + 1); // New context ID
                    self.context.state.system.fn_hash = current_forest[call_node.callee()].digest();
                }

                // Add "start CALL/SYSCALL" row
                self.add_call_start_trace_row(call_node, current_forest)?;

                // Execute the callee
                self.execute_mast_node(call_node.callee(), current_forest)?;

                // Restore context state
                let ctx_info = self.context.replay.block_stack.replay_execution_context();
                self.restore_context_from_replay(&ctx_info);

                // 2. Add "end CALL/SYSCALL" row
                self.add_end_trace_row(call_node.digest())
            },
            MastNode::Dyn(dyn_node) => {
                self.context.state.decoder.replay_node_start(&mut self.context.replay);

                let callee_hash = {
                    let mem_addr = self.context.state.stack.get(0);
                    self.context.replay.memory_reads.replay_read_word(mem_addr)
                };

                // Drop the memory address off the stack. This needs to be done before saving the
                // context.
                self.decrement_size(&mut NoopTracer);

                // Add "start DYN/DYNCALL" row
                if dyn_node.is_dyncall() {
                    let (stack_depth, next_overflow_addr) =
                        self.context.state.stack.start_context();
                    // For DYNCALL, we need to save the current context state
                    // and prepare for dynamic execution
                    let ctx_info = ExecutionContextInfo::new(
                        self.context.state.system.ctx,
                        self.context.state.system.fn_hash,
                        stack_depth as u32,
                        next_overflow_addr,
                    );

                    self.context.state.system.ctx =
                        ContextId::from(self.context.state.system.clk + 1); // New context ID
                    self.context.state.system.fn_hash = callee_hash;

                    self.add_dyncall_start_trace_row(callee_hash, ctx_info)?;
                } else {
                    self.add_dyn_start_trace_row(callee_hash)?;
                };

                // Execute the callee
                match current_forest.find_procedure_root(callee_hash) {
                    Some(callee_id) => self.execute_mast_node(callee_id, current_forest)?,
                    None => {
                        let (resolved_node_id, resolved_forest) =
                            self.context.replay.mast_forest_resolution.replay_resolution();

                        self.execute_mast_node(resolved_node_id, &resolved_forest)?
                    },
                };

                // Restore context state for DYNCALL
                if dyn_node.is_dyncall() {
                    let ctx_info = self.context.replay.block_stack.replay_execution_context();
                    self.restore_context_from_replay(&ctx_info);
                }

                // Add "end DYN/DYNCALL" row
                self.add_end_trace_row(dyn_node.digest())
            },
            MastNode::External(_) => {
                let (resolved_node_id, resolved_forest) =
                    self.context.replay.mast_forest_resolution.replay_resolution();

                self.execute_mast_node(resolved_node_id, &resolved_forest)
            },
        }
    }

    /// Restores the execution context to the state it was in before the last `call`, `syscall` or
    /// `dyncall`.
    ///
    /// This includes restoring the overflow stack and the system parameters.
    fn restore_context_from_replay(&mut self, ctx_info: &ExecutionContextSystemInfo) {
        self.context.state.system.ctx = ctx_info.parent_ctx;
        self.context.state.system.fn_hash = ctx_info.parent_fn_hash;

        self.context
            .state
            .stack
            .restore_context(&mut self.context.replay.stack_overflow);
    }

    /// Executes operations within an operation batch, analogous to FastProcessor::execute_op_batch.
    ///
    /// If `start_op_idx` is provided, execution begins from that operation index within the batch.
    fn execute_op_batch(
        &mut self,
        batch: &OpBatch,
        start_op_idx: Option<usize>,
        current_forest: &MastForest,
        basic_block_context: &mut BasicBlockContext,
    ) -> ControlFlow<()> {
        let start_op_idx = start_op_idx.unwrap_or(0);
        let end_indices = batch.end_indices();

        // Execute operations in the batch starting from the correct static operation index
        for (op_idx_in_batch, (op_group_idx, op_idx_in_group, op)) in
            batch.iter_with_groups().enumerate().skip(start_op_idx)
        {
            {
                // `execute_sync_op` does not support executing `Emit`, so we only call it for all
                // other operations.
                let user_op_helpers = if let Operation::Emit = op {
                    None
                } else {
                    self.execute_sync_op(
                        op,
                        current_forest,
                        &mut NoopHost,
                        &(),
                        &mut NoopTracer,
                    )
                    // The assumption here is that the computation was done by the FastProcessor,
                    // and so all operations in the program are valid and can be executed
                    // successfully.
                    .expect("operation should execute successfully")
                };

                // write the operation to the trace
                self.add_operation_trace_row(
                    *op,
                    op_idx_in_group,
                    user_op_helpers,
                    basic_block_context,
                )?;
            }

            // if we executed all operations in a group and haven't reached the end of the batch
            // yet, set up the decoder for decoding the next operation group
            if op_idx_in_batch + 1 == end_indices[op_group_idx]
                && let Some(next_op_group_idx) = batch.next_op_group_index(op_group_idx)
            {
                basic_block_context.start_op_group(batch.groups()[next_op_group_idx]);
            }
        }

        ControlFlow::Continue(())
    }

    // HELPERS
    // -------------------------------------------------------------------------------------------

    fn done_generating(&mut self) -> bool {
        // If we have built all the rows in the fragment, we are done
        let max_num_rows_in_fragment = self.fragment.columns[0].len();
        self.num_rows_built() >= max_num_rows_in_fragment
    }

    fn num_rows_built(&self) -> usize {
        // Returns the number of rows built so far in the fragment
        self.context.state.system.clk - self.fragment_start_clk
    }

    fn increment_clk(&mut self) -> ControlFlow<()> {
        self.context.state.system.clk += 1u32;

        // Check if we have reached the maximum number of rows in the fragment
        if self.done_generating() {
            // If we have reached the maximum, we are done generating
            ControlFlow::Break(())
        } else {
            // Otherwise, we continue generating
            ControlFlow::Continue(())
        }
    }
}

impl<'a> StackInterface for CoreTraceFragmentFiller<'a> {
    fn top(&self) -> &[Felt] {
        &self.context.state.stack.stack_top
    }

    fn top_mut(&mut self) -> &mut [Felt] {
        &mut self.context.state.stack.stack_top
    }

    fn get(&self, idx: usize) -> Felt {
        debug_assert!(idx < MIN_STACK_DEPTH);
        self.context.state.stack.stack_top[MIN_STACK_DEPTH - idx - 1]
    }

    fn get_mut(&mut self, idx: usize) -> &mut Felt {
        debug_assert!(idx < MIN_STACK_DEPTH);

        &mut self.context.state.stack.stack_top[MIN_STACK_DEPTH - idx - 1]
    }

    fn get_word(&self, start_idx: usize) -> Word {
        debug_assert!(start_idx < MIN_STACK_DEPTH - 4);

        let word_start_idx = MIN_STACK_DEPTH - start_idx - 4;
        self.top()[range(word_start_idx, WORD_SIZE)].try_into().unwrap()
    }

    fn depth(&self) -> u32 {
        (MIN_STACK_DEPTH + self.context.state.stack.num_overflow_elements_in_current_ctx()) as u32
    }

    fn set(&mut self, idx: usize, element: Felt) {
        *self.get_mut(idx) = element;
    }

    fn set_word(&mut self, start_idx: usize, word: &Word) {
        debug_assert!(start_idx < MIN_STACK_DEPTH - 4);
        let word_start_idx = MIN_STACK_DEPTH - start_idx - 4;

        let word_on_stack =
            &mut self.context.state.stack.stack_top[range(word_start_idx, WORD_SIZE)];
        word_on_stack.copy_from_slice(word.as_slice());
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
            self.context.state.stack.stack_top.split_at_mut(MIN_STACK_DEPTH - WORD_SIZE);
        let (_, nth_word) = rest_of_stack.split_at_mut(rest_of_stack.len() - n * WORD_SIZE);

        nth_word[0..WORD_SIZE].swap_with_slice(&mut top_word[0..WORD_SIZE]);
    }

    fn rotate_left(&mut self, n: usize) {
        let rotation_bot_index = MIN_STACK_DEPTH - n;
        let new_stack_top_element = self.context.state.stack.stack_top[rotation_bot_index];

        // shift the top n elements down by 1, starting from the bottom of the rotation.
        for i in 0..n - 1 {
            self.context.state.stack.stack_top[rotation_bot_index + i] =
                self.context.state.stack.stack_top[rotation_bot_index + i + 1];
        }

        // Set the top element (which comes from the bottom of the rotation).
        self.set(0, new_stack_top_element);
    }

    fn rotate_right(&mut self, n: usize) {
        let rotation_bot_index = MIN_STACK_DEPTH - n;
        let new_stack_bot_element = self.context.state.stack.stack_top[MIN_STACK_DEPTH - 1];

        // shift the top n elements up by 1, starting from the top of the rotation.
        for i in 1..n {
            self.context.state.stack.stack_top[MIN_STACK_DEPTH - i] =
                self.context.state.stack.stack_top[MIN_STACK_DEPTH - i - 1];
        }

        // Set the bot element (which comes from the top of the rotation).
        self.context.state.stack.stack_top[rotation_bot_index] = new_stack_bot_element;
    }

    fn increment_size(&mut self, _tracer: &mut impl Tracer) -> Result<(), ExecutionError> {
        const SENTINEL_VALUE: Felt = Felt::new(Felt::MODULUS - 1);

        // push the last element on the overflow table
        {
            let last_element = self.get(MIN_STACK_DEPTH - 1);
            self.context.state.stack.push_overflow(last_element, self.clk());
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

    fn decrement_size(&mut self, _tracer: &mut impl Tracer) {
        // Shift all other elements up
        for write_idx in 0..(MIN_STACK_DEPTH - 1) {
            let read_idx = write_idx + 1;
            self.set(write_idx, self.get(read_idx));
        }

        // Pop the last element from the overflow table
        if let Some(last_element) =
            self.context.state.stack.pop_overflow(&mut self.context.replay.stack_overflow)
        {
            // Write the last element to the bottom of the stack
            self.set(MIN_STACK_DEPTH - 1, last_element);
        } else {
            // If overflow table is empty, set the bottom element to zero
            self.set(MIN_STACK_DEPTH - 1, ZERO);
        }
    }
}

impl<'a> Processor for CoreTraceFragmentFiller<'a> {
    type HelperRegisters = TraceGenerationHelpers;
    type System = Self;
    type Stack = Self;
    type AdviceProvider = AdviceReplay;
    type Memory = MemoryReadsReplay;
    type Hasher = HasherResponseReplay;

    fn stack(&mut self) -> &mut Self::Stack {
        self
    }

    fn system(&mut self) -> &mut Self::System {
        self
    }

    fn state(&mut self) -> ProcessState<'_> {
        ProcessState::Noop(())
    }

    fn advice_provider(&mut self) -> &mut Self::AdviceProvider {
        &mut self.context.replay.advice
    }

    fn memory(&mut self) -> &mut Self::Memory {
        &mut self.context.replay.memory_reads
    }

    fn hasher(&mut self) -> &mut Self::Hasher {
        &mut self.context.replay.hasher
    }

    fn precompile_transcript_state(&self) -> PrecompileTranscriptState {
        self.context.state.system.pc_transcript_state
    }

    fn set_precompile_transcript_state(&mut self, state: PrecompileTranscriptState) {
        self.context.state.system.pc_transcript_state = state;
    }

    fn op_eval_circuit(
        &mut self,
        err_ctx: &impl ErrorContext,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        let num_eval = self.stack().get(2);
        let num_read = self.stack().get(1);
        let ptr = self.stack().get(0);
        let ctx = self.system().ctx();

        let _circuit_evaluation = eval_circuit_parallel_(
            ctx,
            ptr,
            self.system().clk(),
            num_read,
            num_eval,
            self,
            err_ctx,
            tracer,
        )?;

        Ok(())
    }
}

impl<'a> SystemInterface for CoreTraceFragmentFiller<'a> {
    fn caller_hash(&self) -> Word {
        self.context.state.system.fn_hash
    }

    fn clk(&self) -> RowIndex {
        self.context.state.system.clk
    }

    fn ctx(&self) -> ContextId {
        self.context.state.system.ctx
    }
}

/// Implementation of `OperationHelperRegisters` used for trace generation, where we actually
/// compute the helper registers associated with the corresponding operation.
pub struct TraceGenerationHelpers;

impl OperationHelperRegisters for TraceGenerationHelpers {
    #[inline(always)]
    fn op_eq_registers(stack_second: Felt, stack_first: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        let h0 = if stack_second == stack_first {
            ZERO
        } else {
            (stack_first - stack_second).inv()
        };

        [h0, ZERO, ZERO, ZERO, ZERO, ZERO]
    }

    #[inline(always)]
    fn op_u32split_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());
        let m = (Felt::from(u32::MAX) - hi).inv();

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), m, ZERO]
    }

    #[inline(always)]
    fn op_eqz_registers(top: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        // h0 is a helper variable provided by the prover. If the top element is zero, then, h0 can
        // be set to anything otherwise set it to the inverse of the top element in the stack.
        let h0 = if top == ZERO { ZERO } else { top.inv() };

        [h0, ZERO, ZERO, ZERO, ZERO, ZERO]
    }

    #[inline(always)]
    fn op_expacc_registers(acc_update_val: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        [acc_update_val, ZERO, ZERO, ZERO, ZERO, ZERO]
    }

    #[inline(always)]
    fn op_fri_ext2fold4_registers(
        ev: QuadFelt,
        es: QuadFelt,
        x: Felt,
        x_inv: Felt,
    ) -> [Felt; NUM_USER_OP_HELPERS] {
        let ev_arr = [ev];
        let ev_felts = QuadFelt::slice_as_base_elements(&ev_arr);

        let es_arr = [es];
        let es_felts = QuadFelt::slice_as_base_elements(&es_arr);

        [ev_felts[0], ev_felts[1], es_felts[0], es_felts[1], x, x_inv]
    }

    #[inline(always)]
    fn op_u32add_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        // Compute helpers for range checks
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());

        // For u32add, check_element_validity is false
        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), ZERO, ZERO]
    }

    #[inline(always)]
    fn op_u32add3_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        // Compute helpers for range checks
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), ZERO, ZERO]
    }

    #[inline(always)]
    fn op_u32sub_registers(second_new: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        // Compute helpers for range checks (only `second_new` needs range checking)
        let (t1, t0) = split_u32_into_u16(second_new.as_int());

        [Felt::from(t0), Felt::from(t1), ZERO, ZERO, ZERO, ZERO]
    }

    #[inline(always)]
    fn op_u32mul_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        // Compute helpers for range checks
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());
        let m = (Felt::from(u32::MAX) - hi).inv();

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), m, ZERO]
    }

    #[inline(always)]
    fn op_u32madd_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        // Compute helpers for range checks
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());
        let m = (Felt::from(u32::MAX) - hi).inv();

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), m, ZERO]
    }

    #[inline(always)]
    fn op_u32div_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        // Compute helpers for range checks
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), ZERO, ZERO]
    }

    #[inline(always)]
    fn op_u32assert2_registers(first: Felt, second: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        // Compute helpers for range checks for both operands
        let (t1, t0) = split_u32_into_u16(second.as_int());
        let (t3, t2) = split_u32_into_u16(first.as_int());

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), ZERO, ZERO]
    }

    #[inline(always)]
    fn op_hperm_registers(addr: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        [addr, ZERO, ZERO, ZERO, ZERO, ZERO]
    }

    #[inline(always)]
    fn op_merkle_path_registers(addr: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        [addr, ZERO, ZERO, ZERO, ZERO, ZERO]
    }

    #[inline(always)]
    fn op_horner_eval_base_registers(
        alpha: QuadFelt,
        tmp0: QuadFelt,
        tmp1: QuadFelt,
    ) -> [Felt; NUM_USER_OP_HELPERS] {
        [
            alpha.base_element(0),
            alpha.base_element(1),
            tmp1.to_base_elements()[0],
            tmp1.to_base_elements()[1],
            tmp0.to_base_elements()[0],
            tmp0.to_base_elements()[1],
        ]
    }

    fn op_horner_eval_ext_registers(
        alpha: QuadFelt,
        k0: Felt,
        k1: Felt,
        acc_tmp: QuadFelt,
    ) -> [Felt; NUM_USER_OP_HELPERS] {
        [
            alpha.base_element(0),
            alpha.base_element(1),
            k0,
            k1,
            acc_tmp.base_element(0),
            acc_tmp.base_element(1),
        ]
    }

    #[inline(always)]
    fn op_log_precompile_registers(addr: Felt, cap_prev: Word) -> [Felt; NUM_USER_OP_HELPERS] {
        // Helper registers layout for log_precompile:
        // h0-h4 contain: [addr, CAP_PREV[0..3]]
        [addr, cap_prev[0], cap_prev[1], cap_prev[2], cap_prev[3], ZERO]
    }
}

// HELPERS
// ================================================================================================

/// Identical to `[chiplets::ace::eval_circuit]` but adapted for use with
/// `[CoreTraceFragmentGenerator]`.
fn eval_circuit_parallel_(
    ctx: ContextId,
    ptr: Felt,
    clk: RowIndex,
    num_vars: Felt,
    num_eval: Felt,
    processor: &mut CoreTraceFragmentFiller,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<CircuitEvaluation, ExecutionError> {
    // Delegate to the fast implementation with the processor's memory interface.
    // This eliminates ~70 lines of duplicated code while maintaining identical functionality.
    eval_circuit_fast_(ctx, ptr, clk, num_vars, num_eval, processor.memory(), err_ctx, tracer)
}

// BASIC BLOCK CONTEXT
// ================================================================================================

/// Keeps track of the info needed to decode a currently executing BASIC BLOCK. The info includes:
/// - Operations which still need to be executed in the current group. The operations are encoded as
///   opcodes (7 bits) appended one after another into a single field element, with the next
///   operation to be executed located at the least significant position.
/// - Number of operation groups left to be executed in the entire BASIC BLOCK.
#[derive(Debug, Default)]
pub struct BasicBlockContext {
    pub current_op_group: Felt,
    pub group_count_in_block: Felt,
}

impl BasicBlockContext {
    /// Initializes a `BasicBlockContext` for the case where execution starts at the beginning of an
    /// operation batch (i.e. at a SPAN or RESPAN row).
    fn new_at_batch_start(basic_block_node: &BasicBlockNode, batch_index: usize) -> Self {
        let current_batch = &basic_block_node.op_batches()[batch_index];

        Self {
            current_op_group: current_batch.groups()[0],
            group_count_in_block: Felt::new(
                basic_block_node
                    .op_batches()
                    .iter()
                    .skip(batch_index)
                    .map(|batch| batch.num_groups())
                    .sum::<usize>() as u64,
            ),
        }
    }

    /// Given that a trace fragment can start executing from the middle of a basic block, we need to
    /// initialize the `BasicBlockContext` correctly to reflect the state of the decoder at that
    /// point. This function does that initialization.
    ///
    /// Recall that `BasicBlockContext` keeps track of the state needed to correctly fill in the
    /// decoder columns associated with a SPAN of operations (i.e. a basic block). This function
    /// takes in a basic block node, the index of the current operation batch within that block,
    /// and the index of the current operation within that batch, and initializes the
    /// `BasicBlockContext` accordingly. In other words, it figures out how many operations are
    /// left in the current operation group, and how many operation groups are left in the basic
    /// block, given that we are starting execution from the specified operation.
    fn new_at_op(
        basic_block_node: &BasicBlockNode,
        batch_index: usize,
        op_idx_in_batch: usize,
    ) -> Self {
        let op_batches = basic_block_node.op_batches();
        let (current_op_group_idx, op_idx_in_group) = op_batches[batch_index]
            .op_idx_in_batch_to_group(op_idx_in_batch)
            .expect("invalid batch");

        let current_op_group = {
            // Note: this here relies on NOOP's opcode to be 0, since `current_op_group_idx` could
            // point to an op group that contains a NOOP inserted at runtime (i.e.
            // padding at the end of the batch), and hence not encoded in the basic
            // block directly. But since NOOP's opcode is 0, this works out correctly
            // (since empty groups are also represented by 0).
            let current_op_group = op_batches[batch_index].groups()[current_op_group_idx];

            // Shift out all operations that are already executed in this group.
            //
            // Note: `group_ops_left` encodes the bits of the operations left to be executed after
            // the current one, and so we would expect to shift `NUM_OP_BITS` by
            // `op_idx_in_group + 1`. However, we will apply that shift right before
            // writing to the trace, so we only shift by `op_idx_in_group` here.
            Felt::new(current_op_group.as_int() >> (NUM_OP_BITS * op_idx_in_group))
        };

        let group_count_in_block = {
            let total_groups = basic_block_node.num_op_groups();

            // Count groups consumed by completed batches (all batches before current one).
            let mut groups_consumed = 0;
            for op_batch in op_batches.iter().take(batch_index) {
                groups_consumed += op_batch.num_groups().next_power_of_two();
            }

            // We run through previous operations of our current op group, and increment the number
            // of groups consumed for each operation that has an immediate value
            {
                // Note: This is a hacky way of doing this because `OpBatch` doesn't store the
                // information of which operation belongs to which group.
                let mut current_op_group =
                    op_batches[batch_index].groups()[current_op_group_idx].as_int();
                for _ in 0..op_idx_in_group {
                    let current_op = (current_op_group & 0b1111111) as u8;
                    if current_op == OPCODE_PUSH {
                        groups_consumed += 1;
                    }

                    current_op_group >>= NUM_OP_BITS; // Shift to the next operation in the group
                }
            }

            // Add the number of complete groups before the current group in this batch. Add 1 to
            // account for the current group (since `num_groups_left` is the number of groups left
            // *after* being done with the current group)
            groups_consumed += current_op_group_idx + 1;

            Felt::from((total_groups - groups_consumed) as u32)
        };

        Self { current_op_group, group_count_in_block }
    }

    /// Removes the operation that was just executed from the current operation group.
    fn remove_operation_from_current_op_group(&mut self) {
        let prev_op_group = self.current_op_group.as_int();
        self.current_op_group = Felt::new(prev_op_group >> NUM_OP_BITS);

        debug_assert!(prev_op_group >= self.current_op_group.as_int(), "op group underflow");
    }

    /// Starts decoding a new operation group.
    pub fn start_op_group(&mut self, op_group: Felt) {
        // reset the current group value and decrement the number of left groups by ONE
        debug_assert_eq!(ZERO, self.current_op_group, "not all ops executed in current group");
        self.current_op_group = op_group;
        self.group_count_in_block -= ONE;
    }
}
