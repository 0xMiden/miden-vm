use alloc::vec::Vec;
use core::ops::ControlFlow;

use miden_air::{
    RowIndex,
    trace::{
        DECODER_TRACE_WIDTH, STACK_TRACE_WIDTH, SYS_TRACE_WIDTH,
        decoder::{NUM_OP_BITS, NUM_USER_OP_HELPERS},
    },
};
use miden_core::{
    Felt, ONE, Operation, Program, StarkField, WORD_SIZE, Word, ZERO,
    mast::{BasicBlockNode, MastForest, MastNode, MastNodeId, OP_GROUP_SIZE, OpBatch},
    stack::MIN_STACK_DEPTH,
    utils::{range, uninit_vector},
};
use tokio::{sync::mpsc::Receiver, task::JoinHandle};
use traversal::ExecutionTraversal;

use crate::{
    ContextId,
    decoder::{
        SpanContext,
        block_stack::{BlockStack, BlockType, ExecutionContextInfo},
    },
    processor::Processor,
    stack::OverflowTable,
    system::{FMP_MIN, SYSCALL_FMP_MIN},
};

pub const MAIN_TRACE_WIDTH: usize = SYS_TRACE_WIDTH + DECODER_TRACE_WIDTH + STACK_TRACE_WIDTH;

mod basic_block;
mod call;
mod r#dyn;
mod join;
mod r#loop;
mod operations;

mod replay;
use replay::{AdviceReplay, ExternalNodeReplay, HasherReplay, MemoryReplay};

mod split;
mod trace_builder;
mod traversal;

// TRACE ROW TYPE
// ================================================================================================

/// Enum to specify whether this is a start or end trace row for control block operations
/// (JOIN, SPLIT, LOOP, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceRowType {
    Start,
    End,
}

// NODE EXECUTION PHASE
// ================================================================================================

/// Enum to specify the execution phase when starting fragment generation.
///
/// This replaces the previous `Option<(usize, usize)>` parameter to provide clearer
/// semantics for different types of execution resumption scenarios.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeExecutionPhase {
    /// Resume execution within a basic block at a specific batch and operation index.
    /// This is used when continuing execution mid-way through a basic block.
    BasicBlock {
        /// Index of the operation batch within the basic block
        batch_index: usize,
        /// Index of the operation within the batch
        op_idx_in_batch: usize,
        /// Whether a RESPAN operation needs to be added before executing this batch. When true,
        /// `batch_index` refers to the batch to be executed *after* the RESPAN operation, and
        /// `op_index_in_batch` MUST be set to 0.
        needs_respan: bool,
    },
    /// Execute the START phase of a control flow node (JOIN, SPLIT, LOOP, etc.).
    /// This is used when beginning execution of a control flow construct.
    Start,
    /// Execute the END phase of a control flow node (JOIN, SPLIT, LOOP, etc.).
    /// This is used when completing execution of a control flow construct.
    End,
}

// STATE STRUCTS
// ================================================================================================

/// The `SystemState` represents all the information needed to build one row of the System trace.
///
/// This struct captures the complete state of the system at a specific clock cycle,
/// allowing for reconstruction of the system trace during concurrent execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemState {
    /// Current clock cycle (row index in the trace)
    pub clk: RowIndex,

    /// Execution context ID - starts at 0 (root context), changes on CALL/SYSCALL operations
    pub ctx: ContextId,

    /// Free memory pointer - initially set to 2^30, used for local memory offsets
    pub fmp: Felt,

    /// Flag indicating whether currently executing within a SYSCALL block
    pub in_syscall: bool,

    /// Hash of the function that initiated the current execution context
    /// - For root context: [ZERO; 4]
    /// - For CALL/DYNCALL contexts: hash of the called function
    /// - For SYSCALL contexts: hash remains from the calling function
    pub fn_hash: Word,
}

/// A checkpoint represents all the information for one row of the Stack trace.
///
/// This struct captures the complete state of the stack at a specific clock cycle,
/// allowing for reconstruction of the stack trace during concurrent execution.
/// The stack trace consists of 19 columns total: 16 stack columns + 3 helper columns.
/// The helper columns (stack_depth, overflow_addr, and overflow_helper) are derived from the
/// OverflowTable.
#[derive(Debug)]
pub struct StackState {
    /// Top 16 stack slots (s0 to s15)
    /// These represent the top elements of the stack that are directly accessible
    stack_top: [Felt; MIN_STACK_DEPTH], // 16 columns

    /// Overflow table containing all stack elements beyond the top 16
    /// Used to derive the helper columns (b0, b1, h0) for the stack trace
    overflow: OverflowTable,
}

impl StackState {
    /// Creates a new StackState with the provided parameters.
    ///
    /// `stack_top` should be the top 16 elements of the stack stored in reverse order, i.e.,
    /// `stack_top[15]` is the topmost element (s0), and `stack_top[0]` is the bottommost element
    /// (s15).
    pub fn new(stack_top: [Felt; MIN_STACK_DEPTH], overflow: OverflowTable) -> Self {
        Self { stack_top, overflow }
    }

    /// Derives the stack depth (b0 helper column) from the overflow table
    pub fn stack_depth(&self) -> Felt {
        Felt::new((MIN_STACK_DEPTH + self.overflow.total_num_elements()) as u64)
    }

    /// Derives the overflow address (b1 helper column) from the overflow table
    pub fn overflow_addr(&self) -> Felt {
        self.overflow.last_update_clk_in_current_ctx()
    }

    /// Derives the overflow helper (h0 helper column) from the current stack depth
    pub fn overflow_helper(&self) -> Felt {
        let stack_depth = self.stack_depth();
        let depth_value = stack_depth.as_int() as usize;

        if depth_value > MIN_STACK_DEPTH {
            // Note: In the actual trace, this gets inverted later via batch inversion
            Felt::new((depth_value - MIN_STACK_DEPTH) as u64)
        } else {
            ZERO
        }
    }

    pub fn start_context(&mut self) -> (usize, Felt) {
        // Return the current stack depth and overflow address at the start of a new context
        let current_depth = self.stack_depth().as_int() as usize;
        let current_overflow_addr = self.overflow_addr();
        self.overflow.start_context();

        (current_depth, current_overflow_addr)
    }

    pub fn shift_left_and_start_context(&mut self) -> (usize, Felt) {
        const START_POSITION: usize = 1;

        // Get the current state before any modifications
        let current_depth = self.stack_depth().as_int() as usize;
        let current_overflow_addr = self.overflow_addr();

        // Perform the left shift operation
        {
            // Shift all elements left by one position (from start_position to the end)
            for i in START_POSITION..MIN_STACK_DEPTH {
                self.stack_top[i - 1] = self.stack_top[i];
            }

            // Handle the last element (index 15) based on overflow table state
            let new_last_element = if current_depth > MIN_STACK_DEPTH {
                // Pop an element from the overflow table to fill the last position
                self.overflow.pop().expect(
                    "Overflow table should have elements to pop when depth > MIN_STACK_DEPTH",
                )
            } else {
                // When depth <= MIN_STACK_DEPTH, shift in a ZERO to prevent depth shrinking below
                // minimum
                ZERO
            };
            self.stack_top[MIN_STACK_DEPTH - 1] = new_last_element;
        }

        // Start a new context (this resets the overflow table)
        self.overflow.start_context();

        (current_depth, current_overflow_addr)
    }
}

pub struct CoreTraceState {
    pub system: SystemState,
    pub stack: StackState,
    pub block_stack: BlockStack,
    pub traversal: ExecutionTraversal,
    pub memory: MemoryReplay,
    pub advice: AdviceReplay,
    pub hasher: HasherReplay,
    pub external_node_replay: ExternalNodeReplay,
}

// MAIN TRACE FRAGMENT AND MANAGER
// ================================================================================================

/// The columns of the main trace fragment. These consist of the system, decoder, and stack columns.
pub struct CoreTraceFragment {
    pub columns: [Vec<Felt>; MAIN_TRACE_WIDTH],
}

impl CoreTraceFragment {
    /// Creates a new CoreTraceFragment with *uninitialized* columns of length `num_rows`.
    ///
    /// # Safety
    /// The caller is responsible for ensuring that the columns are properly initialized
    /// before use.
    pub unsafe fn new_uninit(num_rows: usize) -> Self {
        Self {
            columns: core::array::from_fn(|_| unsafe { uninit_vector(num_rows) }),
        }
    }

    /// Returns the number of rows in this fragment
    pub fn row_count(&self) -> usize {
        self.columns[0].len()
    }
}

pub struct CoreTraceFragmentManager {
    /// Channel to receive execution state and phase information for fragment generation
    channel: Receiver<(CoreTraceState, NodeExecutionPhase)>,
    fragments: Vec<CoreTraceFragment>,
    program: Program,
}

impl CoreTraceFragmentManager {
    /// The number of rows per main trace fragment.
    pub const NUM_ROWS_PER_FRAGMENT: usize = 1024;

    /// Creates a new CoreTraceGenerator with the provided channel
    pub fn new(program: Program, channel: Receiver<(CoreTraceState, NodeExecutionPhase)>) -> Self {
        Self { program, channel, fragments: Vec::new() }
    }

    /// Processes checkpoints from the channel, producing fragments in order
    ///
    /// This method reads checkpoints from the channel and spawns async tasks to process
    /// each one into a CoreTraceFragment. The fragments are added to self.fragments
    /// in the same order as the checkpoints were received.
    pub async fn process(&mut self) {
        let mut pending_tasks: Vec<JoinHandle<CoreTraceFragment>> = Vec::new();

        // Phase 1: Spawn tasks for all incoming checkpoints
        while let Some((main_trace_state, execution_phase)) = self.channel.recv().await {
            let mast_forest = self.program.mast_forest().clone();
            let task = tokio::task::spawn_blocking(move || {
                let main_trace_generator = CoreTraceFragmentGenerator::new(main_trace_state);
                main_trace_generator.generate_fragment(&mast_forest, execution_phase)
            });

            pending_tasks.push(task);
        }

        // Phase 2: Collect results in order
        // Tasks are already in the correct order since we pushed them sequentially
        for task in pending_tasks {
            let fragment = task.await.expect("Task should not panic");
            self.fragments.push(fragment);
        }
    }

    /// Returns a reference to the collected fragments
    pub fn fragments(&self) -> &[CoreTraceFragment] {
        &self.fragments
    }
}

pub struct CoreTraceFragmentGenerator {
    fragment_start_clk: RowIndex,
    fragment: CoreTraceFragment,
    state: CoreTraceState,
    span_context: Option<SpanContext>,
}

impl CoreTraceFragmentGenerator {
    /// Creates a new CoreTraceFragmentGenerator with the provided checkpoint.
    pub fn new(state: CoreTraceState) -> Self {
        Self {
            fragment_start_clk: state.system.clk,
            // Safety: the `CoreTraceFragmentGenerator` will fill in all the rows, or truncate any
            // unused rows if a `HALT` operation occurs before `NUM_ROWS_PER_FRAGMENT` have been
            // executed.
            fragment: unsafe {
                CoreTraceFragment::new_uninit(CoreTraceFragmentManager::NUM_ROWS_PER_FRAGMENT)
            },
            state,
            span_context: None,
        }
    }

    /// Processes a single checkpoint into a CoreTraceFragment
    pub fn generate_fragment(
        mut self,
        program: &MastForest,
        execution_phase: NodeExecutionPhase,
    ) -> CoreTraceFragment {
        // Execute fragment generation and always finalize at the end
        let _ = self.execute_fragment_generation(program, execution_phase);
        self.finalize_fragment()
    }

    /// Internal method that performs fragment generation with automatic early returns
    fn execute_fragment_generation(
        &mut self,
        program: &MastForest,
        execution_phase: NodeExecutionPhase,
    ) -> ControlFlow<()> {
        match execution_phase {
            NodeExecutionPhase::BasicBlock {
                batch_index,
                op_idx_in_batch,
                needs_respan,
            } => {
                // Finish running the current basic block from the specified batch and operation
                // index
                let node_id = self
                    .state
                    .traversal
                    .peek_current_node()
                    .expect("traversal should not be empty");
                let basic_block_node = {
                    let mast_node = program.get_node_by_id(node_id).expect("node should exist");
                    mast_node.get_basic_block().expect("Expected a basic block node")
                };

                let op_batches = basic_block_node.op_batches();
                assert!(
                    batch_index < op_batches.len(),
                    "Batch index out of bounds: {batch_index} >= {}",
                    op_batches.len()
                );

                // Initialize the span context for the current basic block
                self.span_context =
                    Some(initialize_span_context(basic_block_node, batch_index, op_idx_in_batch));

                // Insert RESPAN if needed
                if needs_respan {
                    assert_eq!(op_idx_in_batch, 0);
                    let current_batch = &op_batches[batch_index];
                    self.respan(current_batch)?;
                }

                // Execute remaining operations in the specified batch
                let current_batch = &op_batches[batch_index];
                if op_idx_in_batch < current_batch.ops().len() {
                    self.execute_op_batch(current_batch, Some(op_idx_in_batch))?;
                }

                // Execute remaining batches
                for op_batch in op_batches.iter().skip(batch_index + 1) {
                    self.respan(op_batch)?;

                    self.execute_op_batch(op_batch, None)?;
                }

                // Add END trace row to complete the basic block
                self.add_span_end_trace_row(basic_block_node)?;

                // Advance the traversal past the current basic block
                self.state.traversal.advance();
            },
            NodeExecutionPhase::Start => {
                // do nothing
            },
            NodeExecutionPhase::End => {
                // Handle END phase of control flow nodes
                // Add the appropriate end trace row based on the current node type
                if let Some(node_id) = self.state.traversal.peek_current_node() {
                    let mast_node = program.get_node_by_id(node_id).expect("node should exist");

                    match mast_node {
                        MastNode::Block(basic_block_node) => {
                            self.add_span_end_trace_row(basic_block_node)?;
                        },
                        MastNode::Join(join_node) => {
                            self.add_join_end_trace_row(join_node, program)?;
                        },
                        MastNode::Split(split_node) => {
                            self.add_split_end_trace_row(split_node, program)?;
                        },
                        MastNode::Loop(loop_node) => {
                            self.add_loop_end_trace_row(loop_node, program)?;
                        },
                        MastNode::Call(call_node) => {
                            self.add_call_end_trace_row(call_node, program)?;
                        },
                        MastNode::Dyn(dyn_node) => {
                            self.add_dyn_end_trace_row(dyn_node)?;
                        },
                        MastNode::External(_external_node) => {
                            // External nodes don't have their own end trace rows
                            // as they resolve to other nodes
                            // TODO(plafer): Should this be unreachable?
                        },
                    }

                    // Advance the traversal past the current node
                    self.state.traversal.advance();
                }
            },
        }

        while let Some(node_id) = self.state.traversal.peek_current_node() {
            // Execute the node - this will return early if fragment is complete
            self.execute_mast_node(node_id, program)?;

            // If we reach here, the node completed without filling the fragment
            self.state.traversal.advance();
        }

        // All nodes completed without filling the fragment
        ControlFlow::Continue(())
    }

    fn execute_mast_node(&mut self, node_id: MastNodeId, program: &MastForest) -> ControlFlow<()> {
        let mast_node = program.get_node_by_id(node_id).expect("node should exist");

        // Set the address of the new block
        let addr = self.state.hasher.replay_block_address();

        match mast_node {
            MastNode::Block(basic_block_node) => {
                // Clone the basic_block_node to avoid borrowing issues
                let basic_block_node = basic_block_node.clone();

                // Push block onto block stack and get parent address
                let parent_addr = self.state.block_stack.push(addr, BlockType::Span, None);
                let num_groups_left_in_block = Felt::from(basic_block_node.num_op_groups() as u32);
                let first_op_batch = basic_block_node
                    .op_batches()
                    .first()
                    .expect("Basic block should have at least one op batch");

                // 1. Add SPAN start trace row
                self.add_span_start_trace_row(
                    first_op_batch,
                    num_groups_left_in_block,
                    parent_addr,
                )?;

                // Initialize the span context for the current basic block. After SPAN operation is
                // executed, we decrement the number of remaining groups by 1 because executing
                // SPAN consumes the first group of the batch.
                // TODO(plafer): use `initialize_span_context` once the potential off-by-one issue
                // is resolved.
                self.span_context = Some(SpanContext {
                    group_ops_left: Felt::from(basic_block_node.num_op_groups() as u32 - 1_u32),
                    num_groups_left: first_op_batch.groups()[0],
                });

                // 2. Execute batches one by one
                let op_batches = basic_block_node.op_batches();

                // Execute first op batch
                {
                    let first_op_batch =
                        op_batches.first().expect("Basic block should have at least one op batch");
                    self.execute_op_batch(first_op_batch, None)?;
                }

                // Execute the rest of the op batches
                for op_batch in op_batches.iter().skip(1) {
                    // 3. Add RESPAN trace row between batches
                    self.respan(op_batch)?;

                    self.execute_op_batch(op_batch, None)?;
                }

                // 4. Add END trace row
                self.add_span_end_trace_row(&basic_block_node)?;

                ControlFlow::Continue(())
            },
            MastNode::Join(join_node) => {
                let parent_addr = self.state.block_stack.push(addr, BlockType::Join(false), None);

                // 1. Add "start JOIN" row
                self.add_join_start_trace_row(join_node, program, parent_addr)?;

                // 2. Execute first child
                self.execute_mast_node(join_node.first(), program)?;

                // 3. Execute second child
                self.execute_mast_node(join_node.second(), program)?;

                // 4. Add "end JOIN" row
                self.add_join_end_trace_row(join_node, program)
            },
            MastNode::Split(split_node) => {
                let parent_addr = self.state.block_stack.push(addr, BlockType::Split, None);

                // 1. Add "start SPLIT" row
                self.add_split_start_trace_row(split_node, program, parent_addr)?;

                // 2. Execute the appropriate branch based on the stack top value
                let condition = self.stack_get(0);
                if condition == ONE {
                    self.execute_mast_node(split_node.on_true(), program)?;
                } else {
                    self.execute_mast_node(split_node.on_false(), program)?;
                }

                // 3. Add "end SPLIT" row
                self.add_split_end_trace_row(split_node, program)
            },
            MastNode::Loop(loop_node) => {
                let parent_addr = {
                    let enter_loop = self.stack_get(0) == ONE;
                    self.state.block_stack.push(addr, BlockType::Loop(enter_loop), None)
                };

                // 1. Add "start LOOP" row
                self.add_loop_start_trace_row(loop_node, program, parent_addr)?;

                // 2. In parallel execution, we simulate executing the loop body once
                // based on the current stack top value
                let condition = self.stack_get(0);
                if condition == miden_core::ONE {
                    // Note: In the refactored version, we don't directly modify stack depth
                    // as it's derived from the overflow table. The stack manipulation would
                    // be handled by proper stack operations in a full implementation.

                    // Execute loop body (in real execution this would be in a while loop)
                    self.execute_mast_node(loop_node.body(), program)?;

                    // Note: In a real implementation, the loop would continue until the condition
                    // becomes false. For parallel analysis, we simulate one iteration.
                }

                // 3. Add "end LOOP" row
                self.add_loop_end_trace_row(loop_node, program)
            },
            MastNode::Call(call_node) => {
                let (stack_depth, next_overflow_addr) = self.state.stack.start_context();
                let ctx_info = ExecutionContextInfo::new(
                    self.state.system.ctx,
                    self.state.system.fn_hash,
                    self.state.system.fmp,
                    stack_depth as u32,
                    next_overflow_addr,
                );

                let parent_addr = if call_node.is_syscall() {
                    self.state.block_stack.push(addr, BlockType::SysCall, Some(ctx_info))
                } else {
                    self.state.block_stack.push(addr, BlockType::Call, Some(ctx_info))
                };

                // 1. Add "start CALL/SYSCALL" row
                self.add_call_start_trace_row(call_node, program, parent_addr)?;

                // Save current context state if needed
                let saved_ctx = self.state.system.ctx;
                let saved_fmp = self.state.system.fmp;
                let saved_in_syscall = self.state.system.in_syscall;

                // Set up new context for the call
                if call_node.is_syscall() {
                    self.state.system.ctx = ContextId::root(); // Root context for syscalls
                    self.state.system.fmp = Felt::new(SYSCALL_FMP_MIN as u64);
                    self.state.system.in_syscall = true;
                } else {
                    self.state.system.ctx = ContextId::from(self.state.system.clk); // New context ID
                    self.state.system.fmp = Felt::new(FMP_MIN);
                }

                // Execute the callee
                self.execute_mast_node(call_node.callee(), program)?;

                // Restore context state
                self.state.system.ctx = saved_ctx;
                self.state.system.fmp = saved_fmp;
                self.state.system.in_syscall = saved_in_syscall;

                // 2. Add "end CALL/SYSCALL" row
                self.add_call_end_trace_row(call_node, program)
            },
            MastNode::Dyn(dyn_node) => {
                let parent_addr = if dyn_node.is_dyncall() {
                    let (stack_depth, next_overflow_addr) =
                        self.state.stack.shift_left_and_start_context();
                    // For DYNCALL, we need to save the current context state
                    // and prepare for dynamic execution
                    let ctx_info = ExecutionContextInfo::new(
                        self.state.system.ctx,
                        self.state.system.fn_hash,
                        self.state.system.fmp,
                        stack_depth as u32,
                        next_overflow_addr,
                    );
                    self.state.block_stack.push(addr, BlockType::Dyncall, Some(ctx_info))
                } else {
                    // For DYN, we just push the block stack without context info
                    self.state.block_stack.push(addr, BlockType::Dyn, None)
                };

                // 1. Add "start DYN/DYNCALL" row
                self.add_dyn_start_trace_row(dyn_node, parent_addr)?;

                // In parallel execution, we can't resolve dynamic calls at compile time
                // So we'll simulate minimal overhead and skip the actual execution
                // This is a limitation of parallel analysis - dynamic behavior requires runtime
                // information to determine the actual callee

                // For DYNCALL, we would save/restore context like in Call nodes, but since
                // we can't execute the dynamic target, we skip the context manipulation
                if dyn_node.is_dyncall() {
                    // Simulate context save/restore overhead without actual execution
                    // The actual dynamic target resolution happens at runtime
                }

                // 2. Add "end DYN/DYNCALL" row
                self.add_dyn_end_trace_row(dyn_node)
            },
            MastNode::External(_external_node) => {
                // Use the ExternalNodeReplay to get the resolved node ID and its forest
                let (resolved_node_id, resolved_forest) =
                    self.state.external_node_replay.replay_resolution();

                // Push the new forest onto the traversal stack with the resolved node
                self.state
                    .traversal
                    .push_forest_with_node(resolved_forest.clone(), resolved_node_id);

                // Execute the resolved node within the new forest context
                let result = self.execute_mast_node(resolved_node_id, &resolved_forest);

                // Pop the external forest when done (the call stack should be empty after
                // execution)
                self.state.traversal.pop_forest();

                result
            },
        }
    }

    /// Executes operations within an operation batch, analogous to FastProcessor::execute_op_batch.
    ///
    /// If `start_op_idx` is provided, execution begins from that operation index within the batch.
    fn execute_op_batch(
        &mut self,
        batch: &OpBatch,
        start_op_idx: Option<usize>,
    ) -> ControlFlow<()> {
        let op_counts = batch.op_counts();
        let mut op_idx_in_group = 0;
        let mut group_idx = 0;
        let mut next_group_idx = 1;
        let start_op_idx = start_op_idx.unwrap_or(0);

        // Find which group and position within group corresponds to start_op_idx
        if start_op_idx > 0 {
            let mut ops_processed = 0;
            for (idx, &count) in op_counts.iter().enumerate() {
                if ops_processed + count > start_op_idx {
                    group_idx = idx;
                    op_idx_in_group = start_op_idx - ops_processed;
                    break;
                }
                ops_processed += count;
                if idx < op_counts.len() - 1 {
                    next_group_idx = idx + 2; // Account for immediate values taking up group slots
                }
            }
        }

        // Round up the number of groups to be processed to the next power of two
        let num_batch_groups = batch.num_groups().next_power_of_two();

        // Execute operations in the batch starting from start_op_idx
        for &op in batch.ops().iter().skip(start_op_idx) {
            // Execute the operation and check if we're done generating
            self.execute_op(op, op_idx_in_group)?;

            // Handle immediate value operations
            let has_imm = op.imm_value().is_some();
            if has_imm {
                next_group_idx += 1;
            }

            // Determine if we've executed all operations in a group
            if op_idx_in_group == op_counts[group_idx] - 1 {
                // If operation has immediate value, execute NOOP after it
                if has_imm {
                    debug_assert!(op_idx_in_group < OP_GROUP_SIZE - 1, "invalid op index");
                    self.increment_clk()?;
                    self.execute_op(Operation::Noop, op_idx_in_group + 1)?;
                }

                // Move to next group and reset operation index
                group_idx = next_group_idx;
                next_group_idx += 1;
                op_idx_in_group = 0;

                // if we haven't reached the end of the batch yet, set up the decoder for
                // decoding the next operation group
                if group_idx < num_batch_groups - 1 {
                    self.start_op_group(batch.groups()[group_idx]);
                }
            } else {
                op_idx_in_group += 1;
            }
        }

        // Execute required number of operation groups (handle padding with NOOPs)
        for group_idx in group_idx..num_batch_groups {
            self.execute_op(Operation::Noop, 0)?;

            // if we are not at the last group yet, set up the decoder for decoding the next
            // operation groups. the groups were are processing are just NOOPs - so, the op group
            // value is ZERO
            if group_idx < num_batch_groups - 1 {
                self.start_op_group(ZERO);
            }
        }

        ControlFlow::Continue(())
    }

    /// Starts decoding a new operation group.
    pub fn start_op_group(&mut self, op_group: Felt) {
        let ctx = self.span_context.as_mut().expect("not in span");

        // reset the current group value and decrement the number of left groups by ONE
        debug_assert_eq!(ZERO, ctx.group_ops_left, "not all ops executed in current group");
        ctx.group_ops_left = op_group;
        ctx.num_groups_left -= ONE;
    }

    /// Executes a single operation, similar to Process::execute_op.
    ///
    /// This implementation executes the operation by updating the state and recording
    /// any memory or advice provider operations for parallel trace generation.
    fn execute_op(&mut self, op: Operation, op_idx_in_group: usize) -> ControlFlow<()> {
        // Execute the operation by dispatching to appropriate operation methods
        let user_op_helpers = self.dispatch_operation(&op);

        // write the operation to the trace
        self.add_operation_trace_row(op, op_idx_in_group, user_op_helpers)
    }

    /// Dispatches the operation to the appropriate execution method.
    fn dispatch_operation(&mut self, op: &Operation) -> Option<[Felt; NUM_USER_OP_HELPERS]> {
        use miden_core::Operation;

        let mut user_op_helpers = None;
        let err_ctx = ();

        match op {
            // ----- system operations ------------------------------------------------------------
            Operation::Noop => {
                // do nothing
            },
            Operation::Assert(_err_code) => self.op_assert(),
            Operation::FmpAdd => self.op_fmpadd(),
            Operation::FmpUpdate => self.op_fmpupdate().expect("FMP update should not fail"),
            Operation::SDepth => self.op_sdepth(),
            Operation::Caller => self.op_caller().expect("Caller operation should not fail"),
            Operation::Clk => self.op_clk(),
            Operation::Emit(_) => {
                // do nothing
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
            Operation::Add => self.op_add(),
            Operation::Neg => self.op_neg(),
            Operation::Mul => self.op_mul(),
            Operation::Inv => self.op_inv(&err_ctx).expect("Inverse operation should not fail"),
            Operation::Incr => self.op_incr(),
            Operation::And => self.op_and(&err_ctx).expect("And operation should not fail"),
            Operation::Or => self.op_or(&err_ctx).expect("Or operation should not fail"),
            Operation::Not => self.op_not(&err_ctx).expect("Not operation should not fail"),
            Operation::Eq => self.op_eq(),
            Operation::Eqz => self.op_eqz(),
            Operation::Expacc => self.op_expacc(),

            // ----- ext2 operations --------------------------------------------------------------
            Operation::Ext2Mul => self.op_ext2mul(),

            // ----- u32 operations ---------------------------------------------------------------
            Operation::U32split => self.op_u32split(),
            Operation::U32add => {
                self.op_u32add(&err_ctx).expect("U32 add operation should not fail")
            },
            Operation::U32add3 => {
                self.op_u32add3(&err_ctx).expect("U32 add3 operation should not fail")
            },
            // Note: the `op_idx_in_block` argument is just in case of error, so we set it to 0
            Operation::U32sub => {
                self.op_u32sub(0, &err_ctx).expect("U32 sub operation should not fail")
            },
            Operation::U32mul => {
                self.op_u32mul(&err_ctx).expect("U32 mul operation should not fail")
            },
            Operation::U32madd => {
                self.op_u32madd(&err_ctx).expect("U32 madd operation should not fail")
            },
            Operation::U32div => {
                self.op_u32div(&err_ctx).expect("U32 div operation should not fail")
            },
            Operation::U32and => {
                self.op_u32and(&err_ctx).expect("U32 and operation should not fail")
            },
            Operation::U32xor => {
                self.op_u32xor(&err_ctx).expect("U32 xor operation should not fail")
            },
            Operation::U32assert2(err_code) => self
                .op_u32assert2(*err_code, &err_ctx)
                .expect("U32 assert2 operation should not fail"),

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
            Operation::CSwap => self.op_cswap(&err_ctx).expect("CSwap operation should not fail"),
            Operation::CSwapW => {
                self.op_cswapw(&err_ctx).expect("CSwapW operation should not fail")
            },

            // ----- input / output ---------------------------------------------------------------
            Operation::Push(value) => self.op_push(*value),
            Operation::AdvPop => self.op_advpop(),
            Operation::AdvPopW => self.op_advpopw(),
            Operation::MLoadW => self.op_mloadw(),
            Operation::MStoreW => self.op_mstorew(),
            Operation::MLoad => self.op_mload(),
            Operation::MStore => self.op_mstore(),
            Operation::MStream => self.op_mstream(),
            Operation::Pipe => self.op_pipe(),

            // ----- cryptographic operations -----------------------------------------------------
            Operation::HPerm => {
                let hperm_helpers = self.op_hperm();
                user_op_helpers = Some(hperm_helpers);
            },
            Operation::MpVerify(_err_code) => {
                let mpverify_helpers = self.op_mpverify();
                user_op_helpers = Some(mpverify_helpers);
            },
            Operation::MrUpdate => {
                let mrupdate_helpers = self.op_mrupdate();
                user_op_helpers = Some(mrupdate_helpers);
            },
            Operation::FriE2F4 => {
                let frie2f4_helpers =
                    self.op_fri_ext2fold4().expect("FriE2F4 operation should not fail");
                user_op_helpers = Some(frie2f4_helpers);
            },
            Operation::HornerBase => {
                let horner_base_helpers = self.op_horner_eval_base();
                user_op_helpers = Some(horner_base_helpers);
            },
            Operation::HornerExt => {
                let horner_ext_helpers = self.op_horner_eval_ext();
                user_op_helpers = Some(horner_ext_helpers);
            },
            Operation::ArithmeticCircuitEval => {
                // do nothing
            },
        }

        user_op_helpers
    }

    fn finalize_fragment(mut self) -> CoreTraceFragment {
        // If we have not built enough rows, we need to truncate the fragment. Similarly, in the
        // rare case where we built too many rows, we truncate to the correct number of rows (i.e.
        // NUM_ROWS_PER_FRAGMENT).
        {
            let num_rows = core::cmp::min(
                self.num_rows_built(),
                CoreTraceFragmentManager::NUM_ROWS_PER_FRAGMENT,
            );
            for column in &mut self.fragment.columns {
                column.truncate(num_rows);
            }
        }

        self.fragment
    }

    // HELPERS
    // -------------------------------------------------------------------------------------------

    fn append_opcode(&mut self, opcode: u8, row_idx: usize) {
        use miden_air::trace::{
            DECODER_TRACE_OFFSET,
            decoder::{NUM_OP_BITS, OP_BITS_OFFSET},
        };

        // Append the opcode bits to the trace row
        for i in 0..NUM_OP_BITS {
            let bit = Felt::from((opcode >> i) & 1);
            self.fragment.columns[DECODER_TRACE_OFFSET + OP_BITS_OFFSET + i][row_idx] = bit;
        }
    }

    fn done_generating(&mut self) -> bool {
        // If we have built all the rows in the fragment, we are done
        self.num_rows_built() >= CoreTraceFragmentManager::NUM_ROWS_PER_FRAGMENT
    }

    fn num_rows_built(&self) -> usize {
        // Returns the number of rows built so far in the fragment
        self.state.system.clk - self.fragment_start_clk
    }

    fn increment_clk(&mut self) -> ControlFlow<()> {
        self.state.system.clk += 1u32;

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

// HELPERS
// ===============================================================================================

fn initialize_span_context(
    basic_block_node: &BasicBlockNode,
    batch_index: usize,
    op_idx_in_batch: usize,
) -> SpanContext {
    let op_batches = basic_block_node.op_batches();
    let current_op_group_idx = get_current_op_group_idx(&op_batches[batch_index], op_idx_in_batch);

    let group_ops_left = {
        let current_op_group = op_batches[batch_index].groups()[current_op_group_idx];

        // shift out all operations that are already executed in this group
        Felt::new(current_op_group.as_int() >> (NUM_OP_BITS * op_idx_in_batch))
    };

    // TODO(plafer): double check that this isn't off-by-one (how after the first SPAN, we decrement
    // by 1)
    let num_groups_left = {
        let total_groups = basic_block_node.num_op_groups();

        // Count groups consumed by completed batches (all batches before current one)
        let mut groups_consumed = 0;
        for op_batch in op_batches.iter().take(batch_index) {
            groups_consumed += op_batch.num_groups();
        }

        // Count groups consumed within the current batch up to op_idx_in_batch
        let current_batch = &op_batches[batch_index];

        // Add the number of complete groups before the current group in this batch
        groups_consumed += current_op_group_idx;

        // Count immediate values consumed by executed operations
        for op in current_batch.ops().iter().take(op_idx_in_batch) {
            if op.imm_value().is_some() {
                groups_consumed += 1; // immediate values consume an additional group slot
            }
        }

        Felt::from((total_groups - groups_consumed) as u32)
    };

    SpanContext { group_ops_left, num_groups_left }
}

/// Returns the index of the current operation group in the batch based on the operation index
/// within the batch.
fn get_current_op_group_idx(op_batch: &OpBatch, op_idx_in_batch: usize) -> usize {
    // Find the group index for the given operation index
    let mut ops_processed = 0;
    for (group_idx, &num_ops_in_group) in op_batch.op_counts().iter().enumerate() {
        if ops_processed + num_ops_in_group > op_idx_in_batch {
            return group_idx;
        }
        ops_processed += num_ops_in_group;
    }

    panic!("operation index {op_idx_in_batch} exceeds batch size");
}

// REQUIRED METHODS
// ===============================================================================================

impl Processor for CoreTraceFragmentGenerator {
    fn caller_hash(&self) -> Word {
        self.state.system.fn_hash
    }

    fn in_syscall(&self) -> bool {
        self.state.system.in_syscall
    }

    fn clk(&self) -> RowIndex {
        self.state.system.clk
    }

    fn fmp(&self) -> Felt {
        self.state.system.fmp
    }

    fn set_fmp(&mut self, new_fmp: Felt) {
        self.state.system.fmp = new_fmp;
    }

    fn stack_top(&self) -> &[Felt] {
        &self.state.stack.stack_top
    }

    fn stack_get(&self, idx: usize) -> Felt {
        debug_assert!(idx < MIN_STACK_DEPTH);
        self.state.stack.stack_top[MIN_STACK_DEPTH - idx - 1]
    }

    fn stack_get_mut(&mut self, idx: usize) -> &mut Felt {
        debug_assert!(idx < MIN_STACK_DEPTH);

        &mut self.state.stack.stack_top[MIN_STACK_DEPTH - idx - 1]
    }

    fn stack_get_word(&self, start_idx: usize) -> Word {
        debug_assert!(start_idx < MIN_STACK_DEPTH - 4);

        let word_start_idx = start_idx - 4;
        self.stack_top()[range(word_start_idx, WORD_SIZE)].try_into().unwrap()
    }

    fn stack_depth(&self) -> u32 {
        (MIN_STACK_DEPTH + self.state.stack.overflow.num_elements_in_current_ctx()) as u32
    }

    fn stack_write(&mut self, idx: usize, element: Felt) {
        *self.stack_get_mut(idx) = element;
    }

    fn stack_write_word(&mut self, start_idx: usize, word: &Word) {
        debug_assert!(start_idx < MIN_STACK_DEPTH - 4);
        let word_start_idx = start_idx - 4;

        let word_on_stack = &mut self.state.stack.stack_top[range(word_start_idx, WORD_SIZE)];
        word_on_stack.copy_from_slice(word.as_slice());
    }

    fn stack_swap(&mut self, idx1: usize, idx2: usize) {
        let a = self.stack_get(idx1);
        let b = self.stack_get(idx2);
        self.stack_write(idx1, b);
        self.stack_write(idx2, a);
    }

    // TODO(plafer): this is copy/pasted (almost) from the FastProcessor. Find a way to
    // properly abstract this out.
    fn swapw_nth(&mut self, n: usize) {
        // For example, for n=3, the stack words and variables look like:
        //    3     2     1     0
        // | ... | ... | ... | ... |
        // ^                 ^
        // nth_word       top_word
        let (rest_of_stack, top_word) =
            self.state.stack.stack_top.split_at_mut(MIN_STACK_DEPTH - WORD_SIZE);
        let (_, nth_word) = rest_of_stack.split_at_mut(rest_of_stack.len() - n * WORD_SIZE);

        nth_word[0..WORD_SIZE].swap_with_slice(&mut top_word[0..WORD_SIZE]);
    }

    // TODO(plafer): this is copy/pasted (almost) from the FastProcessor
    fn rotate_left(&mut self, n: usize) {
        let rotation_bot_index = MIN_STACK_DEPTH - n;
        let new_stack_top_element = self.state.stack.stack_top[rotation_bot_index];

        // shift the top n elements down by 1, starting from the bottom of the rotation.
        for i in 0..n - 1 {
            self.state.stack.stack_top[rotation_bot_index + i] =
                self.state.stack.stack_top[rotation_bot_index + i + 1];
        }

        // Set the top element (which comes from the bottom of the rotation).
        self.stack_write(0, new_stack_top_element);
    }

    // TODO(plafer): this is copy/pasted (almost) from the FastProcessor
    fn rotate_right(&mut self, n: usize) {
        let rotation_bot_index = MIN_STACK_DEPTH - n;
        let new_stack_bot_element = self.state.stack.stack_top[MIN_STACK_DEPTH - 1];

        // shift the top n elements up by 1, starting from the top of the rotation.
        for i in 1..n {
            self.state.stack.stack_top[MIN_STACK_DEPTH - i] =
                self.state.stack.stack_top[MIN_STACK_DEPTH - i - 1];
        }

        // Set the bot element (which comes from the top of the rotation).
        self.state.stack.stack_top[rotation_bot_index] = new_stack_bot_element;
    }

    fn increment_stack_size(&mut self) {
        const SENTINEL_VALUE: Felt = Felt::new(Felt::MODULUS - 1);

        // push the last element on the overflow table
        {
            let last_element = self.stack_get(MIN_STACK_DEPTH - 1);
            self.state.stack.overflow.push(last_element);
        }

        // Shift all other elements down
        for write_idx in (1..MIN_STACK_DEPTH).rev() {
            let read_idx = write_idx - 1;
            self.stack_write(write_idx, self.stack_get(read_idx));
        }

        // Set the top element to SENTINEL_VALUE to help in debugging. Per the method docs, this
        // value will be overwritten
        self.stack_write(0, SENTINEL_VALUE);
    }

    fn decrement_stack_size(&mut self) {
        // Shift all other elements up
        for write_idx in 0..(MIN_STACK_DEPTH - 1) {
            let read_idx = write_idx + 1;
            self.stack_write(write_idx, self.stack_get(read_idx));
        }

        // Pop the last element from the overflow table
        if let Some(last_element) = self.state.stack.overflow.pop() {
            // Write the last element to the bottom of the stack
            self.stack_write(MIN_STACK_DEPTH - 1, last_element);
        } else {
            // If overflow table is empty, set the bottom element to zero
            self.stack_write(MIN_STACK_DEPTH - 1, ZERO);
        }
    }
}
