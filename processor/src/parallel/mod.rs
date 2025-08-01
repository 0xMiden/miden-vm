use alloc::{boxed::Box, vec::Vec};
use core::{mem::MaybeUninit, ops::ControlFlow};

use miden_air::{
    RowIndex,
    trace::{
        CHIPLETS_RANGE, CLK_COL_IDX, CTX_COL_IDX, DECODER_TRACE_OFFSET, DECODER_TRACE_WIDTH,
        FMP_COL_IDX, FN_HASH_RANGE, IN_SYSCALL_COL_IDX, MIN_TRACE_LEN, RANGE_CHECK_AUX_TRACE_RANGE,
        RANGE_CHECK_TRACE_WIDTH, STACK_TRACE_OFFSET, STACK_TRACE_WIDTH, SYS_TRACE_WIDTH,
        TRACE_WIDTH,
        decoder::{
            ADDR_COL_IDX, GROUP_COUNT_COL_IDX, HASHER_STATE_OFFSET, IN_SPAN_COL_IDX,
            NUM_HASHER_COLUMNS, NUM_OP_BATCH_FLAGS, NUM_OP_BITS, NUM_USER_OP_HELPERS,
            OP_BATCH_FLAGS_OFFSET, OP_BITS_EXTRA_COLS_OFFSET, OP_BITS_OFFSET, OP_INDEX_COL_IDX,
        },
        main_trace::MainTrace,
    },
};
use miden_core::{
    Felt, ONE, Operation, StarkField, WORD_SIZE, Word, ZERO,
    mast::{BasicBlockNode, MastForest, MastNode, MastNodeId, OP_GROUP_SIZE, OpBatch},
    stack::MIN_STACK_DEPTH,
    utils::{range, uninit_vector},
};
use rayon::prelude::*;
use winter_prover::crypto::RandomCoin;

use crate::{
    ColMatrix, ContextId,
    continuation_stack::Continuation,
    crypto::RpoRandomCoin,
    decoder::{
        SpanContext,
        block_stack::{BlockType, ExecutionContextInfo},
    },
    fast::{
        NUM_ROWS_PER_CORE_FRAGMENT,
        checkpoints::{CoreTraceState, NodeExecutionPhase},
    },
    processor::Processor,
    system::{FMP_MIN, SYSCALL_FMP_MIN},
    trace::NUM_RAND_ROWS,
};

pub const CORE_TRACE_WIDTH: usize = SYS_TRACE_WIDTH + DECODER_TRACE_WIDTH + STACK_TRACE_WIDTH;

mod basic_block;
mod call;
mod r#dyn;
mod join;
mod r#loop;
mod operations;

mod split;
mod trace_builder;

// BUILD TRACE
// ================================================================================================

/// Builds the main trace from the provided trace states in parallel.
pub fn build_trace(trace_states: Vec<CoreTraceState>, program_hash: Word) -> MainTrace {
    // Build the core trace fragments in parallel
    let fragments: Vec<CoreTraceFragment> = trace_states
        .into_par_iter()
        .map(|trace_state| {
            let main_trace_generator = CoreTraceFragmentGenerator::new(trace_state);
            main_trace_generator.generate_fragment()
        })
        .collect();

    // Combine fragments into a single trace
    combine_fragments(fragments, program_hash)
}

/// Combines multiple CoreTraceFragments into a single MainTrace
fn combine_fragments(fragments: Vec<CoreTraceFragment>, program_hash: Word) -> MainTrace {
    if fragments.is_empty() {
        panic!("Cannot combine empty fragments vector");
    }

    // Calculate total number of rows from fragments
    let total_program_rows: usize = fragments.iter().map(|f| f.row_count()).sum();

    // Pad the trace length to the next power of two and ensure that there is space for random
    // rows (or at least the minimum trace length)
    let trace_len =
        core::cmp::max((total_program_rows + NUM_RAND_ROWS).next_power_of_two(), MIN_TRACE_LEN);

    // Find the last program row (last row of the last fragment)
    let last_program_row = if let Some(_last_fragment) = fragments.last() {
        RowIndex::from((total_program_rows as u32).saturating_sub(1))
    } else {
        RowIndex::from(0u32)
    };

    // Initialize columns for the full trace using uninitialized memory
    let mut trace_columns: Vec<Box<[MaybeUninit<Felt>]>> =
        (0..TRACE_WIDTH).map(|_| Box::new_uninit_slice(trace_len)).collect();

    // Copy core trace columns from fragments
    let mut current_row_idx = 0;
    for fragment in fragments {
        let fragment_rows = fragment.row_count();

        for local_row_idx in 0..fragment_rows {
            let global_row_idx = current_row_idx + local_row_idx;

            // Copy core trace columns (system, decoder, stack)
            for (col_idx, trace_column) in
                trace_columns.iter_mut().enumerate().take(CORE_TRACE_WIDTH)
            {
                trace_column[global_row_idx].write(fragment.columns[col_idx][local_row_idx]);
            }

            // Add zeros for range check columns
            for trace_column in
                trace_columns.iter_mut().skip(CORE_TRACE_WIDTH).take(RANGE_CHECK_TRACE_WIDTH)
            {
                trace_column[global_row_idx].write(ZERO);
            }

            // Add zeros for chiplets columns
            for col_idx in CHIPLETS_RANGE {
                trace_columns[col_idx][global_row_idx].write(ZERO);
            }
        }

        current_row_idx += fragment_rows;
    }

    // Pad the remaining rows (between total_program_rows and trace_len)
    pad_trace_columns(&mut trace_columns, total_program_rows, trace_len);

    // Convert uninitialized columns to initialized Vec<Felt>
    let mut trace_columns: Vec<Vec<Felt>> = trace_columns
        .into_iter()
        .map(|uninit_column| {
            // Safety: All elements have been initialized through MaybeUninit::write()
            let init_column = unsafe { uninit_column.assume_init() };
            Vec::from(init_column)
        })
        .collect();

    // Inject random values into the last NUM_RAND_ROWS rows of core trace columns only
    // Use program hash to initialize random element generator
    let mut rng = RpoRandomCoin::new(program_hash);

    for i in trace_len - NUM_RAND_ROWS..trace_len {
        for column in trace_columns.iter_mut().take(CORE_TRACE_WIDTH) {
            column[i] = rng.draw().expect("failed to draw a random value");
        }
    }

    // Create the MainTrace
    let col_matrix = ColMatrix::new(trace_columns);
    MainTrace::new(col_matrix, last_program_row)
}

/// Pads the trace columns from `total_program_rows` rows to `trace_len` rows.
///
/// # Safety
/// - This function assumes that the first `total_program_rows` rows of the trace columns are
///   already initialized.
///
/// # Panics
/// - If `total_program_rows` is zero.
/// - If `total_program_rows + NUM_RAND_ROWS > trace_len`.
fn pad_trace_columns(
    trace_columns: &mut [Box<[MaybeUninit<Felt>]>],
    total_program_rows: usize,
    trace_len: usize,
) {
    // TODO(plafer): parallelize this function
    assert_ne!(total_program_rows, 0);
    assert!(total_program_rows + NUM_RAND_ROWS <= trace_len);

    // System columns
    // ------------------------

    // Pad CLK trace - fill with index values
    for (clk_val, clk_row) in
        trace_columns[CLK_COL_IDX].iter_mut().enumerate().skip(total_program_rows)
    {
        clk_row.write(Felt::from(clk_val as u32));
    }

    // Pad FMP trace - fill with the last value in the column

    // Safety: per our documented safety guarantees, we know that `total_program_rows > 0`, and row
    // `total_program_rows - 1` is initialized.
    let last_fmp_value =
        unsafe { trace_columns[FMP_COL_IDX][total_program_rows - 1].assume_init() };
    for fmp_row in trace_columns[FMP_COL_IDX].iter_mut().skip(total_program_rows) {
        fmp_row.write(last_fmp_value);
    }

    // Pad CTX trace - fill with ZEROs (root context)
    for ctx_row in trace_columns[CTX_COL_IDX].iter_mut().skip(total_program_rows) {
        ctx_row.write(ZERO);
    }

    // Pad IN_SYSCALL trace - fill with ZEROs (not in syscall)
    for in_syscall_row in trace_columns[IN_SYSCALL_COL_IDX].iter_mut().skip(total_program_rows) {
        in_syscall_row.write(ZERO);
    }

    // Pad FN_HASH traces (4 columns) - fill with ZEROs as program execution must always end in the
    // root context.
    for fn_hash_col_idx in FN_HASH_RANGE {
        for fn_hash_row in trace_columns[fn_hash_col_idx].iter_mut().skip(total_program_rows) {
            fn_hash_row.write(ZERO);
        }
    }

    // Decoder columns
    // ------------------------

    // Pad addr trace (decoder block address column) with ZEROs
    for addr_row in trace_columns[DECODER_TRACE_OFFSET + ADDR_COL_IDX]
        .iter_mut()
        .skip(total_program_rows)
    {
        addr_row.write(ZERO);
    }

    // Pad op_bits columns with HALT opcode bits
    let halt_opcode = Operation::Halt.op_code();
    for i in 0..NUM_OP_BITS {
        let bit_value = Felt::from((halt_opcode >> i) & 1);
        for op_bit_row in trace_columns[DECODER_TRACE_OFFSET + OP_BITS_OFFSET + i]
            .iter_mut()
            .skip(total_program_rows)
        {
            op_bit_row.write(bit_value);
        }
    }

    // Pad hasher state columns (8 columns)
    // - First 4 columns: copy the last value (to propagate program hash)
    // - Remaining 4 columns: fill with ZEROs
    for i in 0..NUM_HASHER_COLUMNS {
        let col_idx = DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + i;
        if i < 4 {
            // For first 4 hasher columns, copy the last value to propagate program hash
            // Safety: per our documented safety guarantees, we know that `total_program_rows > 0`,
            // and row `total_program_rows - 1` is initialized.
            let last_hasher_value =
                unsafe { trace_columns[col_idx][total_program_rows - 1].assume_init() };
            for hasher_row in trace_columns[col_idx].iter_mut().skip(total_program_rows) {
                hasher_row.write(last_hasher_value);
            }
        } else {
            // For remaining 4 hasher columns, fill with ZEROs
            for hasher_row in trace_columns[col_idx].iter_mut().skip(total_program_rows) {
                hasher_row.write(ZERO);
            }
        }
    }

    // Pad in_span column with ZEROs
    for in_span_row in trace_columns[DECODER_TRACE_OFFSET + IN_SPAN_COL_IDX]
        .iter_mut()
        .skip(total_program_rows)
    {
        in_span_row.write(ZERO);
    }

    // Pad group_count column with ZEROs
    for group_count_row in trace_columns[DECODER_TRACE_OFFSET + GROUP_COUNT_COL_IDX]
        .iter_mut()
        .skip(total_program_rows)
    {
        group_count_row.write(ZERO);
    }

    // Pad op_idx column with ZEROs
    for op_idx_row in trace_columns[DECODER_TRACE_OFFSET + OP_INDEX_COL_IDX]
        .iter_mut()
        .skip(total_program_rows)
    {
        op_idx_row.write(ZERO);
    }

    // Pad op_batch_flags columns (3 columns) with ZEROs
    for i in 0..NUM_OP_BATCH_FLAGS {
        let col_idx = DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET + i;
        for op_batch_flag_row in trace_columns[col_idx].iter_mut().skip(total_program_rows) {
            op_batch_flag_row.write(ZERO);
        }
    }

    // Pad op_bit_extra columns (2 columns)
    // - First column: fill with ZEROs (HALT doesn't use this)
    // - Second column: fill with ONEs (product of two most significant HALT bits, both are 1)
    for op_bit_extra_row in trace_columns[DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET]
        .iter_mut()
        .skip(total_program_rows)
    {
        op_bit_extra_row.write(ZERO);
    }
    for op_bit_extra_row in trace_columns[DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET + 1]
        .iter_mut()
        .skip(total_program_rows)
    {
        op_bit_extra_row.write(ONE);
    }

    // Stack columns
    // ------------------------

    // Pad stack columns with the last value in each column (analogous to Stack::into_trace())
    for i in 0..STACK_TRACE_WIDTH {
        let col_idx = STACK_TRACE_OFFSET + i;
        // Safety: per our documented safety guarantees, we know that `total_program_rows > 0`,
        // and row `total_program_rows - 1` is initialized.
        let last_stack_value =
            unsafe { trace_columns[col_idx][total_program_rows - 1].assume_init() };
        for stack_row in trace_columns[col_idx].iter_mut().skip(total_program_rows) {
            stack_row.write(last_stack_value);
        }
    }

    // Range checker and chiplets columns
    // ------------------------

    // Pad with ZEROs for now (still unimplemented)
    for row_idx in total_program_rows..trace_len {
        // Range checker columns
        for col_idx in RANGE_CHECK_AUX_TRACE_RANGE {
            trace_columns[col_idx][row_idx].write(ZERO);
        }

        // Chiplets columns
        for col_idx in CHIPLETS_RANGE {
            trace_columns[col_idx][row_idx].write(ZERO);
        }
    }
}

// TRACE ROW TYPE
// ================================================================================================

/// Enum to specify whether this is a start or end trace row for control block operations
/// (JOIN, SPLIT, LOOP, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceRowType {
    Start,
    End,
}

// CORE TRACE FRAGMENT
// ================================================================================================

/// The columns of the main trace fragment. These consist of the system, decoder, and stack columns.
///
/// A fragment is a collection of columns of length [NUM_ROWS_PER_CORE_FRAGMENT] or less. Only a
/// fragment containing a `HALT` operation is allowed to be shorter than
/// [NUM_ROWS_PER_CORE_FRAGMENT].
struct CoreTraceFragment {
    pub columns: [Vec<Felt>; CORE_TRACE_WIDTH],
}

impl CoreTraceFragment {
    /// Creates a new CoreTraceFragment with *uninitialized* columns of length `num_rows`.
    ///
    /// # Safety
    /// The caller is responsible for ensuring that the columns are properly initialized
    /// before use.
    pub unsafe fn new_uninit(num_rows: usize) -> Self {
        Self {
            // TODO(plafer): Don't use uninit_vector
            columns: core::array::from_fn(|_| unsafe { uninit_vector(num_rows) }),
        }
    }

    /// Returns the number of rows in this fragment
    pub fn row_count(&self) -> usize {
        self.columns[0].len()
    }
}

struct CoreTraceFragmentGenerator {
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
            // unused rows if a `HALT` operation occurs before `NUM_ROWS_PER_CORE_FRAGMENT` have
            // been executed.
            fragment: unsafe { CoreTraceFragment::new_uninit(NUM_ROWS_PER_CORE_FRAGMENT) },
            state,
            span_context: None,
        }
    }

    /// Processes a single checkpoint into a CoreTraceFragment
    pub fn generate_fragment(mut self) -> CoreTraceFragment {
        // Extract the execution phase from the state
        let execution_phase = self.state.exec_phase.clone();
        // Execute fragment generation and always finalize at the end
        let _ = self.execute_fragment_generation(execution_phase);
        self.finalize_fragment()
    }

    /// Internal method that performs fragment generation with automatic early returns
    fn execute_fragment_generation(
        &mut self,
        execution_phase: NodeExecutionPhase,
    ) -> ControlFlow<()> {
        let initial_mast_forest = self.state.initial_mast_forest.clone();

        // Finish the current node given its execution phase
        match execution_phase {
            NodeExecutionPhase::BasicBlock {
                node_id,
                batch_index,
                op_idx_in_batch,
                needs_respan,
            } => {
                let basic_block_node = {
                    let mast_node =
                        initial_mast_forest.get_node_by_id(node_id).expect("node should exist");
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
            },
            NodeExecutionPhase::Start(node_id) => {
                self.execute_mast_node(node_id, &initial_mast_forest)?;
            },
            NodeExecutionPhase::LoopRepeat(_node_id) => {
                // TODO(plafer): Implement loop repeat execution (as well as in the main loop)
                todo!()
            },
            NodeExecutionPhase::End(node_id) => {
                let mast_node =
                    initial_mast_forest.get_node_by_id(node_id).expect("node should exist");

                match mast_node {
                    MastNode::Join(join_node) => {
                        self.add_join_end_trace_row(join_node, &initial_mast_forest)?;
                    },
                    MastNode::Split(split_node) => {
                        self.add_split_end_trace_row(split_node, &initial_mast_forest)?;
                    },
                    MastNode::Loop(loop_node) => {
                        self.add_loop_end_trace_row(loop_node, &initial_mast_forest)?;
                    },
                    MastNode::Call(call_node) => {
                        self.add_call_end_trace_row(call_node, &initial_mast_forest)?;
                    },
                    MastNode::Dyn(dyn_node) => {
                        self.add_dyn_end_trace_row(dyn_node)?;
                    },
                    MastNode::Block(basic_block_node) => {
                        self.add_span_end_trace_row(basic_block_node)?;
                    },
                    MastNode::External(_external_node) => {
                        // External nodes don't generate trace rows directly, and hence will never
                        // show up in the END phase.
                        panic!("Unexpected external node in END phase")
                    },
                }
            },
        }

        // Start of main execution loop
        let mut current_forest = self.state.initial_mast_forest.clone();

        while let Some(continuation) = self.state.traversal.pop_continuation() {
            match continuation {
                Continuation::StartNode(node_id) => {
                    // Check if this is an external node first
                    let mast_node =
                        current_forest.get_node_by_id(node_id).expect("node should exist");
                    match mast_node {
                        MastNode::External(_external_node) => {
                            // Use the ExternalNodeReplay to get the resolved node ID and its forest
                            let (resolved_node_id, resolved_forest) =
                                self.state.external_node_replay.replay_resolution();

                            // Push an EnterForest continuation to restore the current forest when
                            // we're done
                            self.state.traversal.push_enter_forest(current_forest.clone());

                            // Switch to the resolved forest
                            current_forest = resolved_forest;

                            // Push the resolved node to be executed next
                            self.state.traversal.push_start_node(resolved_node_id);
                        },
                        _ => {
                            // Execute regular nodes - this will return early if fragment is
                            // complete
                            self.execute_mast_node(node_id, &current_forest)?;
                        },
                    }
                },
                Continuation::FinishJoin(node_id) => {
                    let mast_node =
                        current_forest.get_node_by_id(node_id).expect("node should exist");
                    self.add_join_end_trace_row(mast_node.unwrap_join(), &current_forest)?;
                },
                Continuation::FinishSplit(node_id) => {
                    let mast_node =
                        current_forest.get_node_by_id(node_id).expect("node should exist");
                    self.add_split_end_trace_row(mast_node.unwrap_split(), &current_forest)?;
                },
                Continuation::FinishLoop(node_id) => {
                    let mast_node =
                        current_forest.get_node_by_id(node_id).expect("node should exist");
                    self.add_loop_end_trace_row(mast_node.unwrap_loop(), &current_forest)?;
                },
                Continuation::FinishCall(node_id) => {
                    let mast_node =
                        current_forest.get_node_by_id(node_id).expect("node should exist");
                    self.add_call_end_trace_row(mast_node.unwrap_call(), &current_forest)?;
                },
                Continuation::FinishDyn(node_id) => {
                    let mast_node =
                        current_forest.get_node_by_id(node_id).expect("node should exist");
                    self.add_dyn_end_trace_row(mast_node.unwrap_dyn())?;
                },
                Continuation::EnterForest(previous_forest) => {
                    // Restore the previous forest
                    current_forest = previous_forest;
                },
            }
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
                    group_ops_left: first_op_batch.groups()[0],
                    num_groups_left: num_groups_left_in_block - ONE,
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
                // TODO(plafer): implement the actual loop, inserting REPEAT
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
            MastNode::External(_) => {
                // External nodes should be handled in the main execution loop, not here
                unreachable!("External nodes should be handled in execute_fragment_generation")
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
            Operation::EvalCircuit => {
                // do nothing
            },
        }

        user_op_helpers
    }

    fn finalize_fragment(mut self) -> CoreTraceFragment {
        // If we have not built enough rows, we need to truncate the fragment. Similarly, in the
        // rare case where we built too many rows, we truncate to the correct number of rows (i.e.
        // [NUM_ROWS_PER_CORE_FRAGMENT]).
        {
            let num_rows = core::cmp::min(self.num_rows_built(), NUM_ROWS_PER_CORE_FRAGMENT);
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
        self.num_rows_built() >= NUM_ROWS_PER_CORE_FRAGMENT
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

// TODO(plafer): Remove `Processor` trait? Or at least update it so it can be used by
// `FastProcessor`
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
        self.state.stack.stack_top()
    }

    fn stack_get(&self, idx: usize) -> Felt {
        debug_assert!(idx < MIN_STACK_DEPTH);
        self.state.stack.stack_top()[MIN_STACK_DEPTH - idx - 1]
    }

    fn stack_get_mut(&mut self, idx: usize) -> &mut Felt {
        debug_assert!(idx < MIN_STACK_DEPTH);

        &mut self.state.stack.stack_top_mut()[MIN_STACK_DEPTH - idx - 1]
    }

    fn stack_get_word(&self, start_idx: usize) -> Word {
        debug_assert!(start_idx < MIN_STACK_DEPTH - 4);

        let word_start_idx = start_idx - 4;
        self.stack_top()[range(word_start_idx, WORD_SIZE)].try_into().unwrap()
    }

    fn stack_depth(&self) -> u32 {
        (MIN_STACK_DEPTH + self.state.stack.num_overflow_elements_in_current_ctx()) as u32
    }

    fn stack_write(&mut self, idx: usize, element: Felt) {
        *self.stack_get_mut(idx) = element;
    }

    fn stack_write_word(&mut self, start_idx: usize, word: &Word) {
        debug_assert!(start_idx < MIN_STACK_DEPTH - 4);
        let word_start_idx = start_idx - 4;

        let word_on_stack = &mut self.state.stack.stack_top_mut()[range(word_start_idx, WORD_SIZE)];
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
            self.state.stack.stack_top_mut().split_at_mut(MIN_STACK_DEPTH - WORD_SIZE);
        let (_, nth_word) = rest_of_stack.split_at_mut(rest_of_stack.len() - n * WORD_SIZE);

        nth_word[0..WORD_SIZE].swap_with_slice(&mut top_word[0..WORD_SIZE]);
    }

    // TODO(plafer): this is copy/pasted (almost) from the FastProcessor
    fn rotate_left(&mut self, n: usize) {
        let rotation_bot_index = MIN_STACK_DEPTH - n;
        let new_stack_top_element = self.state.stack.stack_top()[rotation_bot_index];

        // shift the top n elements down by 1, starting from the bottom of the rotation.
        for i in 0..n - 1 {
            self.state.stack.stack_top_mut()[rotation_bot_index + i] =
                self.state.stack.stack_top()[rotation_bot_index + i + 1];
        }

        // Set the top element (which comes from the bottom of the rotation).
        self.stack_write(0, new_stack_top_element);
    }

    // TODO(plafer): this is copy/pasted (almost) from the FastProcessor
    fn rotate_right(&mut self, n: usize) {
        let rotation_bot_index = MIN_STACK_DEPTH - n;
        let new_stack_bot_element = self.state.stack.stack_top()[MIN_STACK_DEPTH - 1];

        // shift the top n elements up by 1, starting from the top of the rotation.
        for i in 1..n {
            self.state.stack.stack_top_mut()[MIN_STACK_DEPTH - i] =
                self.state.stack.stack_top()[MIN_STACK_DEPTH - i - 1];
        }

        // Set the bot element (which comes from the top of the rotation).
        self.state.stack.stack_top_mut()[rotation_bot_index] = new_stack_bot_element;
    }

    fn increment_stack_size(&mut self) {
        const SENTINEL_VALUE: Felt = Felt::new(Felt::MODULUS - 1);

        // push the last element on the overflow table
        {
            let last_element = self.stack_get(MIN_STACK_DEPTH - 1);
            self.state.stack.push_overflow(last_element);
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
        if let Some(last_element) = self.state.stack.pop_overflow() {
            // Write the last element to the bottom of the stack
            self.stack_write(MIN_STACK_DEPTH - 1, last_element);
        } else {
            // If overflow table is empty, set the bottom element to zero
            self.stack_write(MIN_STACK_DEPTH - 1, ZERO);
        }
    }
}
