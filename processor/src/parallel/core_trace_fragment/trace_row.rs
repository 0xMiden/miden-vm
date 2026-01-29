//! Module which concerns itself with all the trace row building logic.

use core::ops::ControlFlow;

use miden_air::trace::{
    CLK_COL_IDX, CTX_COL_IDX, DECODER_TRACE_OFFSET, FN_HASH_OFFSET, STACK_TRACE_OFFSET,
    SYS_TRACE_WIDTH,
    chiplets::hasher::HASH_CYCLE_LEN_FELT,
    decoder::{
        ADDR_COL_IDX, GROUP_COUNT_COL_IDX, HASHER_STATE_OFFSET, IN_SPAN_COL_IDX,
        NUM_OP_BATCH_FLAGS, NUM_OP_BITS, NUM_USER_OP_HELPERS, OP_BATCH_FLAGS_OFFSET,
        OP_BITS_EXTRA_COLS_OFFSET, OP_BITS_OFFSET, OP_INDEX_COL_IDX,
    },
    stack::{B0_COL_IDX, B1_COL_IDX, H0_COL_IDX, STACK_TOP_OFFSET, STACK_TOP_RANGE},
};
use miden_core::{
    Felt, ONE, Operation, Word, ZERO,
    field::{PrimeCharacteristicRing, PrimeField64},
    mast::{
        BasicBlockNode, CallNode, JoinNode, LoopNode, MastForest, MastNodeExt, OpBatch, SplitNode,
    },
};

use super::CoreTraceFragmentFiller;
use crate::{
    decoder::block_stack::ExecutionContextInfo, parallel::core_trace_fragment::BasicBlockContext,
    processor::StackInterface,
};

// DECODER ROW
// ================================================================================================

/// The data necessary to build the decoder part of a trace row.
#[derive(Debug)]
struct DecoderRow {
    /// The address field to write into trace
    pub addr: Felt,
    /// The operation code for start operations
    pub opcode: u8,
    /// The two child hashes for start operations (first hash, second hash)
    pub hasher_state: (Word, Word),
    /// Whether this row is an operation within a basic block
    pub in_basic_block: bool,
    /// The group count for this operation
    pub group_count: Felt,
    /// The index of the operation within its operation group, or 0 if this is not a row containing
    /// an operation in a basic block.
    pub op_index: Felt,
    /// The operation batch flags, encoding the number of groups present in the current operation
    /// batch.
    pub op_batch_flags: [Felt; NUM_OP_BATCH_FLAGS],
}

impl DecoderRow {
    /// Creates a new `DecoderRow` for control flow operations (JOIN/SPLIT start or end).
    ///
    /// Control flow operations do not occur within basic blocks, so the relevant fields are set
    /// to their default values.
    pub fn new_control_flow(opcode: u8, hasher_state: (Word, Word), addr: Felt) -> Self {
        Self {
            opcode,
            hasher_state,
            addr,
            in_basic_block: false,
            group_count: ZERO,
            op_index: ZERO,
            op_batch_flags: [ZERO; NUM_OP_BATCH_FLAGS],
        }
    }

    /// Creates a new `DecoderRow` for the start of a new batch in a basic block.
    ///
    /// This corresponds either to the SPAN or RESPAN operations.
    pub fn new_basic_block_batch(
        operation: Operation,
        op_batch: &OpBatch,
        addr: Felt,
        group_count: Felt,
    ) -> Self {
        debug_assert!(
            operation == Operation::Span || operation == Operation::Respan,
            "operation must be SPAN or RESPAN"
        );

        let hasher_state = (
            op_batch.groups()[0..4].try_into().expect("slice with incorrect length"),
            op_batch.groups()[4..8].try_into().expect("slice with incorrect length"),
        );

        Self {
            opcode: operation.op_code(),
            hasher_state,
            addr,
            in_basic_block: false,
            group_count,
            op_index: ZERO,
            op_batch_flags: get_op_batch_flags(group_count),
        }
    }

    /// Creates a new `DecoderRow` for an operation within a basic block.
    pub fn new_operation(
        operation: Operation,
        current_addr: Felt,
        parent_addr: Felt,
        op_idx_in_group: usize,
        basic_block_ctx: &BasicBlockContext,
        user_op_helpers: Option<[Felt; NUM_USER_OP_HELPERS]>,
    ) -> Self {
        let hasher_state: (Word, Word) = {
            let user_op_helpers = user_op_helpers.unwrap_or([ZERO; NUM_USER_OP_HELPERS]);

            let word1 = [
                basic_block_ctx.current_op_group,
                parent_addr,
                user_op_helpers[0],
                user_op_helpers[1],
            ];
            let word2 =
                [user_op_helpers[2], user_op_helpers[3], user_op_helpers[4], user_op_helpers[5]];

            (word1.into(), word2.into())
        };

        Self {
            opcode: operation.op_code(),
            hasher_state,
            addr: current_addr,
            in_basic_block: true,
            group_count: basic_block_ctx.group_count_in_block,
            op_index: Felt::from_u32(op_idx_in_group as u32),
            op_batch_flags: [ZERO; NUM_OP_BATCH_FLAGS],
        }
    }
}

// BASIC BLOCK TRACE ROW METHODS
// ================================================================================================

impl<'a> CoreTraceFragmentFiller<'a> {
    /// Adds a trace row for SPAN start operation to the main trace fragment.
    ///
    /// This method creates a trace row that corresponds to the SPAN operation that starts
    /// a basic block execution.
    pub fn add_basic_block_start_trace_row(
        &mut self,
        basic_block_node: &BasicBlockNode,
    ) -> ControlFlow<()> {
        let group_count_for_block = Felt::from_u32(basic_block_node.num_op_groups() as u32);
        let first_op_batch = basic_block_node
            .op_batches()
            .first()
            .expect("Basic block should have at least one op batch");

        let decoder_row = DecoderRow::new_basic_block_batch(
            Operation::Span,
            first_op_batch,
            self.context.state.decoder.parent_addr,
            group_count_for_block,
        );
        self.add_trace_row(decoder_row)
    }

    /// Adds a trace row for SPAN end operation to the main trace fragment.
    ///
    /// This method creates a trace row that corresponds to the END operation that completes
    /// a basic block execution.
    pub fn add_basic_block_end_trace_row(
        &mut self,
        basic_block_node: &BasicBlockNode,
    ) -> ControlFlow<()> {
        let (ended_node_addr, flags) =
            self.context.state.decoder.replay_node_end(&mut self.context.replay);

        let decoder_row = DecoderRow::new_control_flow(
            Operation::End.op_code(),
            (basic_block_node.digest(), flags.to_hasher_state_second_word()),
            ended_node_addr,
        );

        self.add_trace_row(decoder_row)
    }

    // RESPAN
    // -------------------------------------------------------------------------------------------

    /// Processes a RESPAN operation that starts processing of a new operation batch within
    /// the same basic block.
    ///
    /// This method updates the processor state and adds a corresponding trace row
    /// to the main trace fragment.
    pub fn add_respan_trace_row(
        &mut self,
        op_batch: &OpBatch,
        basic_block_context: &mut BasicBlockContext,
    ) -> ControlFlow<()> {
        // Add RESPAN trace row
        {
            let decoder_row = DecoderRow::new_basic_block_batch(
                Operation::Respan,
                op_batch,
                self.context.state.decoder.current_addr,
                basic_block_context.group_count_in_block,
            );
            self.add_trace_row(decoder_row)?;
        }

        // Update block address for the upcoming block
        self.context.state.decoder.current_addr += HASH_CYCLE_LEN_FELT;

        // Update basic block context
        basic_block_context.group_count_in_block -= ONE;
        basic_block_context.current_op_group = op_batch.groups()[0];

        ControlFlow::Continue(())
    }

    /// Writes a trace row for an operation within a basic block.
    ///
    /// This must be called *after* the operation has been executed and the
    /// stack has been updated.
    pub fn add_operation_trace_row(
        &mut self,
        operation: Operation,
        op_idx_in_group: usize,
        user_op_helpers: Option<[Felt; NUM_USER_OP_HELPERS]>,
        basic_block_context: &mut BasicBlockContext,
    ) -> ControlFlow<()> {
        // update operations left to be executed in the group
        basic_block_context.remove_operation_from_current_op_group();

        // Add trace row
        let decoder_row = DecoderRow::new_operation(
            operation,
            self.context.state.decoder.current_addr,
            self.context.state.decoder.parent_addr,
            op_idx_in_group,
            basic_block_context,
            user_op_helpers,
        );
        self.add_trace_row(decoder_row)?;

        // Update number of groups left if the operation had an immediate value
        if operation.imm_value().is_some() {
            basic_block_context.group_count_in_block -= ONE;
        }

        ControlFlow::Continue(())
    }
}

// CONTROL FLOW TRACE ROW METHODS
// ================================================================================================

impl<'a> CoreTraceFragmentFiller<'a> {
    // CALL operations
    // -------------------------------------------------------------------------------------------

    /// Adds a trace row for the start of a CALL/SYSCALL operation.
    pub fn add_call_start_trace_row(
        &mut self,
        call_node: &CallNode,
        program: &MastForest,
    ) -> ControlFlow<()> {
        // For CALL/SYSCALL operations, the hasher state in start operations contains the callee
        // hash in the first half, and zeros in the second half (since CALL only has one
        // child)
        let callee_hash: Word = program
            .get_node_by_id(call_node.callee())
            .expect("callee should exist")
            .digest();
        let zero_hash = Word::default();

        let decoder_row = DecoderRow::new_control_flow(
            if call_node.is_syscall() {
                Operation::SysCall.op_code()
            } else {
                Operation::Call.op_code()
            },
            (callee_hash, zero_hash),
            self.context.state.decoder.parent_addr,
        );

        self.add_trace_row(decoder_row)
    }

    // DYN operations
    // -------------------------------------------------------------------------------------------

    /// Adds a trace row for the start of a DYN operation.
    pub fn add_dyn_start_trace_row(&mut self, callee_hash: Word) -> ControlFlow<()> {
        let decoder_row = DecoderRow::new_control_flow(
            Operation::Dyn.op_code(),
            (callee_hash, Word::default()),
            self.context.state.decoder.parent_addr,
        );
        self.add_trace_row(decoder_row)
    }

    /// Adds a trace row for the start of a DYNCALL operation.
    ///
    /// The decoder hasher trace columns are populated with the callee hash, as well as the stack
    /// helper registers (specifically their state after shifting the stack left). We need to store
    /// those in the decoder trace so that the block stack table can access them (since in the next
    /// row, we start a new context, and hence the stack registers are reset to their default
    /// values).
    pub fn add_dyncall_start_trace_row(
        &mut self,
        callee_hash: Word,
        ctx_info: ExecutionContextInfo,
    ) -> ControlFlow<()> {
        let second_hasher_state: Word = [
            Felt::from_u32(ctx_info.parent_stack_depth),
            ctx_info.parent_next_overflow_addr,
            ZERO,
            ZERO,
        ]
        .into();

        let decoder_row = DecoderRow::new_control_flow(
            Operation::Dyncall.op_code(),
            (callee_hash, second_hasher_state),
            self.context.state.decoder.parent_addr,
        );
        self.add_trace_row(decoder_row)
    }

    // JOIN operations
    // -------------------------------------------------------------------------------------------

    /// Adds a trace row for starting a JOIN operation to the main trace fragment.
    pub fn add_join_start_trace_row(
        &mut self,
        join_node: &JoinNode,
        program: &MastForest,
    ) -> ControlFlow<()> {
        // Get the child hashes for the hasher state
        let child1_hash: Word = program
            .get_node_by_id(join_node.first())
            .expect("first child should exist")
            .digest();
        let child2_hash: Word = program
            .get_node_by_id(join_node.second())
            .expect("second child should exist")
            .digest();

        let decoder_row = DecoderRow::new_control_flow(
            Operation::Join.op_code(),
            (child1_hash, child2_hash),
            self.context.state.decoder.parent_addr,
        );

        self.add_trace_row(decoder_row)
    }

    // LOOP operations
    // -------------------------------------------------------------------------------------------

    /// Adds a trace row for the start of a LOOP operation.
    pub fn add_loop_start_trace_row(
        &mut self,
        loop_node: &LoopNode,
        program: &MastForest,
    ) -> ControlFlow<()> {
        // For LOOP operations, the hasher state in start operations contains the loop body hash in
        // the first half.
        let body_hash: Word = program
            .get_node_by_id(loop_node.body())
            .expect("loop body should exist")
            .digest();
        let zero_hash = Word::default();

        let decoder_row = DecoderRow::new_control_flow(
            Operation::Loop.op_code(),
            (body_hash, zero_hash),
            self.context.state.decoder.parent_addr,
        );

        self.add_trace_row(decoder_row)
    }

    /// Adds a trace row for the start of a REPEAT operation.
    pub fn add_loop_repeat_trace_row(
        &mut self,
        loop_node: &LoopNode,
        program: &MastForest,
        current_addr: Felt,
    ) -> ControlFlow<()> {
        // For REPEAT operations, the hasher state in start operations contains the loop body hash
        // in the first half.
        let body_hash: Word = program
            .get_node_by_id(loop_node.body())
            .expect("loop body should exist")
            .digest();

        let decoder_row = DecoderRow::new_control_flow(
            Operation::Repeat.op_code(),
            // We set hasher[4] (is_loop_body) to 1
            (body_hash, [ONE, ZERO, ZERO, ZERO].into()),
            current_addr,
        );

        self.add_trace_row(decoder_row)
    }

    // SPLIT operations
    // -------------------------------------------------------------------------------------------

    /// Adds a trace row for the start of a SPLIT operation.
    pub fn add_split_start_trace_row(
        &mut self,
        split_node: &SplitNode,
        program: &MastForest,
    ) -> ControlFlow<()> {
        // Get the child hashes for the hasher state
        let on_true_hash: Word = program
            .get_node_by_id(split_node.on_true())
            .expect("on_true child should exist")
            .digest();
        let on_false_hash: Word = program
            .get_node_by_id(split_node.on_false())
            .expect("on_false child should exist")
            .digest();

        let decoder_row = DecoderRow::new_control_flow(
            Operation::Split.op_code(),
            (on_true_hash, on_false_hash),
            self.context.state.decoder.parent_addr,
        );

        self.add_trace_row(decoder_row)
    }

    /// Adds a trace row for the end of a control block.
    ///
    /// This method also updates the decoder state by popping the block from the stack.
    pub fn add_end_trace_row(&mut self, node_digest: Word) -> ControlFlow<()> {
        // Pop the block from stack and use its info for END operations
        let (ended_node_addr, flags) =
            self.context.state.decoder.replay_node_end(&mut self.context.replay);

        let decoder_row = DecoderRow::new_control_flow(
            Operation::End.op_code(),
            (node_digest, flags.to_hasher_state_second_word()),
            ended_node_addr,
        );

        self.add_trace_row(decoder_row)
    }
}

// HELPER METHODS
// ================================================================================================

impl<'a> CoreTraceFragmentFiller<'a> {
    /// Adds a trace row for a control flow operation (JOIN/SPLIT start or end) to the main trace
    /// fragment.
    ///
    /// This is a shared implementation that handles the common trace row generation logic
    /// for both JOIN and SPLIT operations. The operation-specific details are provided
    /// through the `config` parameter.
    fn add_trace_row(&mut self, decoder_row: DecoderRow) -> ControlFlow<()> {
        let row_idx = self.num_rows_built();

        // System trace columns (identical for all control flow operations)
        self.populate_system_trace_columns(row_idx);

        // Decoder trace columns
        self.populate_decoder_trace_columns(row_idx, &decoder_row);

        // Stack trace columns (identical for all control flow operations)
        self.populate_stack_trace_columns(row_idx);

        // Increment clock
        self.increment_clk()
    }

    /// Populates the system trace columns
    fn populate_system_trace_columns(&mut self, row_idx: usize) {
        // If we have buffered system rows from the previous call, write them to the trace
        if let Some(system_rows) = self.system_rows {
            // Write buffered system rows to the trace at current row
            for (i, &value) in system_rows.iter().enumerate() {
                self.fragment.columns[i][row_idx] = value;
            }
        }

        // Now populate the buffer with current system state for the next row
        let mut new_system_rows = [ZERO; SYS_TRACE_WIDTH];

        new_system_rows[CLK_COL_IDX] = (self.context.state.system.clk + 1).into();
        new_system_rows[CTX_COL_IDX] = self.context.state.system.ctx.into();
        new_system_rows[FN_HASH_OFFSET] = self.context.state.system.fn_hash[0];
        new_system_rows[FN_HASH_OFFSET + 1] = self.context.state.system.fn_hash[1];
        new_system_rows[FN_HASH_OFFSET + 2] = self.context.state.system.fn_hash[2];
        new_system_rows[FN_HASH_OFFSET + 3] = self.context.state.system.fn_hash[3];

        // Store the buffer for the next call
        self.system_rows = Some(new_system_rows);
    }

    /// Populates the decoder trace columns with operation-specific data
    fn populate_decoder_trace_columns(&mut self, row_idx: usize, row: &DecoderRow) {
        // Block address
        self.fragment.columns[DECODER_TRACE_OFFSET + ADDR_COL_IDX][row_idx] = row.addr;

        // Decompose operation into bits
        let opcode = row.opcode;
        for i in 0..NUM_OP_BITS {
            let bit = Felt::from_u8((opcode >> i) & 1);
            self.fragment.columns[DECODER_TRACE_OFFSET + OP_BITS_OFFSET + i][row_idx] = bit;
        }

        // Hasher state
        let (first_hash, second_hash) = row.hasher_state;
        self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET][row_idx] = first_hash[0]; // hasher[0]
        self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 1][row_idx] =
            first_hash[1]; // hasher[1]
        self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 2][row_idx] =
            first_hash[2]; // hasher[2]
        self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 3][row_idx] =
            first_hash[3]; // hasher[3]
        self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 4][row_idx] =
            second_hash[0]; // hasher[4]
        self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 5][row_idx] =
            second_hash[1]; // hasher[5]
        self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 6][row_idx] =
            second_hash[2]; // hasher[6]
        self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 7][row_idx] =
            second_hash[3]; // hasher[7]

        // Remaining decoder trace columns (identical for all control flow operations)
        self.fragment.columns[DECODER_TRACE_OFFSET + OP_INDEX_COL_IDX][row_idx] = row.op_index;
        self.fragment.columns[DECODER_TRACE_OFFSET + GROUP_COUNT_COL_IDX][row_idx] =
            row.group_count;
        self.fragment.columns[DECODER_TRACE_OFFSET + IN_SPAN_COL_IDX][row_idx] =
            if row.in_basic_block { ONE } else { ZERO };

        // Batch flag columns - all 0 for control flow operations
        for i in 0..NUM_OP_BATCH_FLAGS {
            self.fragment.columns[DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET + i][row_idx] =
                row.op_batch_flags[i];
        }

        // Extra bit columns
        let bit6 = self.fragment.columns[DECODER_TRACE_OFFSET + OP_BITS_OFFSET + 6][row_idx];
        let bit5 = self.fragment.columns[DECODER_TRACE_OFFSET + OP_BITS_OFFSET + 5][row_idx];
        let bit4 = self.fragment.columns[DECODER_TRACE_OFFSET + OP_BITS_OFFSET + 4][row_idx];
        self.fragment.columns[DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET][row_idx] =
            bit6 * (ONE - bit5) * bit4;
        self.fragment.columns[DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET + 1][row_idx] =
            bit6 * bit5;
    }

    /// Populates the stack trace columns
    fn populate_stack_trace_columns(&mut self, row_idx: usize) {
        use miden_air::trace::STACK_TRACE_WIDTH;

        // If we have buffered stack rows from the previous call, write them to the trace
        if let Some(stack_rows) = self.stack_rows {
            // Write buffered stack rows to the trace at current row
            for (i, &value) in stack_rows.iter().enumerate() {
                self.fragment.columns[STACK_TRACE_OFFSET + i][row_idx] = value;
            }
        }

        // Now populate the buffer with current stack state for the next row
        let mut new_stack_rows = [ZERO; STACK_TRACE_WIDTH];

        // Stack top (16 elements)
        for i in STACK_TOP_RANGE {
            new_stack_rows[STACK_TOP_OFFSET + i] = self.get(i);
        }

        // Stack helpers (b0, b1, h0)
        // Note: H0 will be inverted using batch inversion later
        new_stack_rows[B0_COL_IDX] = Felt::new(self.context.state.stack.stack_depth() as u64); // b0
        new_stack_rows[B1_COL_IDX] = self.context.state.stack.overflow_addr(); // b1
        new_stack_rows[H0_COL_IDX] = self.context.state.stack.overflow_helper(); // h0

        // Store the buffer for the next call
        self.stack_rows = Some(new_stack_rows);
    }
}

// HELPERS
// ===============================================================================================

/// Returns op batch flags for the specified group count.
fn get_op_batch_flags(num_groups_left: Felt) -> [Felt; 3] {
    use miden_air::trace::decoder::{
        OP_BATCH_1_GROUPS, OP_BATCH_2_GROUPS, OP_BATCH_4_GROUPS, OP_BATCH_8_GROUPS,
    };
    use miden_core::mast::OP_BATCH_SIZE;

    let num_groups = core::cmp::min(num_groups_left.as_canonical_u64() as usize, OP_BATCH_SIZE);
    match num_groups {
        8 => OP_BATCH_8_GROUPS,
        4 => OP_BATCH_4_GROUPS,
        2 => OP_BATCH_2_GROUPS,
        1 => OP_BATCH_1_GROUPS,
        _ => panic!("invalid number of groups in a batch: {num_groups}, must be 1, 2, 4, or 8"),
    }
}
