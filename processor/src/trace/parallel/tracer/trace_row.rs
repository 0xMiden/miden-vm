//! Module which concerns itself with all the trace row building logic.

use miden_air::trace::{
    CLK_COL_IDX, CTX_COL_IDX, DECODER_TRACE_OFFSET, FN_HASH_OFFSET, STACK_TRACE_OFFSET,
    STACK_TRACE_WIDTH, SYS_TRACE_WIDTH,
    chiplets::hasher::CONTROLLER_ROWS_PER_PERM_FELT,
    decoder::{
        ADDR_COL_IDX, GROUP_COUNT_COL_IDX, HASHER_STATE_OFFSET, IN_SPAN_COL_IDX,
        NUM_OP_BATCH_FLAGS, NUM_OP_BITS, NUM_USER_OP_HELPERS, OP_BATCH_FLAGS_OFFSET,
        OP_BITS_EXTRA_COLS_OFFSET, OP_BITS_OFFSET, OP_INDEX_COL_IDX,
    },
    stack::{B0_COL_IDX, B1_COL_IDX, H0_COL_IDX, STACK_TOP_OFFSET, STACK_TOP_RANGE},
};
use miden_core::{
    Felt, ONE, Word, ZERO,
    mast::{
        BasicBlockNode, CallNode, JoinNode, LoopNode, MastForest, MastNodeExt, OpBatch, SplitNode,
    },
    operations::{Operation, opcodes},
};

use super::{ExecutionContextInfo, StackState, SystemState, get_node_in_forest};
use crate::{
    ExecutionError,
    trace::parallel::{
        CORE_TRACE_WIDTH, core_trace_fragment::BasicBlockContext, tracer::CoreTraceGenerationTracer,
    },
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
        start_op: BasicBlockStartOperation,
        op_batch: &OpBatch,
        addr: Felt,
        group_count: Felt,
    ) -> Result<Self, ExecutionError> {
        let opcode = match start_op {
            BasicBlockStartOperation::Span => opcodes::SPAN,
            BasicBlockStartOperation::Respan => opcodes::RESPAN,
        };

        let hasher_state = (
            op_batch.groups()[0..4].try_into().expect("slice with incorrect length"),
            op_batch.groups()[4..8].try_into().expect("slice with incorrect length"),
        );

        Ok(Self {
            opcode,
            hasher_state,
            addr,
            in_basic_block: false,
            group_count,
            op_index: ZERO,
            op_batch_flags: get_op_batch_flags(group_count)?,
        })
    }

    /// Creates a new `DecoderRow` for an operation within a basic block.
    pub fn new_operation(
        operation: Operation,
        current_addr: Felt,
        parent_addr: Felt,
        op_idx_in_group: usize,
        basic_block_ctx: &BasicBlockContext,
        user_op_helpers: [Felt; NUM_USER_OP_HELPERS],
    ) -> Self {
        let hasher_state: (Word, Word) = {
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

/// Enum representing the type of operation that starts a basic block.
#[derive(Debug)]
enum BasicBlockStartOperation {
    Span,
    Respan,
}

// BASIC BLOCK TRACE ROW METHODS
// ================================================================================================

impl<'a> CoreTraceGenerationTracer<'a> {
    /// Fills a trace row for SPAN start operation to the main trace fragment.
    ///
    /// This method creates a trace row that corresponds to the SPAN operation that starts
    /// a basic block execution.
    pub fn fill_basic_block_start_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        basic_block_node: &BasicBlockNode,
    ) -> Result<(), ExecutionError> {
        let group_count_for_block = Felt::from_u32(basic_block_node.num_op_groups() as u32);
        let first_op_batch = basic_block_node
            .op_batches()
            .first()
            .ok_or(ExecutionError::Internal("basic block should have at least one op batch"))?;

        let decoder_row = DecoderRow::new_basic_block_batch(
            BasicBlockStartOperation::Span,
            first_op_batch,
            self.decoder_state.parent_addr,
            group_count_for_block,
        )?;
        self.fill_trace_row(system, stack, decoder_row);
        Ok(())
    }

    /// Fills a trace row for SPAN end operation to the main trace fragment.
    ///
    /// This method creates a trace row that corresponds to the END operation that completes
    /// a basic block execution.
    pub fn fill_basic_block_end_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        basic_block_node: &BasicBlockNode,
        hasher_state_second_word: Word,
    ) -> Result<(), ExecutionError> {
        let ended_node_addr = self.decoder_state.replay_node_end(&mut self.block_stack_replay)?;

        let decoder_row = DecoderRow::new_control_flow(
            opcodes::END,
            (basic_block_node.digest(), hasher_state_second_word),
            ended_node_addr,
        );

        self.fill_trace_row(system, stack, decoder_row);
        Ok(())
    }

    // RESPAN
    // -------------------------------------------------------------------------------------------

    /// Processes a RESPAN operation that starts processing of a new operation batch within
    /// the same basic block.
    ///
    /// This method updates the processor state and adds a corresponding trace row
    /// to the main trace fragment.
    pub fn fill_respan_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        op_batch: &OpBatch,
        basic_block_context: &mut BasicBlockContext,
    ) -> Result<(), ExecutionError> {
        // Add RESPAN trace row
        {
            let decoder_row = DecoderRow::new_basic_block_batch(
                BasicBlockStartOperation::Respan,
                op_batch,
                self.decoder_state.current_addr,
                basic_block_context.group_count_in_block,
            )?;
            self.fill_trace_row(system, stack, decoder_row);
        }

        // Update block address for the upcoming block
        self.decoder_state.current_addr += CONTROLLER_ROWS_PER_PERM_FELT;

        // Update basic block context
        basic_block_context.group_count_in_block -= ONE;
        basic_block_context.current_op_group = op_batch.groups()[0];

        Ok(())
    }

    /// Writes a trace row for an operation within a basic block.
    ///
    /// This must be called *after* the operation has been executed and the
    /// stack has been updated.
    pub fn fill_operation_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        operation: Operation,
        op_idx_in_group: usize,
        user_op_helpers: [Felt; NUM_USER_OP_HELPERS],
        basic_block_context: &mut BasicBlockContext,
    ) {
        // update operations left to be executed in the group
        basic_block_context.remove_operation_from_current_op_group();

        // Add trace row
        let decoder_row = DecoderRow::new_operation(
            operation,
            self.decoder_state.current_addr,
            self.decoder_state.parent_addr,
            op_idx_in_group,
            basic_block_context,
            user_op_helpers,
        );
        self.fill_trace_row(system, stack, decoder_row);
    }
}

// CONTROL FLOW TRACE ROW METHODS
// ================================================================================================

impl<'a> CoreTraceGenerationTracer<'a> {
    // CALL operations
    // -------------------------------------------------------------------------------------------

    /// Fills a trace row for the start of a CALL/SYSCALL operation.
    pub fn fill_call_start_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        call_node: &CallNode,
        current_forest: &MastForest,
    ) -> Result<(), ExecutionError> {
        // For CALL/SYSCALL operations, the hasher state in start operations contains the callee
        // hash in the first half, and zeros in the second half (since CALL only has one
        // child)
        let callee_hash: Word = get_node_in_forest(current_forest, call_node.callee())?.digest();
        let zero_hash = Word::default();

        let decoder_row = DecoderRow::new_control_flow(
            if call_node.is_syscall() {
                opcodes::SYSCALL
            } else {
                opcodes::CALL
            },
            (callee_hash, zero_hash),
            self.decoder_state.parent_addr,
        );

        self.fill_trace_row(system, stack, decoder_row);
        Ok(())
    }

    // DYN operations
    // -------------------------------------------------------------------------------------------

    /// Fills a trace row for the start of a DYN operation.
    pub fn fill_dyn_start_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        callee_hash: Word,
    ) {
        let decoder_row = DecoderRow::new_control_flow(
            opcodes::DYN,
            (callee_hash, Word::default()),
            self.decoder_state.parent_addr,
        );
        self.fill_trace_row(system, stack, decoder_row)
    }

    /// Fills a trace row for the start of a DYNCALL operation.
    ///
    /// The decoder hasher trace columns are populated with the callee hash, as well as the stack
    /// helper registers (specifically their state after shifting the stack left). We need to store
    /// those in the decoder trace so that the block stack table can access them (since in the next
    /// row, we start a new context, and hence the stack registers are reset to their default
    /// values).
    pub fn fill_dyncall_start_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        callee_hash: Word,
        ctx_info: ExecutionContextInfo,
    ) {
        let second_hasher_state: Word = [
            Felt::from_u32(ctx_info.parent_stack_depth),
            ctx_info.parent_next_overflow_addr,
            ZERO,
            ZERO,
        ]
        .into();

        let decoder_row = DecoderRow::new_control_flow(
            opcodes::DYNCALL,
            (callee_hash, second_hasher_state),
            self.decoder_state.parent_addr,
        );
        self.fill_trace_row(system, stack, decoder_row)
    }

    // JOIN operations
    // -------------------------------------------------------------------------------------------

    /// Fills a trace row for starting a JOIN operation to the main trace fragment.
    pub fn fill_join_start_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        join_node: &JoinNode,
        current_forest: &MastForest,
    ) -> Result<(), ExecutionError> {
        // Get the child hashes for the hasher state
        let child1_hash: Word = get_node_in_forest(current_forest, join_node.first())?.digest();
        let child2_hash: Word = get_node_in_forest(current_forest, join_node.second())?.digest();

        let decoder_row = DecoderRow::new_control_flow(
            opcodes::JOIN,
            (child1_hash, child2_hash),
            self.decoder_state.parent_addr,
        );

        self.fill_trace_row(system, stack, decoder_row);
        Ok(())
    }

    // LOOP operations
    // -------------------------------------------------------------------------------------------

    /// Fills a trace row for the start of a LOOP operation.
    pub fn fill_loop_start_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        loop_node: &LoopNode,
        current_forest: &MastForest,
    ) -> Result<(), ExecutionError> {
        // For LOOP operations, the hasher state in start operations contains the loop body hash in
        // the first half.
        let body_hash: Word = get_node_in_forest(current_forest, loop_node.body())?.digest();
        let zero_hash = Word::default();

        let decoder_row = DecoderRow::new_control_flow(
            opcodes::LOOP,
            (body_hash, zero_hash),
            self.decoder_state.parent_addr,
        );

        self.fill_trace_row(system, stack, decoder_row);
        Ok(())
    }

    /// Fills a trace row for the start of a REPEAT operation.
    pub fn fill_loop_repeat_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        loop_node: &LoopNode,
        current_forest: &MastForest,
        current_addr: Felt,
    ) -> Result<(), ExecutionError> {
        // For REPEAT operations, the hasher state in start operations contains the loop body hash
        // in the first half.
        let body_hash: Word = get_node_in_forest(current_forest, loop_node.body())?.digest();

        let decoder_row = DecoderRow::new_control_flow(
            opcodes::REPEAT,
            // We set hasher[4] (is_loop_body) to 1
            (body_hash, [ONE, ZERO, ZERO, ZERO].into()),
            current_addr,
        );

        self.fill_trace_row(system, stack, decoder_row);
        Ok(())
    }

    // SPLIT operations
    // -------------------------------------------------------------------------------------------

    /// Fills a trace row for the start of a SPLIT operation.
    pub fn fill_split_start_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        split_node: &SplitNode,
        current_forest: &MastForest,
    ) -> Result<(), ExecutionError> {
        // Get the child hashes for the hasher state
        let on_true_hash: Word = get_node_in_forest(current_forest, split_node.on_true())?.digest();
        let on_false_hash: Word =
            get_node_in_forest(current_forest, split_node.on_false())?.digest();

        let decoder_row = DecoderRow::new_control_flow(
            opcodes::SPLIT,
            (on_true_hash, on_false_hash),
            self.decoder_state.parent_addr,
        );

        self.fill_trace_row(system, stack, decoder_row);
        Ok(())
    }

    /// Fills a trace row for the end of a control block.
    ///
    /// This method also updates the decoder state by popping the block from the stack.
    pub fn fill_end_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        node_digest: Word,
        hasher_state_second_word: Word,
    ) -> Result<(), ExecutionError> {
        // Pop the block from stack and use its info for END operations
        let ended_node_addr = self.decoder_state.replay_node_end(&mut self.block_stack_replay)?;

        let decoder_row = DecoderRow::new_control_flow(
            opcodes::END,
            (node_digest, hasher_state_second_word),
            ended_node_addr,
        );

        self.fill_trace_row(system, stack, decoder_row);
        Ok(())
    }
}

// HELPER METHODS
// ================================================================================================

impl<'a> CoreTraceGenerationTracer<'a> {
    /// Fills a trace row for a control flow operation (JOIN/SPLIT start or end) to the main trace
    /// fragment.
    ///
    /// This is a shared implementation that handles the common trace row generation logic
    /// for both JOIN and SPLIT operations. The operation-specific details are provided
    /// through the `config` parameter.
    fn fill_trace_row(
        &mut self,
        system: &SystemState,
        stack: &StackState,
        decoder_row: DecoderRow,
    ) {
        let mut row = [ZERO; CORE_TRACE_WIDTH];

        // System trace columns (identical for all control flow operations)
        if let Some(ref system_cols) = self.system_cols {
            row[..SYS_TRACE_WIDTH].copy_from_slice(system_cols);
        }

        // Decoder trace columns
        Self::write_decoder_to_row(&mut row, &decoder_row);

        // Stack trace columns (identical for all control flow operations)
        if let Some(ref stack_cols) = self.stack_cols {
            row[STACK_TRACE_OFFSET..STACK_TRACE_OFFSET + STACK_TRACE_WIDTH]
                .copy_from_slice(stack_cols);
        }

        self.writer.write_row(self.row_write_index, &row);

        // Store the buffer for the next call
        self.system_cols = Some(Self::build_system_buffer(system));
        self.stack_cols = Some(Self::build_stack_buffer(stack));

        // Increment the row write index
        self.row_write_index += 1;
    }

    fn write_decoder_to_row(row: &mut [Felt; CORE_TRACE_WIDTH], decoder_row: &DecoderRow) {
        // Block address
        row[DECODER_TRACE_OFFSET + ADDR_COL_IDX] = decoder_row.addr;

        // Decompose operation into bits
        let opcode = decoder_row.opcode;
        for i in 0..NUM_OP_BITS {
            let bit = Felt::from_u8((opcode >> i) & 1);
            row[DECODER_TRACE_OFFSET + OP_BITS_OFFSET + i] = bit;
        }

        // Hasher state
        let (first_hash, second_hash) = decoder_row.hasher_state;
        row[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET] = first_hash[0];
        row[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 1] = first_hash[1];
        row[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 2] = first_hash[2];
        row[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 3] = first_hash[3];
        row[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 4] = second_hash[0];
        row[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 5] = second_hash[1];
        row[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 6] = second_hash[2];
        row[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 7] = second_hash[3];

        // Remaining decoder trace columns (identical for all control flow operations)
        row[DECODER_TRACE_OFFSET + OP_INDEX_COL_IDX] = decoder_row.op_index;
        row[DECODER_TRACE_OFFSET + GROUP_COUNT_COL_IDX] = decoder_row.group_count;
        row[DECODER_TRACE_OFFSET + IN_SPAN_COL_IDX] =
            if decoder_row.in_basic_block { ONE } else { ZERO };

        // Batch flag columns - all 0 for control flow operations
        for i in 0..NUM_OP_BATCH_FLAGS {
            row[DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET + i] = decoder_row.op_batch_flags[i];
        }

        // Extra bit columns
        let bit6 = Felt::from_u8((opcode >> 6) & 1);
        let bit5 = Felt::from_u8((opcode >> 5) & 1);
        let bit4 = Felt::from_u8((opcode >> 4) & 1);
        row[DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET] = bit6 * (ONE - bit5) * bit4;
        row[DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET + 1] = bit6 * bit5;
    }

    fn build_system_buffer(system: &SystemState) -> [Felt; SYS_TRACE_WIDTH] {
        let mut buf = [ZERO; SYS_TRACE_WIDTH];
        buf[CLK_COL_IDX] = (system.clk + 1).into();
        buf[CTX_COL_IDX] = system.ctx.into();
        buf[FN_HASH_OFFSET] = system.fn_hash[0];
        buf[FN_HASH_OFFSET + 1] = system.fn_hash[1];
        buf[FN_HASH_OFFSET + 2] = system.fn_hash[2];
        buf[FN_HASH_OFFSET + 3] = system.fn_hash[3];
        buf
    }

    fn build_stack_buffer(stack: &StackState) -> [Felt; STACK_TRACE_WIDTH] {
        let mut buf = [ZERO; STACK_TRACE_WIDTH];
        for i in STACK_TOP_RANGE {
            buf[STACK_TOP_OFFSET + i] = stack.get(i);
        }

        // Stack helpers (b0, b1, h0)
        // Note: H0 will be inverted using batch inversion later
        buf[B0_COL_IDX] = Felt::new(stack.stack_depth() as u64);
        buf[B1_COL_IDX] = stack.overflow_addr();
        buf[H0_COL_IDX] = stack.overflow_helper();
        buf
    }
}

// HELPERS
// ===============================================================================================

/// Returns op batch flags for the specified group count.
fn get_op_batch_flags(num_groups_left: Felt) -> Result<[Felt; 3], ExecutionError> {
    use miden_air::trace::decoder::{
        OP_BATCH_1_GROUPS, OP_BATCH_2_GROUPS, OP_BATCH_4_GROUPS, OP_BATCH_8_GROUPS,
    };
    use miden_core::mast::OP_BATCH_SIZE;

    let num_groups = core::cmp::min(num_groups_left.as_canonical_u64() as usize, OP_BATCH_SIZE);
    match num_groups {
        8 => Ok(OP_BATCH_8_GROUPS),
        4 => Ok(OP_BATCH_4_GROUPS),
        2 => Ok(OP_BATCH_2_GROUPS),
        1 => Ok(OP_BATCH_1_GROUPS),
        _ => Err(ExecutionError::Internal(
            "invalid number of groups in a batch, must be 1, 2, 4, or 8",
        )),
    }
}
