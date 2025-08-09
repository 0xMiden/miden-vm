use core::ops::ControlFlow;

use miden_air::trace::{
    CLK_COL_IDX, CTX_COL_IDX, DECODER_TRACE_OFFSET, FMP_COL_IDX, FN_HASH_OFFSET,
    IN_SYSCALL_COL_IDX, STACK_TRACE_OFFSET, SYS_TRACE_WIDTH,
    decoder::{
        ADDR_COL_IDX, GROUP_COUNT_COL_IDX, HASHER_STATE_OFFSET, IN_SPAN_COL_IDX,
        NUM_OP_BATCH_FLAGS, NUM_OP_BITS, OP_BATCH_FLAGS_OFFSET, OP_BITS_EXTRA_COLS_OFFSET,
        OP_BITS_OFFSET, OP_INDEX_COL_IDX,
    },
    stack::{B0_COL_IDX, B1_COL_IDX, H0_COL_IDX, STACK_TOP_OFFSET, STACK_TOP_RANGE},
};
use miden_core::{Felt, ONE, Word, ZERO};

use super::{CoreTraceFragmentGenerator, TraceRowType};
use crate::{decoder::block_stack::BlockInfo, processor::Processor};

/// Configuration for operation-specific trace row data
#[derive(Debug)]
pub struct OperationTraceConfig {
    /// The operation code for start operations
    pub start_opcode: u8,
    /// The two child hashes for start operations (first hash, second hash)
    pub start_hasher_state: (Word, Word),
    /// The node digest for end operations
    pub end_node_digest: Word,
    /// The address field to write into trace
    pub addr: Felt,
    /// Block info for end operations (contains the block type flags)
    pub block_info: Option<BlockInfo>,
}

impl CoreTraceFragmentGenerator {
    /// Adds a trace row for a control flow operation (JOIN/SPLIT start or end) to the main trace
    /// fragment.
    ///
    /// This is a shared implementation that handles the common trace row generation logic
    /// for both JOIN and SPLIT operations. The operation-specific details are provided
    /// through the `config` parameter.
    pub fn add_control_flow_trace_row(
        &mut self,
        config: OperationTraceConfig,
        trace_type: TraceRowType,
    ) -> ControlFlow<()> {
        let row_idx = self.num_rows_built();

        // System trace columns (identical for all control flow operations)
        self.populate_system_trace_columns(row_idx);

        // Decoder trace columns
        self.populate_decoder_trace_columns(row_idx, &config, trace_type);

        // Stack trace columns (identical for all control flow operations)
        self.populate_stack_trace_columns(row_idx);

        // Increment clock
        self.increment_clk()
    }

    /// Populates the system trace columns
    pub fn populate_system_trace_columns(&mut self, row_idx: usize) {
        // If we have buffered system rows from the previous call, write them to the trace
        if let Some(system_rows) = self.system_rows {
            // Write buffered system rows to the trace at current row
            for (i, &value) in system_rows.iter().enumerate() {
                self.fragment.columns[i][row_idx] = value;
            }
        }

        // Now populate the buffer with current system state for the next row
        let mut new_system_rows = [ZERO; SYS_TRACE_WIDTH];

        new_system_rows[CLK_COL_IDX] = Felt::from(self.state.system.clk + 1); // clk
        new_system_rows[FMP_COL_IDX] = self.state.system.fmp; // fmp
        new_system_rows[CTX_COL_IDX] = Felt::from(self.state.system.ctx); // ctx
        new_system_rows[IN_SYSCALL_COL_IDX] = if self.state.system.in_syscall { ONE } else { ZERO }; // in_syscall flag
        new_system_rows[FN_HASH_OFFSET] = self.state.system.fn_hash[0]; // fn_hash[0]
        new_system_rows[FN_HASH_OFFSET + 1] = self.state.system.fn_hash[1]; // fn_hash[1]
        new_system_rows[FN_HASH_OFFSET + 2] = self.state.system.fn_hash[2]; // fn_hash[2]
        new_system_rows[FN_HASH_OFFSET + 3] = self.state.system.fn_hash[3]; // fn_hash[3]

        // Store the buffer for the next call
        self.system_rows = Some(new_system_rows);
    }

    /// Populates the decoder trace columns with operation-specific data
    fn populate_decoder_trace_columns(
        &mut self,
        row_idx: usize,
        config: &OperationTraceConfig,
        trace_type: TraceRowType,
    ) {
        // Block address
        self.fragment.columns[DECODER_TRACE_OFFSET + ADDR_COL_IDX][row_idx] = config.addr;

        // Operation bits and hasher state differ based on trace type
        match trace_type {
            TraceRowType::Start => {
                // Operation bits for the specific operation (JOIN/SPLIT)
                let opcode = config.start_opcode;
                for i in 0..NUM_OP_BITS {
                    let bit = Felt::from((opcode >> i) & 1);
                    self.fragment.columns[DECODER_TRACE_OFFSET + OP_BITS_OFFSET + i][row_idx] = bit;
                }

                // Hasher state (8 columns) - first half gets first hash, second half gets second
                // hash
                let (first_hash, second_hash) = config.start_hasher_state;
                self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET][row_idx] =
                    first_hash[0]; // hasher[0]
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
            },
            TraceRowType::End => {
                // Operation bits for END opcode
                let end_opcode = miden_core::Operation::End.op_code();
                for i in 0..NUM_OP_BITS {
                    let bit = Felt::from((end_opcode >> i) & 1);
                    self.fragment.columns[DECODER_TRACE_OFFSET + OP_BITS_OFFSET + i][row_idx] = bit;
                }

                // Hasher state (8 columns) - set to the node's digest in first half, zeros in
                // second half
                let node_digest = config.end_node_digest;
                self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET][row_idx] =
                    node_digest[0]; // hasher[0]
                self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 1][row_idx] =
                    node_digest[1]; // hasher[1]
                self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 2][row_idx] =
                    node_digest[2]; // hasher[2]
                self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 3][row_idx] =
                    node_digest[3]; // hasher[3]

                // TODO(plafer): cleanup
                // Second half contains block type flags - use the block info from config for END
                // operations
                let block_info = config
                    .block_info
                    .as_ref()
                    .expect("Block info must be provided for END operations");
                self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 4][row_idx] =
                    block_info.is_loop_body();
                self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 5][row_idx] =
                    block_info.is_entered_loop();
                self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 6][row_idx] =
                    block_info.is_call();
                self.fragment.columns[DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + 7][row_idx] =
                    block_info.is_syscall();
            },
        }

        // Remaining decoder trace columns (identical for all control flow operations)
        self.fragment.columns[DECODER_TRACE_OFFSET + OP_INDEX_COL_IDX][row_idx] = ZERO;
        self.fragment.columns[DECODER_TRACE_OFFSET + GROUP_COUNT_COL_IDX][row_idx] = ZERO;
        self.fragment.columns[DECODER_TRACE_OFFSET + IN_SPAN_COL_IDX][row_idx] = ZERO;

        // Batch flag columns - all 0 for control flow operations
        for i in 0..NUM_OP_BATCH_FLAGS {
            self.fragment.columns[DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET + i][row_idx] = ZERO;
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
    pub fn populate_stack_trace_columns(&mut self, row_idx: usize) {
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
            new_stack_rows[STACK_TOP_OFFSET + i] = self.stack_get(i);
        }

        // Stack helpers (b0, b1, h0)
        // Note: H0 will be inverted using batch inversion later
        new_stack_rows[B0_COL_IDX] = self.state.stack.stack_depth(); // b0
        new_stack_rows[B1_COL_IDX] = self.state.stack.overflow_addr(); // b1
        new_stack_rows[H0_COL_IDX] = self.state.stack.overflow_helper(); // h0

        // Store the buffer for the next call
        self.stack_rows = Some(new_stack_rows);
    }
}
