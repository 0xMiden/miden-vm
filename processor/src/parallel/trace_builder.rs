use core::ops::ControlFlow;

use miden_air::trace::{
    CLK_COL_IDX, CTX_COL_IDX, DECODER_TRACE_OFFSET, FN_HASH_OFFSET, STACK_TRACE_OFFSET,
    SYS_TRACE_WIDTH,
    decoder::{
        ADDR_COL_IDX, GROUP_COUNT_COL_IDX, HASHER_STATE_OFFSET, IN_SPAN_COL_IDX,
        NUM_OP_BATCH_FLAGS, NUM_OP_BITS, OP_BATCH_FLAGS_OFFSET, OP_BITS_EXTRA_COLS_OFFSET,
        OP_BITS_OFFSET, OP_INDEX_COL_IDX,
    },
    stack::{B0_COL_IDX, B1_COL_IDX, H0_COL_IDX, STACK_TOP_OFFSET, STACK_TOP_RANGE},
};
use miden_core::{Felt, ONE, Operation, Word, ZERO};

use super::CoreTraceFragmentFiller;
use crate::{fast::trace_state::NodeFlags, processor::StackInterface};

/// Configuration for operation-specific trace row data
#[derive(Debug)]
pub struct OperationTraceConfig {
    /// The operation code for start operations
    pub opcode: u8,
    /// The two child hashes for start operations (first hash, second hash)
    pub hasher_state: (Word, Word),
    /// The address field to write into trace
    pub addr: Felt,
}

impl<'a> CoreTraceFragmentFiller<'a> {
    // TODO(plafer): move in a different file (when we merge all the other control flow ones)
    pub fn add_end_trace_row(&mut self, node_digest: Word) -> ControlFlow<()> {
        // Pop the block from stack and use its info for END operations
        let (ended_node_addr, flags) = self.update_decoder_state_on_node_end();

        self.add_end_trace_row_impl(node_digest, flags, ended_node_addr)
    }

    pub fn add_end_trace_row_impl(
        &mut self,
        node_digest: Word,
        flags: NodeFlags,
        ended_node_addr: Felt,
    ) -> ControlFlow<()> {
        let config = OperationTraceConfig {
            opcode: Operation::End.op_code(),
            hasher_state: (node_digest, flags.to_hasher_state_second_word()),
            addr: ended_node_addr,
        };

        // Reset the span context after completing the basic block
        self.span_context = None;

        self.add_control_flow_trace_row(config)
    }

    /// Adds a trace row for a control flow operation (JOIN/SPLIT start or end) to the main trace
    /// fragment.
    ///
    /// This is a shared implementation that handles the common trace row generation logic
    /// for both JOIN and SPLIT operations. The operation-specific details are provided
    /// through the `config` parameter.
    pub fn add_control_flow_trace_row(&mut self, config: OperationTraceConfig) -> ControlFlow<()> {
        let row_idx = self.num_rows_built();

        // System trace columns (identical for all control flow operations)
        self.populate_system_trace_columns(row_idx);

        // Decoder trace columns
        self.populate_decoder_trace_columns(row_idx, &config);

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

        new_system_rows[CLK_COL_IDX] = Felt::from(self.context.state.system.clk + 1); // clk
        new_system_rows[CTX_COL_IDX] = Felt::from(self.context.state.system.ctx); // ctx
        new_system_rows[FN_HASH_OFFSET] = self.context.state.system.fn_hash[0]; // fn_hash[0]
        new_system_rows[FN_HASH_OFFSET + 1] = self.context.state.system.fn_hash[1]; // fn_hash[1]
        new_system_rows[FN_HASH_OFFSET + 2] = self.context.state.system.fn_hash[2]; // fn_hash[2]
        new_system_rows[FN_HASH_OFFSET + 3] = self.context.state.system.fn_hash[3]; // fn_hash[3]

        // Store the buffer for the next call
        self.system_rows = Some(new_system_rows);
    }

    /// Populates the decoder trace columns with operation-specific data
    fn populate_decoder_trace_columns(&mut self, row_idx: usize, config: &OperationTraceConfig) {
        // Block address
        self.fragment.columns[DECODER_TRACE_OFFSET + ADDR_COL_IDX][row_idx] = config.addr;

        // Decompose operation into bits
        let opcode = config.opcode;
        for i in 0..NUM_OP_BITS {
            let bit = Felt::from((opcode >> i) & 1);
            self.fragment.columns[DECODER_TRACE_OFFSET + OP_BITS_OFFSET + i][row_idx] = bit;
        }

        // Hasher state
        let (first_hash, second_hash) = config.hasher_state;
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
