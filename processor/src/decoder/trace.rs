use alloc::vec::Vec;
use core::ops::Range;

#[cfg(test)]
use miden_air::trace::decoder::NUM_USER_OP_HELPERS;
use miden_core::utils::new_array_vec;

use super::{
    super::utils::get_trace_len, DIGEST_LEN, Felt, MIN_TRACE_LEN, NUM_HASHER_COLUMNS,
    NUM_OP_BATCH_FLAGS, NUM_OP_BITS, NUM_OP_BITS_EXTRA_COLS, ONE, OP_BATCH_1_GROUPS,
    OP_BATCH_2_GROUPS, OP_BATCH_4_GROUPS, OP_BATCH_8_GROUPS, OP_BATCH_SIZE, Operation, Word, ZERO,
    get_num_groups_in_next_batch,
};

// CONSTANTS
// ================================================================================================

/// The range of columns in the decoder's `hasher_trace` which is available for use as helper
/// registers during user operations.
pub const USER_OP_HELPERS: Range<usize> = Range { start: 2, end: NUM_HASHER_COLUMNS };

// DECODER TRACE
// ================================================================================================

/// Execution trace of the decoder.
///
/// The trace currently consists of 24 columns grouped logically as follows:
/// - 1 column for code block ID / related hasher table row address.
/// - 7 columns for the binary representation of an opcode.
/// - 8 columns used for providing inputs to, and reading results from the hasher, but also used for
///   other purposes when inside a BASIC BLOCK.
/// - 1 column for the flag indicating whether we are in a BASIC BLOCK or not.
/// - 1 column to keep track of the number of operation groups left to decode in the current BASIC
///   BLOCK.
/// - 1 column to keep track of the index of a currently executing operation within an operation
///   group.
/// - 3 columns for keeping track of operation batch flags.
/// - 2 columns used for op flag degree reduction (to support degree 4 and 5 operations).
pub struct DecoderTrace {
    addr_trace: Vec<Felt>,
    op_bits_trace: [Vec<Felt>; NUM_OP_BITS],
    hasher_trace: [Vec<Felt>; NUM_HASHER_COLUMNS],
    in_span_trace: Vec<Felt>,
    group_count_trace: Vec<Felt>,
    op_idx_trace: Vec<Felt>,
    op_batch_flag_trace: [Vec<Felt>; NUM_OP_BATCH_FLAGS],
    op_bit_extra_trace: [Vec<Felt>; NUM_OP_BITS_EXTRA_COLS],
}

impl DecoderTrace {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Initializes a blank [DecoderTrace].
    pub fn new() -> Self {
        Self {
            addr_trace: Vec::with_capacity(MIN_TRACE_LEN),
            op_bits_trace: new_array_vec(MIN_TRACE_LEN),
            hasher_trace: new_array_vec(MIN_TRACE_LEN),
            group_count_trace: Vec::with_capacity(MIN_TRACE_LEN),
            in_span_trace: Vec::with_capacity(MIN_TRACE_LEN),
            op_idx_trace: Vec::with_capacity(MIN_TRACE_LEN),
            op_batch_flag_trace: new_array_vec(MIN_TRACE_LEN),
            op_bit_extra_trace: new_array_vec(MIN_TRACE_LEN),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the current length of columns in this trace.
    pub fn trace_len(&self) -> usize {
        self.addr_trace.len()
    }

    /// Returns the contents of the first 4 registers of the hasher state at the last row.
    pub fn program_hash(&self) -> [Felt; DIGEST_LEN] {
        let mut result = [ZERO; DIGEST_LEN];
        for (i, element) in result.iter_mut().enumerate() {
            *element = self.last_hasher_value(i);
        }
        result
    }

    // TRACE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Appends a trace row marking the start of a flow control block (JOIN, SPLIT, LOOP, CALL,
    /// SYSCALL, DYN, DYNCALL).
    ///
    /// When a control block is starting, we do the following:
    /// - Set the address to the address of the parent block. This is not necessarily equal to the
    ///   address from the previous row because in a SPLIT block, the second child follows the first
    ///   child, rather than the parent.
    /// - Set op_bits to opcode of the specified block (e.g., JOIN, SPLIT, LOOP, CALL, SYSCALL, DYN,
    ///   DYNCALL).
    /// - Set the first half of the hasher state to the h1 parameter. For JOIN and SPLIT blocks this
    ///   will contain the hash of the left child; for LOOP block this will contain hash of the
    ///   loop's body, for CALL, SYSCALL, DYN and DYNCALL blocks this will contain hash of the
    ///   called function.
    /// - Set the second half of the hasher state to the h2 parameter. For JOIN and SPLIT blocks
    ///   this will contain hash of the right child.
    /// - Set is_span to ZERO.
    /// - Set op group count register to the ZERO.
    /// - Set operation index register to ZERO.
    /// - Set op_batch_flags to ZEROs.
    pub fn append_block_start(&mut self, parent_addr: Felt, op: Operation, h1: Word, h2: Word) {
        self.addr_trace.push(parent_addr);
        self.append_opcode(op);

        self.hasher_trace[0].push(h1[0]);
        self.hasher_trace[1].push(h1[1]);
        self.hasher_trace[2].push(h1[2]);
        self.hasher_trace[3].push(h1[3]);

        self.hasher_trace[4].push(h2[0]);
        self.hasher_trace[5].push(h2[1]);
        self.hasher_trace[6].push(h2[2]);
        self.hasher_trace[7].push(h2[3]);

        self.in_span_trace.push(ZERO);
        self.group_count_trace.push(ZERO);
        self.op_idx_trace.push(ZERO);

        self.op_batch_flag_trace[0].push(ZERO);
        self.op_batch_flag_trace[1].push(ZERO);
        self.op_batch_flag_trace[2].push(ZERO);
    }

    /// Appends a trace row marking the end of a flow control block (JOIN, SPLIT, LOOP, CALL,
    /// SYSCALL).
    ///
    /// When a control block is ending, we do the following:
    /// - Set the block address to the specified address.
    /// - Set op_bits to END opcode.
    /// - Put the provided block hash into the first 4 elements of the hasher state.
    /// - Set the remaining 4 elements of the hasher state to [is_loop_body, is_loop, is_call,
    ///   is_syscall].
    /// - Set in_span to ZERO.
    /// - Copy over op group count from the previous row. This group count must be ZERO.
    /// - Set operation index register to ZERO.
    /// - Set op_batch_flags to ZEROs.
    pub fn append_block_end(
        &mut self,
        block_addr: Felt,
        block_hash: Word,
        is_loop_body: Felt,
        is_loop: Felt,
        is_call: Felt,
        is_syscall: Felt,
    ) {
        debug_assert!(is_loop_body.as_int() <= 1, "invalid is_loop_body");
        debug_assert!(is_loop.as_int() <= 1, "invalid is_loop");
        debug_assert!(is_call.as_int() <= 1, "invalid is_call");
        debug_assert!(is_syscall.as_int() <= 1, "invalid is_syscall");

        self.addr_trace.push(block_addr);
        self.append_opcode(Operation::End);

        self.hasher_trace[0].push(block_hash[0]);
        self.hasher_trace[1].push(block_hash[1]);
        self.hasher_trace[2].push(block_hash[2]);
        self.hasher_trace[3].push(block_hash[3]);

        self.hasher_trace[4].push(is_loop_body);
        self.hasher_trace[5].push(is_loop);
        self.hasher_trace[6].push(is_call);
        self.hasher_trace[7].push(is_syscall);

        self.in_span_trace.push(ZERO);

        let last_group_count = self.last_group_count();
        debug_assert!(last_group_count == ZERO, "group count not zero");
        self.group_count_trace.push(last_group_count);

        self.op_idx_trace.push(ZERO);

        self.op_batch_flag_trace[0].push(ZERO);
        self.op_batch_flag_trace[1].push(ZERO);
        self.op_batch_flag_trace[2].push(ZERO);
    }

    /// Appends a trace row marking the beginning of a new loop iteration.
    ///
    /// When we start a new loop iteration, we do the following:
    /// - Set the block address to the address of the loop block.
    /// - Set op_bits to REPEAT opcode.
    /// - Copy over the hasher state from the previous row. Technically, we need to copy over only
    ///   the first 5 elements of the hasher state, but it is easier to copy over the whole row.
    /// - Set in_span to ZERO.
    /// - Set op group count register to the ZERO.
    /// - Set operation index register to ZERO.
    /// - Set op_batch_flags to ZEROs.
    pub fn append_loop_repeat(&mut self, loop_addr: Felt) {
        self.addr_trace.push(loop_addr);
        self.append_opcode(Operation::Repeat);

        let last_row = get_trace_len(&self.hasher_trace) - 1;
        for column in self.hasher_trace.iter_mut() {
            column.push(column[last_row]);
        }

        self.in_span_trace.push(ZERO);
        self.group_count_trace.push(ZERO);
        self.op_idx_trace.push(ZERO);

        self.op_batch_flag_trace[0].push(ZERO);
        self.op_batch_flag_trace[1].push(ZERO);
        self.op_batch_flag_trace[2].push(ZERO);
    }

    /// Appends a trace row marking the start of a BASIC BLOCK.
    ///
    /// When a BASIC BLOCK is starting, we do the following:
    /// - Set the address to the address of the parent block. This is not necessarily equal to the
    ///   address from the previous row because in a SPLIT block, the second child follows the first
    ///   child, rather than the parent.
    /// - Set op_bits to SPAN opcode.
    /// - Set hasher state to op groups of the first op batch of the BASIC BLOCK.
    /// - Set is_span to ZERO. is_span will be set to one in the following row.
    /// - Set op group count to the total number of op groups in the BASIC BLOCK.
    /// - Set operation index register to ZERO.
    /// - Set the op_batch_flags based on the specified number of operation groups.
    pub fn append_span_start(
        &mut self,
        parent_addr: Felt,
        first_op_batch: &[Felt; OP_BATCH_SIZE],
        num_op_groups: Felt,
    ) {
        self.addr_trace.push(parent_addr);
        self.append_opcode(Operation::Span);
        for (i, &op_group) in first_op_batch.iter().enumerate() {
            self.hasher_trace[i].push(op_group);
        }

        self.in_span_trace.push(ZERO);
        self.group_count_trace.push(num_op_groups);
        self.op_idx_trace.push(ZERO);

        let op_batch_flags = get_op_batch_flags(num_op_groups);
        self.op_batch_flag_trace[0].push(op_batch_flags[0]);
        self.op_batch_flag_trace[1].push(op_batch_flags[1]);
        self.op_batch_flag_trace[2].push(op_batch_flags[2]);
    }

    /// Appends a trace row marking a RESPAN operation.
    ///
    /// When a RESPAN operation is executed, we do the following:
    /// - Copy over the block address from the previous row. The BASIC BLOCK address will be updated
    ///   in the following row.
    /// - Set op_bits to RESPAN opcode.
    /// - Set hasher state to op groups of the next op batch of the BASIC BLOCK.
    /// - Set in_span to ZERO.
    /// - Copy over op group count from the previous row.
    /// - Set operation index register to ZERO.
    /// - Set the op_batch_flags based on the current operation group count.
    pub fn append_respan(&mut self, op_batch: &[Felt; OP_BATCH_SIZE]) {
        self.addr_trace.push(self.last_addr());
        self.append_opcode(Operation::Respan);
        for (i, &op_group) in op_batch.iter().enumerate() {
            self.hasher_trace[i].push(op_group);
        }

        let group_count = self.last_group_count();
        self.in_span_trace.push(ZERO);
        self.group_count_trace.push(group_count);
        self.op_idx_trace.push(ZERO);

        let op_batch_flags = get_op_batch_flags(group_count);
        self.op_batch_flag_trace[0].push(op_batch_flags[0]);
        self.op_batch_flag_trace[1].push(op_batch_flags[1]);
        self.op_batch_flag_trace[2].push(op_batch_flags[2]);
    }

    /// Appends a trace row for a user operation.
    ///
    /// When we execute a user operation in a BASIC BLOCK, we do the following:
    /// - Set the address of the row to the address of the basic block.
    /// - Set op_bits to the opcode of the executed operation.
    /// - Set the first hasher state register to the aggregation of remaining operations to be
    ///   executed in the current operation group.
    /// - Set the second hasher state register to the address of the BASIC BLOCK's parent block.
    /// - Set the remaining hasher state registers to ZEROs.
    /// - Set is_span to ONE.
    /// - Set the number of groups remaining to be processed. This number of groups changes if in
    ///   the previous row an operation with an immediate value was executed or if this operation is
    ///   a start of a new operation group.
    /// - Set the operation's index within the current operation group.
    /// - Set op_batch_flags to ZEROs.
    pub fn append_user_op(
        &mut self,
        op: Operation,
        basic_block_addr: Felt,
        parent_addr: Felt,
        num_groups_left: Felt,
        group_ops_left: Felt,
        op_idx: Felt,
    ) {
        self.addr_trace.push(basic_block_addr);
        self.append_opcode(op);

        self.hasher_trace[0].push(group_ops_left);
        self.hasher_trace[1].push(parent_addr);

        // Note: use `Decoder::set_user_op_helpers()` when processing an instruction to set any of
        // these values to something other than 0
        for idx in USER_OP_HELPERS {
            self.hasher_trace[idx].push(ZERO);
        }

        self.in_span_trace.push(ONE);
        self.group_count_trace.push(num_groups_left);
        self.op_idx_trace.push(op_idx);

        self.op_batch_flag_trace[0].push(ZERO);
        self.op_batch_flag_trace[1].push(ZERO);
        self.op_batch_flag_trace[2].push(ZERO);
    }

    /// Appends a trace row marking the end of a BASIC BLOCK.
    ///
    /// When the BASIC BLOCK is ending, we do the following:
    /// - Copy over the block address from the previous row.
    /// - Set op_bits to END opcode.
    /// - Put the hash of the basic block into the first 4 registers of the hasher state.
    /// - Put a flag indicating whether the BASIC BLOCK was a body of a loop into the 5th register
    ///   of the hasher state.
    /// - Set in_span to ZERO to indicate that the basic block is completed.
    /// - Copy over op group count from the previous row. This group count must be ZERO.
    /// - Set operation index register to ZERO.
    /// - Set op_batch_flags to ZEROs.
    pub fn append_span_end(&mut self, span_hash: Word, is_loop_body: Felt) {
        debug_assert!(is_loop_body.as_int() <= 1, "invalid loop body");

        self.addr_trace.push(self.last_addr());
        self.append_opcode(Operation::End);

        self.hasher_trace[0].push(span_hash[0]);
        self.hasher_trace[1].push(span_hash[1]);
        self.hasher_trace[2].push(span_hash[2]);
        self.hasher_trace[3].push(span_hash[3]);

        // we don't need to set is_loop, is_call, and is_syscall here because we know that this
        // is a BASIC BLOCK
        self.hasher_trace[4].push(is_loop_body);
        self.hasher_trace[5].push(ZERO);
        self.hasher_trace[6].push(ZERO);
        self.hasher_trace[7].push(ZERO);

        self.in_span_trace.push(ZERO);

        let last_group_count = self.last_group_count();
        debug_assert!(last_group_count == ZERO, "group count not zero");
        self.group_count_trace.push(last_group_count);

        self.op_idx_trace.push(ZERO);

        self.op_batch_flag_trace[0].push(ZERO);
        self.op_batch_flag_trace[1].push(ZERO);
        self.op_batch_flag_trace[2].push(ZERO);
    }

    // TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Returns vector of columns of this execution trace.
    ///
    /// Each column in the trace is extended to the specified trace length. The extension is done
    /// by inserting ZEROs into the unfilled rows of most columns. The only exceptions are:
    /// - The op_bits columns, where the unfilled rows are filled with the opcode of the HALT
    ///   operation.
    /// - The first 4 columns of the hasher state, where the unfilled rows are filled with the
    ///   values from the last filled row. This is done so that the hash of the program is
    ///   propagated to the last row.
    pub fn into_vec(mut self, trace_len: usize, num_rand_rows: usize) -> Vec<Vec<Felt>> {
        let own_len = self.trace_len();
        // make sure that only the duplicate rows will be overwritten with random values
        assert!(own_len + num_rand_rows <= trace_len, "target trace length too small");

        let mut trace = Vec::new();

        // put ZEROs into the unfilled rows of block address column
        self.addr_trace.resize(trace_len, ZERO);
        trace.push(self.addr_trace);

        // insert HALT opcode into the unfilled rows of op_bits columns
        let halt_opcode = Operation::Halt.op_code();
        for (i, mut column) in self.op_bits_trace.into_iter().enumerate() {
            debug_assert_eq!(own_len, column.len());
            let value = Felt::from((halt_opcode >> i) & 1);
            column.resize(trace_len, value);
            trace.push(column);
        }

        // for unfilled rows of hasher state columns, copy over values from the last row for the
        // first 4 columns, and pad the other 4 columns with ZEROs
        for (i, mut column) in self.hasher_trace.into_iter().enumerate() {
            debug_assert_eq!(own_len, column.len());
            if i < 4 {
                let last_value = *column.last().expect("no last hasher trace value");
                column.resize(trace_len, last_value);
            } else {
                column.resize(trace_len, ZERO);
            }
            trace.push(column);
        }

        // put ZEROs into the unfilled rows of in_span column
        debug_assert_eq!(own_len, self.in_span_trace.len());
        self.in_span_trace.resize(trace_len, ZERO);
        trace.push(self.in_span_trace);

        // put ZEROs into the unfilled rows of operation group count column
        debug_assert_eq!(own_len, self.group_count_trace.len());
        self.group_count_trace.resize(trace_len, ZERO);
        trace.push(self.group_count_trace);

        // put ZEROs into the unfilled rows of operation index column
        debug_assert_eq!(own_len, self.op_idx_trace.len());
        self.op_idx_trace.resize(trace_len, ZERO);
        trace.push(self.op_idx_trace);

        // put ZEROs into the unfilled rows of op_batch_flags columns
        for mut column in self.op_batch_flag_trace.into_iter() {
            debug_assert_eq!(own_len, column.len());
            column.resize(trace_len, ZERO);
            trace.push(column);
        }

        // finalize the op bit extra columns
        let [mut op_bit_extra_0, mut op_bit_extra_1] = self.op_bit_extra_trace;
        debug_assert_eq!(own_len, op_bit_extra_0.len());
        debug_assert_eq!(own_len, op_bit_extra_1.len());

        // put ZEROs into the unfilled rows of the first op bit extra column, because the HALT
        // operation does not use this column.
        op_bit_extra_0.resize(trace_len, ZERO);
        trace.push(op_bit_extra_0);

        // put ONEs into the unfilled rows of the second op bit extra column. we put ONE because the
        // two most significant bits of the HALT operation are ONE and this column is computed as
        // the product of the two most significant op bits.
        debug_assert_eq!(1, (halt_opcode >> 6) & 1);
        debug_assert_eq!(1, (halt_opcode >> 5) & 1);
        op_bit_extra_1.resize(trace_len, ONE);
        trace.push(op_bit_extra_1);

        trace
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Returns the last block address.
    fn last_addr(&self) -> Felt {
        *self.addr_trace.last().expect("no last addr")
    }

    /// Returns the last value of the operation group count.
    fn last_group_count(&self) -> Felt {
        *self.group_count_trace.last().expect("no group count")
    }

    /// Returns the last value in the specified hasher column.
    fn last_hasher_value(&self, idx: usize) -> Felt {
        debug_assert!(idx < NUM_HASHER_COLUMNS, "invalid hasher register index");
        *self.hasher_trace[idx].last().expect("no last hasher value")
    }

    /// Returns a reference to the last value in the helper register at the specified index.
    fn last_helper_mut(&mut self, idx: usize) -> &mut Felt {
        debug_assert!(idx < USER_OP_HELPERS.len(), "invalid helper register index");

        self.hasher_trace[USER_OP_HELPERS.start + idx]
            .last_mut()
            .expect("no last helper value")
    }

    /// Populates op_bits registers for the next row with the opcode of the provided operation.
    fn append_opcode(&mut self, op: Operation) {
        let op_code = op.op_code();
        for i in 0..NUM_OP_BITS {
            let bit = Felt::from((op_code >> i) & 1);
            self.op_bits_trace[i].push(bit);
        }

        // populate the op bit extra columns used for degree reduction
        let clk = self.op_bit_extra_trace[0].len();
        let bit6 = self.op_bits_trace[NUM_OP_BITS - 1][clk];
        let bit5 = self.op_bits_trace[NUM_OP_BITS - 2][clk];
        let bit4 = self.op_bits_trace[NUM_OP_BITS - 3][clk];
        self.op_bit_extra_trace[0].push(bit6 * (ONE - bit5) * bit4);
        self.op_bit_extra_trace[1].push(bit6 * bit5);
    }

    /// Add all provided values to the helper registers in the order provided, starting from the
    /// first hasher register that is available for user operation helper values.
    ///
    /// The specified USER_OP_HELPERS in the `hasher_trace` are used as helper registers, since they
    /// are not required for hashing during execution of user operations.
    pub fn set_user_op_helpers(&mut self, values: &[Felt]) {
        assert!(values.len() <= USER_OP_HELPERS.len(), "too many values for helper columns");

        for (idx, value) in values.iter().enumerate() {
            *self.last_helper_mut(idx) = *value;
        }
    }

    // TEST METHODS
    // --------------------------------------------------------------------------------------------

    /// Adds a new decoder trace row of zeros for testing purposes.
    #[cfg(test)]
    pub fn add_dummy_row(&mut self) {
        self.addr_trace.push(ZERO);
        for column in self.op_bits_trace.iter_mut() {
            column.push(ZERO);
        }
        self.in_span_trace.push(ZERO);
        for column in self.hasher_trace.iter_mut() {
            column.push(ZERO);
        }
        self.group_count_trace.push(ZERO);
        self.op_idx_trace.push(ZERO);
    }

    /// Fetches all the helper registers from the trace.
    #[cfg(test)]
    pub fn get_user_op_helpers(&self) -> [Felt; NUM_USER_OP_HELPERS] {
        let mut result = [ZERO; NUM_USER_OP_HELPERS];
        for (idx, helper) in result.iter_mut().enumerate() {
            *helper = *self.hasher_trace[USER_OP_HELPERS.start + idx]
                .last()
                .expect("no last helper value");
        }
        result
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns op batch flags for the specified group count. If the group count is greater than 8,
/// we assume that the operation batch is full - i.e., has 8 operation groups.
fn get_op_batch_flags(num_groups_left: Felt) -> [Felt; NUM_OP_BATCH_FLAGS] {
    let num_groups = get_num_groups_in_next_batch(num_groups_left);
    match num_groups {
        8 => OP_BATCH_8_GROUPS,
        4 => OP_BATCH_4_GROUPS,
        2 => OP_BATCH_2_GROUPS,
        1 => OP_BATCH_1_GROUPS,
        _ => panic!(
            "invalid number of groups in a batch: {num_groups}, group count: {num_groups_left}"
        ),
    }
}
