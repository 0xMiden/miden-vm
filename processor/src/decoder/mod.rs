use alloc::vec::Vec;

use miden_air::{
    RowIndex,
    trace::{
        chiplets::hasher::DIGEST_LEN,
        decoder::{
            NUM_HASHER_COLUMNS, NUM_OP_BATCH_FLAGS, NUM_OP_BITS, NUM_OP_BITS_EXTRA_COLS,
            OP_BATCH_1_GROUPS, OP_BATCH_2_GROUPS, OP_BATCH_4_GROUPS, OP_BATCH_8_GROUPS,
        },
    },
};
#[cfg(test)]
use miden_core::mast::OP_GROUP_SIZE;
use miden_core::{
    AssemblyOp,
    mast::{
        BasicBlockNode, CallNode, DynNode, JoinNode, LoopNode, MastForest, MastNodeExt,
        OP_BATCH_SIZE, SplitNode,
    },
    stack::MIN_STACK_DEPTH,
};

use super::{
    EMPTY_WORD, ExecutionError, Felt, MIN_TRACE_LEN, ONE, OpBatch, Operation, Process, Word, ZERO,
};
use crate::{SyncHost, errors::ErrorContext};

mod trace;
use trace::DecoderTrace;

mod aux_trace;
pub use aux_trace::AuxTraceBuilder;
#[cfg(test)]
pub use aux_trace::BlockHashTableRow;

pub mod block_stack;
use block_stack::{BlockStack, BlockType, ExecutionContextInfo};
#[cfg(test)]
use miden_air::trace::decoder::NUM_USER_OP_HELPERS;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

const HASH_CYCLE_LEN: Felt = Felt::new(miden_air::trace::chiplets::hasher::HASH_CYCLE_LEN as u64);

// DECODER PROCESS EXTENSION
// ================================================================================================

impl Process {
    // JOIN NODE
    // --------------------------------------------------------------------------------------------

    /// Starts decoding of a JOIN node.
    pub(super) fn start_join_node<H: SyncHost>(
        &mut self,
        node: &JoinNode,
        program: &MastForest,
        host: &mut H,
    ) -> Result<(), ExecutionError> {
        // use the hasher to compute the hash of the JOIN block; the row address returned by the
        // hasher is used as the ID of the block; the result of the hash is expected to be in
        // row addr + 7.
        let child1_hash = program
            .get_node_by_id(node.first())
            .ok_or(ExecutionError::MastNodeNotFoundInForest { node_id: node.first() })?
            .digest();
        let child2_hash = program
            .get_node_by_id(node.second())
            .ok_or(ExecutionError::MastNodeNotFoundInForest { node_id: node.second() })?
            .digest();

        let (addr, hashed_block) = self.chiplets.hasher.hash_control_block(
            child1_hash,
            child2_hash,
            JoinNode::DOMAIN,
            node.digest(),
        );

        debug_assert_eq!(node.digest(), hashed_block);

        // start decoding the JOIN block; this appends a row with JOIN operation to the decoder
        // trace. when JOIN operation is executed, the rest of the VM state does not change
        self.decoder.start_join(child1_hash, child2_hash, addr);
        self.execute_op(Operation::Noop, program, host)
    }

    ///  Ends decoding of a JOIN node.
    pub(super) fn end_join_node<H: SyncHost>(
        &mut self,
        node: &JoinNode,
        program: &MastForest,
        host: &mut H,
    ) -> Result<(), ExecutionError> {
        // this appends a row with END operation to the decoder trace. when END operation is
        // executed the rest of the VM state does not change
        self.decoder.end_control_block(node.digest());

        self.execute_op(Operation::Noop, program, host)
    }

    // SPLIT NODE
    // --------------------------------------------------------------------------------------------

    /// Starts decoding a SPLIT node. This also pops the value from the top of the stack and
    /// returns it.
    pub(super) fn start_split_node<H: SyncHost>(
        &mut self,
        node: &SplitNode,
        program: &MastForest,
        host: &mut H,
    ) -> Result<Felt, ExecutionError> {
        let condition = self.stack.peek();

        // use the hasher to compute the hash of the SPLIT block; the row address returned by the
        // hasher is used as the ID of the block; the result of the hash is expected to be in
        // row addr + 7.
        let child1_hash = program
            .get_node_by_id(node.on_true())
            .ok_or(ExecutionError::MastNodeNotFoundInForest { node_id: node.on_true() })?
            .digest();
        let child2_hash = program
            .get_node_by_id(node.on_false())
            .ok_or(ExecutionError::MastNodeNotFoundInForest { node_id: node.on_false() })?
            .digest();
        let (addr, hashed_block) = self.chiplets.hasher.hash_control_block(
            child1_hash,
            child2_hash,
            SplitNode::DOMAIN,
            node.digest(),
        );

        debug_assert_eq!(node.digest(), hashed_block);

        // start decoding the SPLIT block. this appends a row with SPLIT operation to the decoder
        // trace. we also pop the value off the top of the stack and return it.
        self.decoder.start_split(child1_hash, child2_hash, addr);
        self.execute_op(Operation::Drop, program, host)?;
        Ok(condition)
    }

    /// Ends decoding of a SPLIT node.
    pub(super) fn end_split_node<H: SyncHost>(
        &mut self,
        block: &SplitNode,
        program: &MastForest,
        host: &mut H,
    ) -> Result<(), ExecutionError> {
        // this appends a row with END operation to the decoder trace. when END operation is
        // executed the rest of the VM state does not change
        self.decoder.end_control_block(block.digest());

        self.execute_op(Operation::Noop, program, host)
    }

    // LOOP NODE
    // --------------------------------------------------------------------------------------------

    /// Starts decoding a LOOP node. This also pops the value from the top of the stack and
    /// returns it.
    pub(super) fn start_loop_node<H: SyncHost>(
        &mut self,
        node: &LoopNode,
        program: &MastForest,
        host: &mut H,
    ) -> Result<Felt, ExecutionError> {
        let condition = self.stack.peek();

        // use the hasher to compute the hash of the LOOP block; for LOOP block there is no
        // second child so we set the second hash to ZEROs; the row address returned by the
        // hasher is used as the ID of the block; the result of the hash is expected to be in
        // row addr + 7.
        let body_hash = program
            .get_node_by_id(node.body())
            .ok_or(ExecutionError::MastNodeNotFoundInForest { node_id: node.body() })?
            .digest();

        let (addr, hashed_block) = self.chiplets.hasher.hash_control_block(
            body_hash,
            EMPTY_WORD,
            LoopNode::DOMAIN,
            node.digest(),
        );

        debug_assert_eq!(node.digest(), hashed_block);

        // start decoding the LOOP block; this appends a row with LOOP operation to the decoder
        // trace, but if the value on the top of the stack is not ONE, the block is not marked
        // as the loop block, and the hash of the body will not be added to the block hash table.
        // basically, if the top of the stack is ZERO, a LOOP operation should be immediately
        // followed by an END operation.
        self.decoder.start_loop(body_hash, addr, condition);
        self.execute_op(Operation::Drop, program, host)?;
        Ok(condition)
    }

    /// Ends decoding of a LOOP block. If pop_stack is set to true, this also removes the
    /// value at the top of the stack.
    pub(super) fn end_loop_node<H: SyncHost>(
        &mut self,
        node: &LoopNode,
        pop_stack: bool,
        program: &MastForest,
        host: &mut H,
    ) -> Result<(), ExecutionError> {
        // this appends a row with END operation to the decoder trace.
        self.decoder.end_control_block(node.digest());

        // if we are exiting a loop, we also need to pop the top value off the stack (and this
        // value must be ZERO - otherwise, we should have stayed in the loop). but, if we never
        // entered the loop in the first place, the stack would have been popped when the LOOP
        // operation was executed.
        if pop_stack {
            // make sure the condition at the top of the stack is set to ZERO
            #[cfg(debug_assertions)]
            debug_assert_eq!(ZERO, self.stack.peek());

            self.execute_op(Operation::Drop, program, host)
        } else {
            self.execute_op(Operation::Noop, program, host)
        }
    }

    // CALL NODE
    // --------------------------------------------------------------------------------------------

    /// Starts decoding of a CALL or a SYSCALL node.
    pub(super) fn start_call_node<H: SyncHost>(
        &mut self,
        node: &CallNode,
        program: &MastForest,
        host: &mut H,
    ) -> Result<(), ExecutionError> {
        // use the hasher to compute the hash of the CALL or SYSCALL block; the row address
        // returned by the hasher is used as the ID of the block; the result of the hash is
        // expected to be in row addr + 7.
        let callee_hash = program
            .get_node_by_id(node.callee())
            .ok_or(ExecutionError::MastNodeNotFoundInForest { node_id: node.callee() })?
            .digest();

        let (addr, hashed_block) = self.chiplets.hasher.hash_control_block(
            callee_hash,
            EMPTY_WORD,
            node.domain(),
            node.digest(),
        );

        debug_assert_eq!(node.digest(), hashed_block);

        // start new execution context for the operand stack. this has the effect of resetting
        // stack depth to 16.
        let (stack_depth, next_overflow_addr) = self.stack.start_context();
        debug_assert!(stack_depth <= u32::MAX as usize, "stack depth too big");

        // update the system registers and start decoding the block; this appends a row with
        // CALL/SYSCALL operation to the decoder trace and records information about the current
        // execution context in the block stack table. this info will be used to restore the
        // context after the function returns.
        let ctx_info = ExecutionContextInfo::new(
            self.system.ctx(),
            self.system.fn_hash(),
            self.system.fmp(),
            stack_depth as u32,
            next_overflow_addr,
        );

        if node.is_syscall() {
            self.system.start_syscall();
            self.decoder.start_syscall(callee_hash, addr, ctx_info);
        } else {
            self.system.start_call_or_dyncall(callee_hash);
            self.decoder.start_call(callee_hash, addr, ctx_info);
        }

        // the rest of the VM state does not change
        self.execute_op(Operation::Noop, program, host)
    }

    /// Ends decoding of a CALL or a SYSCALL block.
    pub(super) fn end_call_node<H: SyncHost>(
        &mut self,
        node: &CallNode,
        program: &MastForest,
        host: &mut H,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        // when a CALL block ends, stack depth must be exactly 16
        let stack_depth = self.stack.depth();
        if stack_depth > MIN_STACK_DEPTH {
            return Err(ExecutionError::invalid_stack_depth_on_return(stack_depth, err_ctx));
        }

        // this appends a row with END operation to the decoder trace; the returned value contains
        // information about the execution context prior to execution of the CALL block
        let ctx_info = self.decoder.end_control_block(node.digest()).expect("no execution context");

        // when returning from a function call or a syscall, restore the context of the system
        // registers and the operand stack to what it was prior to the call.
        self.system.restore_context(
            ctx_info.parent_ctx,
            ctx_info.parent_fmp,
            ctx_info.parent_fn_hash,
        );
        self.stack.restore_context(ctx_info.parent_stack_depth as usize);

        // the rest of the VM state does not change
        self.execute_op(Operation::Noop, program, host)
    }

    // DYN NODE
    // --------------------------------------------------------------------------------------------

    /// Starts decoding of a DYN node.
    ///
    /// Note: even though we will write the callee hash to h[0..4] for the chiplets bus and block
    /// hash table, the issued hash request is still hash([ZERO; 8]).
    pub(super) fn start_dyn_node<H: SyncHost>(
        &mut self,
        dyn_node: &DynNode,
        program: &MastForest,
        host: &mut H,
        err_ctx: &impl ErrorContext,
    ) -> Result<Word, ExecutionError> {
        debug_assert!(!dyn_node.is_dyncall());

        let mem_addr = self.stack.get(0);
        // The callee hash is stored in memory, and the address is specified on the top of the
        // stack.
        let callee_hash = self
            .chiplets
            .memory
            .read_word(self.system.ctx(), mem_addr, self.system.clk(), err_ctx)
            .map_err(ExecutionError::MemoryError)?;

        let (addr, hashed_block) = self.chiplets.hasher.hash_control_block(
            EMPTY_WORD,
            EMPTY_WORD,
            dyn_node.domain(),
            dyn_node.digest(),
        );

        debug_assert_eq!(dyn_node.digest(), hashed_block);

        self.decoder.start_dyn(addr, callee_hash);

        // Pop the memory address off the stack.
        self.execute_op(Operation::Drop, program, host)?;

        Ok(callee_hash)
    }

    /// Starts decoding of a DYNCALL node.
    ///
    /// Note: even though we will write the callee hash to h[0..4] for the chiplets bus and block
    /// hash table, and the stack helper registers to h[4..5], the issued hash request is still
    /// hash([ZERO; 8]).
    pub(super) fn start_dyncall_node(
        &mut self,
        dyn_node: &DynNode,
        err_ctx: &impl ErrorContext,
    ) -> Result<Word, ExecutionError> {
        debug_assert!(dyn_node.is_dyncall());

        let mem_addr = self.stack.get(0);
        // The callee hash is stored in memory, and the address is specified on the top of the
        // stack.
        let callee_hash = self
            .chiplets
            .memory
            .read_word(self.system.ctx(), mem_addr, self.system.clk(), err_ctx)
            .map_err(ExecutionError::MemoryError)?;

        // Note: other functions end in "executing a Noop", which
        // 1. ensures trace capacity,
        // 2. copies the stack over to the next row,
        // 3. advances clock.
        //
        // Dyncall's effect on the trace can't be written in terms of any other operation, and
        // therefore can't follow this framework. Hence, we do it "manually". It's probably worth
        // refactoring the decoder though to remove this Noop execution pattern.
        self.ensure_trace_capacity();

        let (addr, hashed_block) = self.chiplets.hasher.hash_control_block(
            EMPTY_WORD,
            EMPTY_WORD,
            dyn_node.domain(),
            dyn_node.digest(),
        );

        debug_assert_eq!(dyn_node.digest(), hashed_block);

        let (stack_depth, next_overflow_addr) = self.stack.shift_left_and_start_context();
        debug_assert!(stack_depth <= u32::MAX as usize, "stack depth too big");

        let ctx_info = ExecutionContextInfo::new(
            self.system.ctx(),
            self.system.fn_hash(),
            self.system.fmp(),
            stack_depth as u32,
            next_overflow_addr,
        );

        self.system.start_call_or_dyncall(callee_hash);
        self.decoder.start_dyncall(addr, callee_hash, ctx_info);

        self.advance_clock()?;

        Ok(callee_hash)
    }

    /// Ends decoding of a DYN node.
    pub(super) fn end_dyn_node<H: SyncHost>(
        &mut self,
        dyn_node: &DynNode,
        program: &MastForest,
        host: &mut H,
    ) -> Result<(), ExecutionError> {
        // this appends a row with END operation to the decoder trace. when the END operation is
        // executed the rest of the VM state does not change
        self.decoder.end_control_block(dyn_node.digest());

        self.execute_op(Operation::Noop, program, host)
    }

    /// Ends decoding of a DYNCALL node.
    pub(super) fn end_dyncall_node<H: SyncHost>(
        &mut self,
        dyn_node: &DynNode,
        program: &MastForest,
        host: &mut H,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        // when a DYNCALL block ends, stack depth must be exactly 16
        let stack_depth = self.stack.depth();
        if stack_depth > MIN_STACK_DEPTH {
            return Err(ExecutionError::invalid_stack_depth_on_return(stack_depth, err_ctx));
        }

        // this appends a row with END operation to the decoder trace. when the END operation is
        // executed the rest of the VM state does not change
        let ctx_info =
            self.decoder.end_control_block(dyn_node.digest()).expect("no execution context");

        // when returning from a function call, restore the context of the system
        // registers and the operand stack to what it was prior to the call.
        self.system.restore_context(
            ctx_info.parent_ctx,
            ctx_info.parent_fmp,
            ctx_info.parent_fn_hash,
        );
        self.stack.restore_context(ctx_info.parent_stack_depth as usize);

        self.execute_op(Operation::Noop, program, host)
    }

    // BASIC BLOCK NODE
    // --------------------------------------------------------------------------------------------

    /// Starts decoding a BASIC BLOCK node.
    pub(super) fn start_basic_block_node<H: SyncHost>(
        &mut self,
        basic_block: &BasicBlockNode,
        program: &MastForest,
        host: &mut H,
    ) -> Result<(), ExecutionError> {
        // use the hasher to compute the hash of the SPAN block; the row address returned by the
        // hasher is used as the ID of the block; hash of a SPAN block is computed by sequentially
        // hashing operation batches. Thus, the result of the hash is expected to be in row
        // addr + (num_batches * 8) - 1.
        let op_batches = basic_block.op_batches();
        let (addr, hashed_block) =
            self.chiplets.hasher.hash_basic_block(op_batches, basic_block.digest());

        debug_assert_eq!(basic_block.digest(), hashed_block);

        // start decoding the first operation batch; this also appends a row with SPAN operation
        // to the decoder trace. we also need the total number of operation groups so that we can
        // set the value of the group_count register at the beginning of the SPAN.
        let num_op_groups = basic_block.num_op_groups();
        self.decoder
            .start_basic_block(&op_batches[0], Felt::new(num_op_groups as u64), addr);
        self.execute_op(Operation::Noop, program, host)
    }

    /// Ends decoding a BASIC BLOCK node.
    pub(super) fn end_basic_block_node<H: SyncHost>(
        &mut self,
        block: &BasicBlockNode,
        program: &MastForest,
        host: &mut H,
    ) -> Result<(), ExecutionError> {
        // this appends a row with END operation to the decoder trace. when END operation is
        // executed the rest of the VM state does not change
        self.decoder.end_basic_block(block.digest());

        self.execute_op(Operation::Noop, program, host)
    }

    /// Continues decoding a SPAN block by absorbing the next batch of operations.
    pub(super) fn respan(&mut self, op_batch: &OpBatch) {
        self.decoder.respan(op_batch);
    }
}

// DECODER
// ================================================================================================

/// Program decoder for the VM.
///
/// This component is responsible for decoding operations executed on the VM, computing the hash
/// of the executed program, as well as building an execution trace for these computations.
///
/// ## Execution trace
/// Decoder execution trace currently consists of 24 columns as illustrated below:
///
///  addr b0 b1 b2 b3 b4 b5 b6 h0 h1 h2 h3 h4 h5 h6 h7 in_span g_count op_idx c0 c1 c2 be0 be1
/// ├────┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴───────┴───────┴──────┴──┴──┴──┴───┴───┤
///
/// In the above, the meaning of the columns is as follows:
/// * addr column contains address of the hasher for the current block (row index from the auxiliary
///   hashing table). It also serves the role of unique block identifiers. This is convenient,
///   because hasher addresses are guaranteed to be unique.
/// * op_bits columns b0 through b6 are used to encode an operation to be executed by the VM. Each
///   of these columns contains a single binary value, which together form a single opcode.
/// * Hasher state columns h0 through h7. These are multi purpose columns used as follows:
///   - When starting decoding of a new code block (e.g., via JOIN, SPLIT, LOOP, SPAN operations)
///     these columns are used for providing inputs for the current block's hash computations.
///   - When finishing decoding of a code block (i.e., via END operation), these columns are used to
///     record the result of the hash computation.
///   - Inside a SPAN block, the first two columns are used to keep track of un-executed operations
///     in the current operation group, as well as the address of the parent code block. The
///     remaining 6 columns are unused by the decoder and, thus, can be used by the VM as helper
///     columns.
/// * in_span column is a binary flag set to ONE when we are inside a SPAN block, and to ZERO
///   otherwise.
/// * Operation group count column is used to keep track of the number of un-executed operation
///   groups in the current SPAN block.
/// * Operation index column is used to keep track of the indexes of the currently executing
///   operations within an operation group. Values in this column could be between 0 and 8 (both
///   inclusive) as there could be at most 9 operations in an operation group.
/// * Operation batch flag columns c0, c1, c2 which indicate how many operation groups are in a
///   given operation batch. These flags are set only for SPAN or RESPAN operations, and are set to
///   ZEROs otherwise.
/// * Operation bit extra columns `be0` and `be1` which are used to reduce the degree of op flags
///   for operations.
///   - `be0` is set when op_bits[6] is ONE, op_bits[5] is ZERO, and op_bits[4] is ONE.
///   - `be1` is set when the two most significant op bits are ONE.
///
/// In addition to the execution trace, the decoder also contains the following:
/// - An instance of [DebugInfo] which is only populated in debug mode. This debug_info instance
///   includes operations executed by the VM and AsmOp decorators. AsmOp decorators are populated
///   only when both the processor and assembler are in debug mode.
pub struct Decoder {
    block_stack: BlockStack,
    span_context: Option<SpanContext>,
    trace: DecoderTrace,
    debug_info: DebugInfo,
}

impl Decoder {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns an empty instance of [Decoder].
    pub fn new(in_debug_mode: bool) -> Self {
        Self {
            block_stack: BlockStack::default(),
            span_context: None,
            trace: DecoderTrace::new(),
            debug_info: DebugInfo::new(in_debug_mode),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns execution trace length for this decoder.
    pub fn trace_len(&self) -> usize {
        self.trace.trace_len()
    }

    /// Hash of the program decoded by this decoder.
    ///
    /// Hash of the program is taken from the last row of first 4 registers of the hasher section
    /// of the decoder trace (i.e., columns 8 - 12).
    pub fn program_hash(&self) -> [Felt; DIGEST_LEN] {
        self.trace.program_hash()
    }

    pub fn debug_info(&self) -> &DebugInfo {
        debug_assert!(self.in_debug_mode());
        &self.debug_info
    }

    /// Returns whether this decoder instance is instantiated in debug mode.
    pub fn in_debug_mode(&self) -> bool {
        self.debug_info.in_debug_mode()
    }

    // CONTROL BLOCKS
    // --------------------------------------------------------------------------------------------

    /// Starts decoding of a JOIN block.
    ///
    /// This pushes a block with ID=addr onto the block stack and appends execution of a JOIN
    /// operation to the trace.
    pub fn start_join(&mut self, child1_hash: Word, child2_hash: Word, addr: Felt) {
        // append a JOIN row to the execution trace
        let parent_addr = self.block_stack.push(addr, BlockType::Join(false), None);
        self.trace
            .append_block_start(parent_addr, Operation::Join, child1_hash, child2_hash);

        self.debug_info.append_operation(Operation::Join);
    }

    /// Starts decoding of a SPLIT block.
    ///
    /// This pushes a block with ID=addr onto the block stack and appends execution of a SPLIT
    /// operation to the trace.
    pub fn start_split(&mut self, child1_hash: Word, child2_hash: Word, addr: Felt) {
        // append a SPLIT row to the execution trace
        let parent_addr = self.block_stack.push(addr, BlockType::Split, None);
        self.trace
            .append_block_start(parent_addr, Operation::Split, child1_hash, child2_hash);

        self.debug_info.append_operation(Operation::Split);
    }

    /// Starts decoding of a LOOP block.
    ///
    /// This pushes a block with ID=addr onto the block stack and appends execution of a LOOP
    /// operation to the trace. A block is marked as a loop block only if is_loop = ONE.
    pub fn start_loop(&mut self, loop_body_hash: Word, addr: Felt, stack_top: Felt) {
        // append a LOOP row to the execution trace
        let enter_loop = stack_top == ONE;
        let parent_addr = self.block_stack.push(addr, BlockType::Loop(enter_loop), None);
        self.trace
            .append_block_start(parent_addr, Operation::Loop, loop_body_hash, EMPTY_WORD);

        self.debug_info.append_operation(Operation::Loop);
    }

    /// Starts decoding another iteration of a loop.
    ///
    /// This appends an execution of a REPEAT operation to the trace.
    pub fn repeat(&mut self) {
        // append a REPEAT row to the execution trace
        let block_info = self.block_stack.peek();
        debug_assert_eq!(ONE, block_info.is_entered_loop());
        self.trace.append_loop_repeat(block_info.addr);

        self.debug_info.append_operation(Operation::Repeat);
    }

    /// Starts decoding of a CALL block.
    ///
    /// This pushes a block with ID=addr onto the block stack and appends execution of a CALL
    /// operation to the trace.
    pub fn start_call(&mut self, fn_hash: Word, addr: Felt, ctx_info: ExecutionContextInfo) {
        // push CALL block info onto the block stack and append a CALL row to the execution trace
        let parent_addr = self.block_stack.push(addr, BlockType::Call, Some(ctx_info));
        self.trace.append_block_start(parent_addr, Operation::Call, fn_hash, EMPTY_WORD);

        self.debug_info.append_operation(Operation::Call);
    }

    /// Starts decoding of a SYSCALL block.
    ///
    /// This pushes a block with ID=addr onto the block stack and appends execution of a SYSCALL
    /// operation to the trace.
    pub fn start_syscall(&mut self, fn_hash: Word, addr: Felt, ctx_info: ExecutionContextInfo) {
        // push SYSCALL block info onto the block stack and append a SYSCALL row to the execution
        // trace
        let parent_addr = self.block_stack.push(addr, BlockType::SysCall, Some(ctx_info));
        self.trace
            .append_block_start(parent_addr, Operation::SysCall, fn_hash, EMPTY_WORD);

        self.debug_info.append_operation(Operation::SysCall);
    }

    /// Starts decoding of a DYN block.
    ///
    /// Note that even though the hasher decoder columns are populated, the issued hash request is
    /// still for [ZERO; 8 | domain=DYN]. This is because a `DYN` node takes its child on the stack,
    /// and therefore the child hash cannot be included in the `DYN` node hash computation (see
    /// [`miden_core::mast::DynNode`]). The decoder hasher columns are then not needed for the `DYN`
    /// node hash computation, and so were used to store the result of the memory read operation for
    /// the child hash.
    ///
    /// This pushes a block with ID=addr onto the block stack and appends execution of a DYN
    /// operation to the trace.
    pub fn start_dyn(&mut self, addr: Felt, callee_hash: Word) {
        // push DYN block info onto the block stack and append a DYN row to the execution trace
        let parent_addr = self.block_stack.push(addr, BlockType::Dyn, None);
        self.trace
            .append_block_start(parent_addr, Operation::Dyn, callee_hash, [ZERO; 4].into());

        self.debug_info.append_operation(Operation::Dyn);
    }

    /// Starts decoding of a DYNCALL block.
    ///
    /// Note that even though the hasher decoder columns are populated, the issued hash request is
    /// still for [ZERO; 8 | domain=DYNCALL].
    ///
    /// This pushes a block with ID=addr onto the block stack and appends execution of a DYNCALL
    /// operation to the trace. The decoder hasher trace columns are populated with the callee hash,
    /// as well as the stack helper registers (specifically their state after shifting the stack
    /// left). We need to store those in the decoder trace so that the block stack table can access
    /// them (since in the next row, we start a new context, and hence the stack registers are reset
    /// to their default values).
    pub fn start_dyncall(&mut self, addr: Felt, callee_hash: Word, ctx_info: ExecutionContextInfo) {
        let parent_stack_depth = ctx_info.parent_stack_depth.into();
        let parent_next_overflow_addr = ctx_info.parent_next_overflow_addr;

        let parent_addr = self.block_stack.push(addr, BlockType::Dyncall, Some(ctx_info));
        self.trace.append_block_start(
            parent_addr,
            Operation::Dyncall,
            callee_hash,
            [parent_stack_depth, parent_next_overflow_addr, ZERO, ZERO].into(),
        );

        self.debug_info.append_operation(Operation::Dyncall);
    }

    /// Ends decoding of a control block (i.e., a non-SPAN block).
    ///
    /// This appends an execution of an END operation to the trace. The top block on the block
    /// stack is also popped.
    ///
    /// If the ended block is a CALL or a SYSCALL block, this method will return values to which
    /// execution context and free memory pointers were set before the CALL block started
    /// executing. For non-CALL blocks these values are set to zeros and should be ignored.
    pub fn end_control_block(&mut self, block_hash: Word) -> Option<ExecutionContextInfo> {
        // remove the block from the top of the block stack and add an END row to the trace
        let block_info = self.block_stack.pop();
        self.trace.append_block_end(
            block_info.addr,
            block_hash,
            block_info.is_loop_body(),
            block_info.is_entered_loop(),
            block_info.is_call(),
            block_info.is_syscall(),
        );

        self.debug_info.append_operation(Operation::End);

        block_info.ctx_info
    }

    // SPAN BLOCK
    // --------------------------------------------------------------------------------------------

    /// Starts decoding of a SPAN block defined by the specified operation batches.
    pub fn start_basic_block(&mut self, first_op_batch: &OpBatch, num_op_groups: Felt, addr: Felt) {
        debug_assert!(self.span_context.is_none(), "already in span");
        let parent_addr = self.block_stack.push(addr, BlockType::Span, None);

        // add a SPAN row to the trace
        self.trace
            .append_span_start(parent_addr, first_op_batch.groups(), num_op_groups);

        // after SPAN operation is executed, we decrement the number of remaining groups by ONE
        // because executing SPAN consumes the first group of the batch.
        self.span_context = Some(SpanContext {
            num_groups_left: num_op_groups - ONE,
            group_ops_left: first_op_batch.groups()[0],
        });

        self.debug_info.append_operation(Operation::Span);
    }

    /// Starts decoding of the next operation batch in the current SPAN.
    pub fn respan(&mut self, op_batch: &OpBatch) {
        // get the current clock cycle here (before the trace table is updated)
        // add RESPAN row to the trace
        self.trace.append_respan(op_batch.groups());

        // we also need to increment block address by 8 because hashing every additional operation
        // batch requires 8 rows of the hasher trace.
        let block_info = self.block_stack.peek_mut();
        block_info.addr += HASH_CYCLE_LEN;

        let ctx = self.span_context.as_mut().expect("not in span");

        // after RESPAN operation is executed, we decrement the number of remaining groups by ONE
        // because executing RESPAN consumes the first group of the batch
        ctx.num_groups_left -= ONE;
        ctx.group_ops_left = op_batch.groups()[0];

        self.debug_info.append_operation(Operation::Respan);
    }

    /// Starts decoding a new operation group.
    pub fn start_op_group(&mut self, op_group: Felt) {
        let ctx = self.span_context.as_mut().expect("not in span");

        // reset the current group value and decrement the number of left groups by ONE
        debug_assert_eq!(ZERO, ctx.group_ops_left, "not all ops executed in current group");
        ctx.group_ops_left = op_group;
        ctx.num_groups_left -= ONE;
    }

    /// Decodes a user operation (i.e., not a control flow operation).
    pub fn execute_user_op(&mut self, op: Operation, op_idx: usize) {
        let block = self.block_stack.peek();
        let ctx = self.span_context.as_mut().expect("not in span");

        // update operations left to be executed in the group
        ctx.group_ops_left = remove_opcode_from_group(ctx.group_ops_left, op);

        // append the row for the operation to the trace
        self.trace.append_user_op(
            op,
            block.addr,
            block.parent_addr,
            ctx.num_groups_left,
            ctx.group_ops_left,
            Felt::from(op_idx as u32),
        );

        // if the operation carries an immediate value, decrement the number of  operation
        // groups left to decode. this number will be inserted into the trace in the next row.
        // we also mark the current clock cycle as a cycle at which the immediate value was
        // removed from the op_group table.
        if op.imm_value().is_some() {
            ctx.num_groups_left -= ONE;
        }

        self.debug_info.append_operation(op);
    }

    /// Sets the helper registers in the trace to the user-provided helper values. This is expected
    /// to be called during the execution of a user operation.
    ///
    /// TODO: it might be better to get the operation information from the decoder trace, rather
    /// than passing it in as a parameter.
    pub fn set_user_op_helpers(&mut self, op: Operation, values: &[Felt]) {
        debug_assert!(
            !op.populates_decoder_hasher_registers(),
            "user op helper registers not available for op"
        );
        self.trace.set_user_op_helpers(values);
    }

    /// Ends decoding of a SPAN block.
    pub fn end_basic_block(&mut self, block_hash: Word) {
        // remove the block from the stack of executing blocks and add an END row to the
        // execution trace
        let block_info = self.block_stack.pop();
        self.trace.append_span_end(block_hash, block_info.is_loop_body());
        self.span_context = None;

        self.debug_info.append_operation(Operation::End);
    }

    // TRACE GENERATIONS
    // --------------------------------------------------------------------------------------------

    /// Returns an array of columns containing an execution trace of this decoder.
    ///
    /// Trace columns are extended to match the specified trace length.
    pub fn into_trace(self, trace_len: usize, num_rand_rows: usize) -> super::DecoderTrace {
        let trace = self
            .trace
            .into_vec(trace_len, num_rand_rows)
            .try_into()
            .expect("failed to convert vector to array");
        let aux_builder = AuxTraceBuilder::default();

        super::DecoderTrace { trace, aux_builder }
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Appends an asmop decorator at the specified clock cycle to the asmop list in debug mode.
    pub fn append_asmop(&mut self, clk: RowIndex, asmop: AssemblyOp) {
        self.debug_info.append_asmop(clk, asmop);
    }

    // TEST METHODS
    // --------------------------------------------------------------------------------------------

    /// Adds a row of zeros to the decoder trace for testing purposes.
    #[cfg(test)]
    pub fn add_dummy_trace_row(&mut self) {
        self.trace.add_dummy_row();
    }

    /// Returns a list of all the helper registers set during an operation.
    #[cfg(test)]
    pub fn get_user_op_helpers(&self) -> [Felt; NUM_USER_OP_HELPERS] {
        self.trace.get_user_op_helpers()
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new(false)
    }
}

// SPAN CONTEXT
// ================================================================================================

/// Keeps track of the info needed to decode a currently executing SPAN block. The info includes:
/// - Operations which still need to be executed in the current group. The operations are encoded as
///   opcodes (7 bits) appended one after another into a single field element, with the next
///   operation to be executed located at the least significant position.
/// - Number of operation groups left to be executed in the entire SPAN block.
#[derive(Default)]
pub(crate) struct SpanContext {
    pub group_ops_left: Felt,
    pub num_groups_left: Felt,
}

// HELPER FUNCTIONS
// ================================================================================================

/// Removes the specified operation from the op group and returns the resulting op group.
fn remove_opcode_from_group(op_group: Felt, op: Operation) -> Felt {
    let opcode = op.op_code() as u64;
    let result = Felt::new((op_group.as_int() - opcode) >> NUM_OP_BITS);
    debug_assert!(op_group.as_int() >= result.as_int(), "op group underflow");
    result
}

/// Returns the number of op groups in the next batch based on how many total groups are left to
/// process in a span.
///
/// This is computed as the min of number of groups left and max batch size. Thus, if the number
/// of groups left is > 8, the number of groups will be 8; otherwise, it will be equal to the
/// number of groups left to process.
fn get_num_groups_in_next_batch(num_groups_left: Felt) -> usize {
    core::cmp::min(num_groups_left.as_int() as usize, OP_BATCH_SIZE)
}

// TEST HELPERS
// ================================================================================================

/// Build an operation group from the specified list of operations.
#[cfg(test)]
pub fn build_op_group(ops: &[Operation]) -> Felt {
    let mut group = 0u64;
    let mut i = 0;
    for op in ops.iter() {
        group |= (op.op_code() as u64) << (Operation::OP_BITS * i);
        i += 1;
    }
    assert!(i <= OP_GROUP_SIZE, "too many ops");
    Felt::new(group)
}

// DEBUG INFO
// ================================================================================================

pub struct DebugInfo {
    in_debug_mode: bool,
    operations: Vec<Operation>,
    assembly_ops: Vec<(usize, AssemblyOp)>,
}

impl DebugInfo {
    pub fn new(in_debug_mode: bool) -> Self {
        Self {
            in_debug_mode,
            operations: Vec::<Operation>::new(),
            assembly_ops: Vec::<(usize, AssemblyOp)>::new(),
        }
    }

    /// Returns whether this decoder instance is instantiated in debug mode.
    #[inline(always)]
    pub fn in_debug_mode(&self) -> bool {
        self.in_debug_mode
    }

    /// Returns an operation to be executed at the specified clock cycle. Only applicable in debug
    /// mode.
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }

    /// Returns list of assembly operations in debug mode.
    pub fn assembly_ops(&self) -> &[(usize, AssemblyOp)] {
        &self.assembly_ops
    }

    /// Adds an operation to the operations vector in debug mode.
    #[inline(always)]
    pub fn append_operation(&mut self, op: Operation) {
        if self.in_debug_mode {
            self.operations.push(op);
        }
    }

    /// Appends an asmop decorator at the specified clock cycle to the asmop list in debug mode.
    pub fn append_asmop(&mut self, clk: RowIndex, asmop: AssemblyOp) {
        self.assembly_ops.push((clk.into(), asmop));
    }
}
