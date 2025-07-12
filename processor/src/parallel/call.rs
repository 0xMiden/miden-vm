use core::ops::ControlFlow;

use miden_core::{Felt, Word, mast::CallNode};

use super::{CoreTraceFragmentGenerator, TraceRowType, trace_builder::OperationTraceConfig};
use crate::decoder::block_stack::BlockInfo;

impl CoreTraceFragmentGenerator {
    /// Adds a trace row for a CALL/SYSCALL operation (start or end) to the main trace fragment.
    ///
    /// This method populates the system, decoder, and stack columns for a single trace row
    /// corresponding to either the start or end of a CALL/SYSCALL block execution. It uses the
    /// shared control flow trace building infrastructure.
    pub fn add_call_trace_row(
        &mut self,
        call_node: &CallNode,
        program: &miden_core::mast::MastForest,
        trace_type: TraceRowType,
        addr: Felt,
        block_info: Option<BlockInfo>,
    ) -> ControlFlow<()> {
        // For CALL/SYSCALL operations, the hasher state in start operations contains the callee
        // hash in the first half, and zeros in the second half (since CALL only has one
        // child)
        let callee_hash: Word = program
            .get_node_by_id(call_node.callee())
            .expect("callee should exist")
            .digest();
        let zero_hash = Word::default();

        let config = OperationTraceConfig {
            start_opcode: if call_node.is_syscall() {
                miden_core::Operation::SysCall.op_code()
            } else {
                miden_core::Operation::Call.op_code()
            },
            start_hasher_state: (callee_hash, zero_hash),
            end_node_digest: call_node.digest(),
            addr,
            block_info,
        };

        self.add_control_flow_trace_row(config, trace_type)
    }

    /// Adds a trace row for the start of a CALL/SYSCALL operation.
    ///
    /// This is a convenience method that calls `add_call_trace_row` with `TraceRowType::Start`.
    pub fn add_call_start_trace_row(
        &mut self,
        call_node: &CallNode,
        program: &miden_core::mast::MastForest,
        parent_addr: Felt,
    ) -> ControlFlow<()> {
        self.add_call_trace_row(call_node, program, TraceRowType::Start, parent_addr, None)
    }

    /// Adds a trace row for the end of a CALL/SYSCALL operation.
    ///
    /// This is a convenience method that calls `add_call_trace_row` with `TraceRowType::End`.
    pub fn add_call_end_trace_row(
        &mut self,
        call_node: &CallNode,
        program: &miden_core::mast::MastForest,
    ) -> ControlFlow<()> {
        // Pop the block from stack and use its info for END operations
        let block_info = self.state.block_stack.pop();
        let block_addr = block_info.addr;
        self.add_call_trace_row(call_node, program, TraceRowType::End, block_addr, Some(block_info))
    }
}
