use core::ops::ControlFlow;

use miden_core::{Felt, Word, mast::LoopNode};

use super::{CoreTraceFragmentGenerator, TraceRowType, trace_builder::OperationTraceConfig};
use crate::decoder::block_stack::BlockInfo;

impl CoreTraceFragmentGenerator {
    /// Adds a trace row for a LOOP operation (start or end) to the main trace fragment.
    ///
    /// This method populates the system, decoder, and stack columns for a single trace row
    /// corresponding to either the start or end of a LOOP block execution. It uses the
    /// shared control flow trace building infrastructure.
    pub fn add_loop_trace_row(
        &mut self,
        loop_node: &LoopNode,
        program: &miden_core::mast::MastForest,
        trace_type: TraceRowType,
        addr: Felt,
        block_info: Option<BlockInfo>,
    ) -> ControlFlow<()> {
        // For LOOP operations, the hasher state in start operations contains the loop body hash
        // in the first half, and zeros in the second half (since LOOP only has one child)
        let body_hash: Word = program
            .get_node_by_id(loop_node.body())
            .expect("loop body should exist")
            .digest();
        let zero_hash = Word::default();

        let config = OperationTraceConfig {
            start_opcode: miden_core::Operation::Loop.op_code(),
            start_hasher_state: (body_hash, zero_hash),
            end_node_digest: loop_node.digest(),
            addr,
            block_info,
        };

        self.add_control_flow_trace_row(config, trace_type)
    }

    /// Adds a trace row for the start of a LOOP operation.
    ///
    /// This is a convenience method that calls `add_loop_trace_row` with `TraceRowType::Start`.
    pub fn add_loop_start_trace_row(
        &mut self,
        loop_node: &LoopNode,
        program: &miden_core::mast::MastForest,
        parent_addr: Felt,
    ) -> ControlFlow<()> {
        self.add_loop_trace_row(loop_node, program, TraceRowType::Start, parent_addr, None)
    }

    /// Adds a trace row for the end of a LOOP operation.
    ///
    /// This is a convenience method that calls `add_loop_trace_row` with `TraceRowType::End`.
    pub fn add_loop_end_trace_row(
        &mut self,
        loop_node: &LoopNode,
        program: &miden_core::mast::MastForest,
    ) -> ControlFlow<()> {
        // Pop the block from stack and use its info for END operations
        let block_info = self.state.block_stack.pop();
        let block_addr = block_info.addr;
        self.add_loop_trace_row(loop_node, program, TraceRowType::End, block_addr, Some(block_info))
    }
}
