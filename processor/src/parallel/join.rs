use core::ops::ControlFlow;

use miden_core::{Felt, Word, mast::JoinNode};

use super::{CoreTraceFragmentGenerator, TraceRowType, trace_builder::OperationTraceConfig};
use crate::decoder::block_stack::BlockInfo;

impl CoreTraceFragmentGenerator {
    /// Adds a trace row for a JOIN operation (start or end) to the main trace fragment.
    ///
    /// This method populates the system, decoder, and stack columns for a single trace row
    /// corresponding to either the start or end of a JOIN block execution. It uses the
    /// shared control flow trace building infrastructure.
    pub fn add_join_trace_row(
        &mut self,
        join_node: &JoinNode,
        program: &miden_core::mast::MastForest,
        trace_type: TraceRowType,
        addr: Felt,
        block_info: Option<BlockInfo>,
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

        let config = OperationTraceConfig {
            start_opcode: miden_core::Operation::Join.op_code(),
            start_hasher_state: (child1_hash, child2_hash),
            end_node_digest: join_node.digest(),
            addr,
            block_info,
        };

        self.add_control_flow_trace_row(config, trace_type)
    }

    /// Adds a trace row for starting a JOIN operation to the main trace fragment.
    ///
    /// This is a convenience wrapper around `add_join_trace_row` for JOIN start operations.
    pub fn add_join_start_trace_row(
        &mut self,
        join_node: &JoinNode,
        program: &miden_core::mast::MastForest,
        parent_addr: Felt,
    ) -> ControlFlow<()> {
        self.add_join_trace_row(join_node, program, TraceRowType::Start, parent_addr, None)
    }

    /// Adds a trace row for ending a JOIN operation to the main trace fragment.
    ///
    /// This is a convenience wrapper around `add_join_trace_row` for JOIN end operations.
    pub fn add_join_end_trace_row(
        &mut self,
        join_node: &JoinNode,
        program: &miden_core::mast::MastForest,
    ) -> ControlFlow<()> {
        // Pop the block from stack and use its info for END operations
        let block_info = self.state.block_stack.pop();
        let block_addr = block_info.addr;
        self.add_join_trace_row(join_node, program, TraceRowType::End, block_addr, Some(block_info))
    }
}
