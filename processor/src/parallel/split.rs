use core::ops::ControlFlow;

use miden_core::{Felt, Word, mast::SplitNode};

use super::{CoreTraceFragmentGenerator, TraceRowType, trace_builder::OperationTraceConfig};
use crate::decoder::block_stack::BlockInfo;

impl CoreTraceFragmentGenerator {
    /// Adds a trace row for a SPLIT operation (start or end) to the main trace fragment.
    ///
    /// This method populates the system, decoder, and stack columns for a single trace row
    /// corresponding to either the start or end of a SPLIT block execution. It uses the
    /// shared control flow trace building infrastructure.
    pub fn add_split_trace_row(
        &mut self,
        split_node: &SplitNode,
        program: &miden_core::mast::MastForest,
        trace_type: TraceRowType,
        addr: Felt,
        block_info: Option<BlockInfo>,
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

        let config = OperationTraceConfig {
            start_opcode: miden_core::Operation::Split.op_code(),
            start_hasher_state: (on_true_hash, on_false_hash),
            end_node_digest: split_node.digest(),
            addr,
            block_info,
        };

        self.add_control_flow_trace_row(config, trace_type)
    }

    /// Adds a trace row for the start of a SPLIT operation.
    ///
    /// This is a convenience method that calls `add_split_trace_row` with `TraceRowType::Start`.
    pub fn add_split_start_trace_row(
        &mut self,
        split_node: &SplitNode,
        program: &miden_core::mast::MastForest,
        parent_addr: Felt,
    ) -> ControlFlow<()> {
        self.add_split_trace_row(split_node, program, TraceRowType::Start, parent_addr, None)
    }

    /// Adds a trace row for the end of a SPLIT operation.
    ///
    /// This is a convenience method that calls `add_split_trace_row` with `TraceRowType::End`.
    pub fn add_split_end_trace_row(
        &mut self,
        split_node: &SplitNode,
        program: &miden_core::mast::MastForest,
    ) -> ControlFlow<()> {
        // Pop the block from stack and use its info for END operations
        let block_info = self.state.block_stack.pop();
        let block_addr = block_info.addr;
        self.add_split_trace_row(
            split_node,
            program,
            TraceRowType::End,
            block_addr,
            Some(block_info),
        )
    }
}
