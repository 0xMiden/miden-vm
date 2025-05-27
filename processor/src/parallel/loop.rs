use core::ops::ControlFlow;

use miden_core::{
    Felt, ONE, Operation, Word, ZERO,
    mast::{LoopNode, MastForest},
};

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
        program: &MastForest,
        trace_type: TraceRowType,
        is_repeat: bool,
        addr: Felt,
        block_info: Option<BlockInfo>,
    ) -> ControlFlow<()> {
        // For LOOP or REPEAT operations, the hasher state in start operations contains the loop
        // body hash in the first half.
        let body_hash: Word = program
            .get_node_by_id(loop_node.body())
            .expect("loop body should exist")
            .digest();

        let config = if is_repeat {
            OperationTraceConfig {
                start_opcode: Operation::Repeat.op_code(),
                // We set hasher[4] (is_loop_body) to 1
                start_hasher_state: (body_hash, [ONE, ZERO, ZERO, ZERO].into()),
                end_node_digest: loop_node.digest(),
                addr,
                block_info,
            }
        } else {
            OperationTraceConfig {
                start_opcode: Operation::Loop.op_code(),
                start_hasher_state: (body_hash, Word::default()),
                end_node_digest: loop_node.digest(),
                addr,
                block_info,
            }
        };

        self.add_control_flow_trace_row(config, trace_type)
    }

    /// Adds a trace row for the start of a LOOP operation.
    ///
    /// This is a convenience method that calls `add_loop_trace_row` with `TraceRowType::Start`.
    pub fn add_loop_start_trace_row(
        &mut self,
        loop_node: &LoopNode,
        program: &MastForest,
        parent_addr: Felt,
    ) -> ControlFlow<()> {
        self.add_loop_trace_row(loop_node, program, TraceRowType::Start, false, parent_addr, None)
    }

    pub fn add_loop_repeat_trace_row(
        &mut self,
        loop_node: &LoopNode,
        program: &MastForest,
        parent_addr: Felt,
    ) -> ControlFlow<()> {
        self.add_loop_trace_row(loop_node, program, TraceRowType::Start, true, parent_addr, None)
    }

    /// Adds a trace row for the end of a LOOP operation.
    ///
    /// This is a convenience method that calls `add_loop_trace_row` with `TraceRowType::End`.
    pub fn add_loop_end_trace_row(
        &mut self,
        loop_node: &LoopNode,
        program: &MastForest,
    ) -> ControlFlow<()> {
        // Pop the block from stack and use its info for END operations
        let block_info = self.state.block_stack.pop();
        let block_addr = block_info.addr;
        self.add_loop_trace_row(
            loop_node,
            program,
            TraceRowType::End,
            false,
            block_addr,
            Some(block_info),
        )
    }
}
