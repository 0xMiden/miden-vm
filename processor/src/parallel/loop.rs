use core::ops::ControlFlow;

use miden_core::{
    Felt, ONE, Operation, Word, ZERO,
    mast::{LoopNode, MastForest, MastNodeExt},
};

use super::{CoreTraceFragmentGenerator, trace_builder::OperationTraceConfig};

impl CoreTraceFragmentGenerator {
    /// Adds a trace row for the start of a LOOP operation.
    pub fn add_loop_start_trace_row(
        &mut self,
        loop_node: &LoopNode,
        program: &MastForest,
        parent_addr: Felt,
    ) -> ControlFlow<()> {
        // For LOOP operations, the hasher state in start operations contains the loop body hash in
        // the first half.
        let body_hash: Word = program
            .get_node_by_id(loop_node.body())
            .expect("loop body should exist")
            .digest();
        let zero_hash = Word::default();

        let config = OperationTraceConfig {
            opcode: Operation::Loop.op_code(),
            hasher_state: (body_hash, zero_hash),
            addr: parent_addr,
        };

        self.add_control_flow_trace_row(config)
    }

    /// Adds a trace row for the start of a REPEAT operation.
    pub fn add_loop_repeat_trace_row(
        &mut self,
        loop_node: &LoopNode,
        program: &MastForest,
        current_addr: Felt,
    ) -> ControlFlow<()> {
        // For REPEAT operations, the hasher state in start operations contains the loop body hash
        // in the first half.
        let body_hash: Word = program
            .get_node_by_id(loop_node.body())
            .expect("loop body should exist")
            .digest();

        let config = OperationTraceConfig {
            opcode: Operation::Repeat.op_code(),
            // We set hasher[4] (is_loop_body) to 1
            hasher_state: (body_hash, [ONE, ZERO, ZERO, ZERO].into()),
            addr: current_addr,
        };

        self.add_control_flow_trace_row(config)
    }
}
