use core::ops::ControlFlow;

use miden_core::{
    Felt, Word,
    mast::{JoinNode, MastNodeExt},
};

use super::{CoreTraceFragmentGenerator, trace_builder::OperationTraceConfig};

impl CoreTraceFragmentGenerator {
    /// Adds a trace row for starting a JOIN operation to the main trace fragment.
    pub fn add_join_start_trace_row(
        &mut self,
        join_node: &JoinNode,
        program: &miden_core::mast::MastForest,
        parent_addr: Felt,
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
            opcode: miden_core::Operation::Join.op_code(),
            hasher_state: (child1_hash, child2_hash),
            addr: parent_addr,
        };

        self.add_control_flow_trace_row(config)
    }
}
