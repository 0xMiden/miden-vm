use core::ops::ControlFlow;

use miden_core::{
    Operation::Split,
    Word,
    mast::{MastNodeExt, SplitNode},
};

use super::{CoreTraceFragmentGenerator, trace_builder::OperationTraceConfig};

impl CoreTraceFragmentGenerator {
    /// Adds a trace row for the start of a SPLIT operation.
    ///
    /// This is a convenience method that calls `add_split_trace_row` with `TraceRowType::Start`.
    pub fn add_split_start_trace_row(
        &mut self,
        split_node: &SplitNode,
        program: &miden_core::mast::MastForest,
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
            opcode: Split.op_code(),
            hasher_state: (on_true_hash, on_false_hash),
            addr: self.context.state.decoder.parent_addr,
        };

        self.add_control_flow_trace_row(config)
    }
}
