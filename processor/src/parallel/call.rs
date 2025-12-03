use core::ops::ControlFlow;

use miden_core::{
    Word,
    mast::{CallNode, MastNodeExt},
};

use super::{CoreTraceFragmentFiller, trace_builder::OperationTraceConfig};

impl<'a> CoreTraceFragmentFiller<'a> {
    /// Adds a trace row for the start of a CALL/SYSCALL operation.
    pub fn add_call_start_trace_row(
        &mut self,
        call_node: &CallNode,
        program: &miden_core::mast::MastForest,
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
            opcode: if call_node.is_syscall() {
                miden_core::Operation::SysCall.op_code()
            } else {
                miden_core::Operation::Call.op_code()
            },
            hasher_state: (callee_hash, zero_hash),
            addr: self.context.state.decoder.parent_addr,
        };

        self.add_control_flow_trace_row(config)
    }
}
