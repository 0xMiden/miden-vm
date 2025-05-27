use core::ops::ControlFlow;

use miden_core::{Felt, Word, ZERO, mast::DynNode};

use super::{CoreTraceFragmentGenerator, trace_builder::OperationTraceConfig};
use crate::decoder::block_stack::ExecutionContextInfo;

impl CoreTraceFragmentGenerator {
    // TODO(plafer): split into 2 methods (dyn and dyncall)
    /// Adds a trace row for the start of a DYN/DYNCALL operation.
    ///
    /// This is a convenience method that calls `add_dyn_trace_row` with `TraceRowType::Start`.
    pub fn add_dyn_start_trace_row(
        &mut self,
        dyn_node: &DynNode,
        parent_addr: Felt,
        callee_hash: Word,
        ctx_info: Option<ExecutionContextInfo>,
    ) -> ControlFlow<()> {
        let second_hasher_state: Word = match ctx_info {
            Some(ctx_info) => [
                Felt::from(ctx_info.parent_stack_depth),
                ctx_info.parent_next_overflow_addr,
                ZERO,
                ZERO,
            ]
            .into(),
            None => Word::default(),
        };

        let config = OperationTraceConfig {
            opcode: if dyn_node.is_dyncall() {
                miden_core::Operation::Dyncall.op_code()
            } else {
                miden_core::Operation::Dyn.op_code()
            },
            hasher_state: (callee_hash, second_hasher_state),
            addr: parent_addr,
        };

        self.add_control_flow_trace_row(config)
    }
}
