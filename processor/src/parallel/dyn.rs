use core::ops::ControlFlow;

use miden_core::{Felt, Operation, Word, ZERO};

use super::{CoreTraceFragmentGenerator, trace_builder::OperationTraceConfig};
use crate::decoder::block_stack::ExecutionContextInfo;

impl CoreTraceFragmentGenerator {
    /// Adds a trace row for the start of a DYN operation.
    pub fn add_dyn_start_trace_row(&mut self, callee_hash: Word) -> ControlFlow<()> {
        let config = OperationTraceConfig {
            opcode: Operation::Dyn.op_code(),
            hasher_state: (callee_hash, Word::default()),
            addr: self.context.state.decoder.parent_addr,
        };

        self.add_control_flow_trace_row(config)
    }

    /// Adds a trace row for the start of a DYNCALL operation.
    ///
    /// The decoder hasher trace columns are populated with the callee hash, as well as the stack
    /// helper registers (specifically their state after shifting the stack left). We need to store
    /// those in the decoder trace so that the block stack table can access them (since in the next
    /// row, we start a new context, and hence the stack registers are reset to their default
    /// values).
    pub fn add_dyncall_start_trace_row(
        &mut self,
        callee_hash: Word,
        ctx_info: ExecutionContextInfo,
    ) -> ControlFlow<()> {
        let second_hasher_state: Word = [
            Felt::from(ctx_info.parent_stack_depth),
            ctx_info.parent_next_overflow_addr,
            ZERO,
            ZERO,
        ]
        .into();

        let config = OperationTraceConfig {
            opcode: Operation::Dyncall.op_code(),
            hasher_state: (callee_hash, second_hasher_state),
            addr: self.context.state.decoder.parent_addr,
        };

        self.add_control_flow_trace_row(config)
    }
}
