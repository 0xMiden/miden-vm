use core::ops::ControlFlow;

use miden_core::{Felt, Word, ZERO, mast::DynNode};

use super::{CoreTraceFragmentGenerator, TraceRowType, trace_builder::OperationTraceConfig};
use crate::decoder::block_stack::{BlockInfo, ExecutionContextInfo};

impl CoreTraceFragmentGenerator {
    /// Adds a trace row for a DYN/DYNCALL operation (start or end) to the main trace fragment.
    ///
    /// This method populates the system, decoder, and stack columns for a single trace row
    /// corresponding to either the start or end of a DYN/DYNCALL block execution.
    pub fn add_dyn_trace_row(
        &mut self,
        dyn_node: &DynNode,
        trace_type: TraceRowType,
        addr: Felt,
        callee_hash: Word,
        block_info: Option<BlockInfo>,
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
            start_opcode: if dyn_node.is_dyncall() {
                miden_core::Operation::Dyncall.op_code()
            } else {
                miden_core::Operation::Dyn.op_code()
            },
            start_hasher_state: (callee_hash, second_hasher_state),
            end_node_digest: dyn_node.digest(),
            addr,
            block_info,
        };

        self.add_control_flow_trace_row(config, trace_type)
    }

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
        self.add_dyn_trace_row(
            dyn_node,
            TraceRowType::Start,
            parent_addr,
            callee_hash,
            None,
            ctx_info,
        )
    }

    /// Adds a trace row for the end of a DYN/DYNCALL operation.
    ///
    /// This is a convenience method that calls `add_dyn_trace_row` with `TraceRowType::End`.
    pub fn add_dyn_end_trace_row(
        &mut self,
        dyn_node: &DynNode,
        block_info: BlockInfo,
    ) -> ControlFlow<()> {
        let block_addr = block_info.addr;
        self.add_dyn_trace_row(
            dyn_node,
            TraceRowType::End,
            block_addr,
            Word::default(),
            Some(block_info),
            None,
        )
    }
}
