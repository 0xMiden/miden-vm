use core::ops::ControlFlow;

use miden_core::{Felt, Word, mast::DynNode};

use super::{CoreTraceFragmentGenerator, TraceRowType, trace_builder::OperationTraceConfig};
use crate::decoder::block_stack::BlockInfo;

impl CoreTraceFragmentGenerator {
    /// Adds a trace row for a DYN/DYNCALL operation (start or end) to the main trace fragment.
    ///
    /// This method populates the system, decoder, and stack columns for a single trace row
    /// corresponding to either the start or end of a DYN/DYNCALL block execution. It uses the
    /// shared control flow trace building infrastructure.
    pub fn add_dyn_trace_row(
        &mut self,
        dyn_node: &DynNode,
        trace_type: TraceRowType,
        addr: Felt,
        block_info: Option<BlockInfo>,
    ) -> ControlFlow<()> {
        // For DYN/DYNCALL operations, the hasher state is set to zeros since the dynamic target
        // is resolved at runtime and cannot be known at compile time during parallel execution
        let zero_hash = Word::default();

        let config = OperationTraceConfig {
            start_opcode: if dyn_node.is_dyncall() {
                miden_core::Operation::Dyncall.op_code()
            } else {
                miden_core::Operation::Dyn.op_code()
            },
            start_hasher_state: (zero_hash, zero_hash),
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
    ) -> ControlFlow<()> {
        self.add_dyn_trace_row(dyn_node, TraceRowType::Start, parent_addr, None)
    }

    /// Adds a trace row for the end of a DYN/DYNCALL operation.
    ///
    /// This is a convenience method that calls `add_dyn_trace_row` with `TraceRowType::End`.
    pub fn add_dyn_end_trace_row(&mut self, dyn_node: &DynNode) -> ControlFlow<()> {
        // Pop the block from stack and use its info for END operations
        let block_info = self.state.block_stack.pop();
        let block_addr = block_info.addr;
        self.add_dyn_trace_row(dyn_node, TraceRowType::End, block_addr, Some(block_info))
    }
}
