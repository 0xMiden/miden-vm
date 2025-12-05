use core::ops::ControlFlow;

use miden_air::Felt;
use miden_core::{
    ONE,
    mast::{BasicBlockNode, CallNode, DynNode, MastForest, MastNodeExt, MastNodeId},
};

use crate::{
    fast::NoopTracer,
    parallel::core_trace_fragment::{BasicBlockContext, CoreTraceFragmentFiller},
    processor::StackInterface,
};

impl<'a> CoreTraceFragmentFiller<'a> {
    // BASIC BLOCK NODE HANDLING
    // ------------------------------------------------------------------------------------------

    #[inline(always)]
    /// Finishes executing a basic block node starting from the specified operation in the specific
    /// batch.
    pub(super) fn finish_basic_block_node_from_op(
        &mut self,
        basic_block_node: &BasicBlockNode,
        current_forest: &MastForest,
        start_batch_index: usize,
        op_idx_in_batch: usize,
        basic_block_context: &mut BasicBlockContext,
    ) -> ControlFlow<()> {
        let op_batches = basic_block_node.op_batches();
        assert!(
            start_batch_index < op_batches.len(),
            "Batch index out of bounds: {start_batch_index} >= {}",
            op_batches.len()
        );

        // Execute remaining operations in the current batch
        {
            let current_batch = &op_batches[start_batch_index];
            self.execute_op_batch(
                current_batch,
                Some(op_idx_in_batch),
                current_forest,
                basic_block_context,
            )?;
        }

        // Execute remaining batches
        for op_batch in op_batches.iter().skip(start_batch_index + 1) {
            self.add_respan_trace_row(op_batch, basic_block_context)?;

            self.execute_op_batch(op_batch, None, current_forest, basic_block_context)?;
        }

        // Add END trace row to complete the basic block
        self.add_basic_block_end_trace_row(basic_block_node)
    }

    // LOOP NODE HANDLING
    // ------------------------------------------------------------------------------------------

    /// Finishes executing a loop node by processing its body repeatedly while the condition is
    /// true.
    #[inline(always)]
    pub(super) fn finish_loop_node(
        &mut self,
        node_id: MastNodeId,
        mast_forest: &MastForest,
        condition: Option<Felt>,
    ) -> ControlFlow<()> {
        let loop_node =
            mast_forest.get_node_by_id(node_id).expect("node should exist").unwrap_loop();

        // If no condition is provided, read it from the stack
        let mut condition = if let Some(cond) = condition {
            cond
        } else {
            let cond = self.get(0);
            self.decrement_size(&mut NoopTracer);
            cond
        };

        while condition == ONE {
            self.add_loop_repeat_trace_row(
                loop_node,
                mast_forest,
                self.context.state.decoder.current_addr,
            )?;

            self.execute_mast_node(loop_node.body(), mast_forest)?;

            condition = self.get(0);
            self.decrement_size(&mut NoopTracer);
        }

        // Add "end LOOP" row
        //
        // Note that we don't confirm that the condition is properly ZERO here, as
        // the FastProcessor already ran that check.
        self.add_end_trace_row(loop_node.digest())
    }

    // CALL NODE HANDLING
    // ------------------------------------------------------------------------------------------

    /// Performs necessary operations to finish executing a call node, and inserting its
    /// corresponding END row.
    #[inline(always)]
    pub(super) fn finish_call_node(&mut self, call_node: &CallNode) -> ControlFlow<()> {
        // Restore context
        let ctx_info = self.context.replay.block_stack.replay_execution_context();
        self.restore_context_from_replay(&ctx_info);

        // write END row to trace
        self.add_end_trace_row(call_node.digest())
    }

    /// Performs necessary operations to finish executing a dyn node, and inserting its
    /// corresponding END row.
    #[inline(always)]
    pub(super) fn finish_dyn_node(&mut self, dyn_node: &DynNode) -> ControlFlow<()> {
        if dyn_node.is_dyncall() {
            let ctx_info = self.context.replay.block_stack.replay_execution_context();
            self.restore_context_from_replay(&ctx_info);
        }

        self.add_end_trace_row(dyn_node.digest())
    }
}
