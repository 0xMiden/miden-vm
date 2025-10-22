use alloc::sync::Arc;

use miden_core::{
    EventId, Operation,
    mast::{BasicBlockNode, DecoratorOpLinkIterator, MastForest, MastNodeId, OpBatch},
    sys_events::SystemEvent,
};

use crate::{
    AsyncHost, ErrorContext, ExecutionError,
    continuation_stack::ContinuationStack,
    err_ctx,
    fast::{FastProcessor, Tracer, trace_state::NodeExecutionState},
    operations::sys_ops::sys_event_handlers::handle_system_event,
    processor::Processor,
};

impl FastProcessor {
    /// Execute the given basic block node.
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    pub(super) async fn execute_basic_block_node(
        &mut self,
        basic_block_node: &BasicBlockNode,
        node_id: MastNodeId,
        program: &MastForest,
        host: &mut impl AsyncHost,
        continuation_stack: &mut ContinuationStack,
        current_forest: &Arc<MastForest>,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        tracer.start_clock_cycle(
            self,
            NodeExecutionState::Start(node_id),
            continuation_stack,
            current_forest,
        );

        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(node_id, program, host)?;

        // Corresponds to the row inserted for the BASIC BLOCK operation added to the trace.
        self.increment_clk(tracer);

        let mut batch_offset_in_block = 0;
        let mut op_batches = basic_block_node.op_batches().iter();
        let mut decorator_ids = basic_block_node.indexed_decorator_iter();

        // execute first op batch
        if let Some(first_op_batch) = op_batches.next() {
            self.execute_op_batch(
                basic_block_node,
                node_id,
                first_op_batch,
                0,
                &mut decorator_ids,
                batch_offset_in_block,
                program,
                host,
                continuation_stack,
                current_forest,
                tracer,
            )
            .await?;
            batch_offset_in_block += first_op_batch.ops().len();
        }

        // execute the rest of the op batches
        for (batch_index_minus_1, op_batch) in op_batches.enumerate() {
            let batch_index = batch_index_minus_1 + 1;
            // RESPAN
            {
                tracer.start_clock_cycle(
                    self,
                    NodeExecutionState::Respan { node_id, batch_index },
                    continuation_stack,
                    current_forest,
                );

                // Corresponds to the RESPAN operation added to the trace.
                self.increment_clk(tracer);
            }

            self.execute_op_batch(
                basic_block_node,
                node_id,
                op_batch,
                batch_index,
                &mut decorator_ids,
                batch_offset_in_block,
                program,
                host,
                continuation_stack,
                current_forest,
                tracer,
            )
            .await?;
            batch_offset_in_block += op_batch.ops().len();
        }

        tracer.start_clock_cycle(
            self,
            NodeExecutionState::End(node_id),
            continuation_stack,
            current_forest,
        );

        // Corresponds to the row inserted for the END operation added to the trace.
        self.increment_clk(tracer);

        // execute any decorators which have not been executed during span ops execution; this can
        // happen for decorators appearing after all operations in a block. these decorators are
        // executed after BASIC BLOCK is closed to make sure the VM clock cycle advances beyond the
        // last clock cycle of the BASIC BLOCK ops.
        for (_, decorator_id) in decorator_ids {
            let decorator = program
                .get_decorator_by_id(decorator_id)
                .ok_or(ExecutionError::DecoratorNotFoundInForest { decorator_id })?;
            self.execute_decorator(decorator, host)?;
        }

        self.execute_after_exit_decorators(node_id, program, host)
    }

    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    async fn execute_op_batch(
        &mut self,
        basic_block: &BasicBlockNode,
        node_id: MastNodeId,
        batch: &OpBatch,
        batch_index: usize,
        decorators: &mut DecoratorOpLinkIterator<'_>,
        batch_offset_in_block: usize,
        program: &MastForest,
        host: &mut impl AsyncHost,
        continuation_stack: &mut ContinuationStack,
        current_forest: &Arc<MastForest>,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        let end_indices = batch.end_indices();
        let mut group_idx = 0;
        let mut next_group_idx = 1;

        // execute operations in the batch one by one
        for (op_idx_in_batch, op) in batch.ops().iter().enumerate() {
            let op_idx_in_block = batch_offset_in_block + op_idx_in_batch;
            while let Some((_, decorator_id)) = decorators.next_filtered(op_idx_in_block) {
                let decorator = program
                    .get_decorator_by_id(decorator_id)
                    .ok_or(ExecutionError::DecoratorNotFoundInForest { decorator_id })?;
                self.execute_decorator(decorator, host)?;
            }

            // if in trace mode, check if we need to record a trace state before executing the
            // operation
            tracer.start_clock_cycle(
                self,
                NodeExecutionState::BasicBlock { node_id, batch_index, op_idx_in_batch },
                continuation_stack,
                current_forest,
            );

            // Execute the operation.
            //
            // Note: we handle the `Emit` operation separately, because it is an async operation,
            // whereas all the other operations are synchronous (resulting in a significant
            // performance improvement).
            {
                let err_ctx = err_ctx!(program, basic_block, host, op_idx_in_block);
                match op {
                    Operation::Emit => self.op_emit(host, &err_ctx).await?,
                    _ => {
                        // if the operation is not an Emit, we execute it normally
                        self.execute_sync_op(op, op_idx_in_block, program, host, &err_ctx, tracer)?;
                    },
                }
            }

            // if the operation carries an immediate value, the value is stored at the next group
            // pointer; so, we advance the pointer to the following group
            let has_imm = op.imm_value().is_some();
            if has_imm {
                next_group_idx += 1;
            }

            // determine if we've executed all operations in a group
            if op_idx_in_batch + 1 == end_indices[group_idx] {
                // then, move to the next group and reset operation index
                group_idx = next_group_idx;
                next_group_idx += 1;
            }

            self.increment_clk(tracer);
        }

        Ok(())
    }

    #[inline(always)]
    async fn op_emit(
        &mut self,
        host: &mut impl AsyncHost,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        let mut process = self.state();
        let event_id = EventId::from_felt(process.get_stack_item(0));

        // If it's a system event, handle it directly. Otherwise, forward it to the host.
        if let Some(system_event) = SystemEvent::from_event_id(event_id) {
            handle_system_event(&mut process, system_event, err_ctx)
        } else {
            let clk = process.clk();
            let mutations = host.on_event(&process).await.map_err(|err| {
                let event_name = host.resolve_event(event_id).cloned();
                ExecutionError::event_error(err, event_id, event_name, err_ctx)
            })?;
            self.advice
                .apply_mutations(mutations)
                .map_err(|err| ExecutionError::advice_error(err, clk, err_ctx))?;
            Ok(())
        }
    }
}
