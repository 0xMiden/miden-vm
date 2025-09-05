use alloc::sync::Arc;

use miden_core::{
    DecoratorIterator, Operation,
    mast::{BasicBlockNode, MastForest, MastNodeId, OpBatch},
    stack::MIN_STACK_DEPTH,
};

use crate::{
    AsyncHost, ErrorContext, ExecutionError,
    continuation_stack::ContinuationStack,
    err_ctx,
    fast::{FastProcessor, Tracer, trace_state::NodeExecutionState},
};

mod circuit_eval;
mod crypto_ops;
mod field_ops;
mod fri_ops;
mod horner_ops;
mod io_ops;
mod stack_ops;
mod sys_ops;
mod u32_ops;

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

        // Corresponds to the row inserted for the SPAN operation added to the trace.
        self.increment_clk(tracer);

        let mut batch_offset_in_block = 0;
        let mut op_batches = basic_block_node.op_batches().iter();
        let mut decorator_ids = basic_block_node.decorator_iter();

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
            // RESPAN
            {
                tracer.start_clock_cycle(
                    self,
                    NodeExecutionState::Respan {
                        node_id,
                        batch_index: batch_index_minus_1 + 1,
                    },
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
                batch_index_minus_1 + 1,
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
        // executed after SPAN block is closed to make sure the VM clock cycle advances beyond the
        // last clock cycle of the SPAN block ops.
        for &decorator_id in decorator_ids {
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
        decorators: &mut DecoratorIterator<'_>,
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
            while let Some(&decorator_id) = decorators.next_filtered(op_idx_in_block) {
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

            let err_ctx = err_ctx!(program, basic_block, host, op_idx_in_block);

            // Execute the operation.
            //
            // Note: we handle the `Emit` operation separately, because it is an async operation,
            // whereas all the other operations are synchronous (resulting in a significant
            // performance improvement).
            match op {
                Operation::Emit => {
                    if self.bounds_check_counter == 0 {
                        let err_str = if self.stack_top_idx - MIN_STACK_DEPTH == 0 {
                            "stack underflow"
                        } else {
                            "stack overflow"
                        };
                        return Err(ExecutionError::FailedToExecuteProgram(err_str));
                    }

                    self.op_emit(host, &err_ctx).await?
                },
                _ => {
                    // if the operation is not an Emit, we execute it normally
                    self.execute_op(op, op_idx_in_block, program, host, &err_ctx, tracer)?;
                },
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

    /// Executes the given operation.
    ///
    /// # Panics
    /// - if the operation is a control flow operation, as these are never executed,
    /// - if the operation is an `Emit` operation, as this requires async execution.
    #[inline(always)]
    fn execute_op(
        &mut self,
        operation: &Operation,
        op_idx: usize,
        program: &MastForest,
        host: &mut impl AsyncHost,
        err_ctx: &impl ErrorContext,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        if self.bounds_check_counter == 0 {
            let err_str = if self.stack_top_idx - MIN_STACK_DEPTH == 0 {
                "stack underflow"
            } else {
                "stack overflow"
            };
            return Err(ExecutionError::FailedToExecuteProgram(err_str));
        }

        match operation {
            // ----- system operations ------------------------------------------------------------
            Operation::Noop => {
                // do nothing
            },
            Operation::Assert(err_code) => {
                self.op_assert(*err_code, host, program, err_ctx, tracer)?
            },
            Operation::FmpAdd => self.op_fmpadd(),
            Operation::FmpUpdate => self.op_fmpupdate(tracer)?,
            Operation::SDepth => self.op_sdepth(tracer),
            Operation::Caller => self.op_caller()?,
            Operation::Clk => self.op_clk(tracer)?,
            Operation::Emit => {
                panic!("emit instruction requires async, so is not supported by execute_op()")
            },

            // ----- flow control operations ------------------------------------------------------
            // control flow operations are never executed directly
            Operation::Join => unreachable!("control flow operation"),
            Operation::Split => unreachable!("control flow operation"),
            Operation::Loop => unreachable!("control flow operation"),
            Operation::Call => unreachable!("control flow operation"),
            Operation::SysCall => unreachable!("control flow operation"),
            Operation::Dyn => unreachable!("control flow operation"),
            Operation::Dyncall => unreachable!("control flow operation"),
            Operation::Span => unreachable!("control flow operation"),
            Operation::Repeat => unreachable!("control flow operation"),
            Operation::Respan => unreachable!("control flow operation"),
            Operation::End => unreachable!("control flow operation"),
            Operation::Halt => unreachable!("control flow operation"),

            // ----- field operations -------------------------------------------------------------
            Operation::Add => self.op_add(tracer)?,
            Operation::Neg => self.op_neg()?,
            Operation::Mul => self.op_mul(tracer)?,
            Operation::Inv => self.op_inv(err_ctx)?,
            Operation::Incr => self.op_incr()?,
            Operation::And => self.op_and(tracer, err_ctx)?,
            Operation::Or => self.op_or(tracer, err_ctx)?,
            Operation::Not => self.op_not(err_ctx)?,
            Operation::Eq => self.op_eq(tracer)?,
            Operation::Eqz => self.op_eqz()?,
            Operation::Expacc => self.op_expacc(),
            Operation::Ext2Mul => self.op_ext2mul(),

            // ----- u32 operations ---------------------------------------------------------------
            Operation::U32split => self.op_u32split(tracer),
            Operation::U32add => self.op_u32add(err_ctx)?,
            Operation::U32add3 => self.op_u32add3(err_ctx, tracer)?,
            Operation::U32sub => self.op_u32sub(op_idx, err_ctx, tracer)?,
            Operation::U32mul => self.op_u32mul(err_ctx)?,
            Operation::U32madd => self.op_u32madd(err_ctx, tracer)?,
            Operation::U32div => self.op_u32div(err_ctx, tracer)?,
            Operation::U32and => self.op_u32and(err_ctx, tracer)?,
            Operation::U32xor => self.op_u32xor(err_ctx, tracer)?,
            Operation::U32assert2(err_code) => self.op_u32assert2(*err_code, err_ctx, tracer)?,

            // ----- stack manipulation -----------------------------------------------------------
            Operation::Pad => self.op_pad(tracer),
            Operation::Drop => self.decrement_stack_size(tracer),
            Operation::Dup0 => self.dup_nth(0, tracer),
            Operation::Dup1 => self.dup_nth(1, tracer),
            Operation::Dup2 => self.dup_nth(2, tracer),
            Operation::Dup3 => self.dup_nth(3, tracer),
            Operation::Dup4 => self.dup_nth(4, tracer),
            Operation::Dup5 => self.dup_nth(5, tracer),
            Operation::Dup6 => self.dup_nth(6, tracer),
            Operation::Dup7 => self.dup_nth(7, tracer),
            Operation::Dup9 => self.dup_nth(9, tracer),
            Operation::Dup11 => self.dup_nth(11, tracer),
            Operation::Dup13 => self.dup_nth(13, tracer),
            Operation::Dup15 => self.dup_nth(15, tracer),
            Operation::Swap => self.op_swap(),
            Operation::SwapW => self.swapw_nth(1),
            Operation::SwapW2 => self.swapw_nth(2),
            Operation::SwapW3 => self.swapw_nth(3),
            Operation::SwapDW => self.op_swap_double_word(),
            Operation::MovUp2 => self.rotate_left(3),
            Operation::MovUp3 => self.rotate_left(4),
            Operation::MovUp4 => self.rotate_left(5),
            Operation::MovUp5 => self.rotate_left(6),
            Operation::MovUp6 => self.rotate_left(7),
            Operation::MovUp7 => self.rotate_left(8),
            Operation::MovUp8 => self.rotate_left(9),
            Operation::MovDn2 => self.rotate_right(3),
            Operation::MovDn3 => self.rotate_right(4),
            Operation::MovDn4 => self.rotate_right(5),
            Operation::MovDn5 => self.rotate_right(6),
            Operation::MovDn6 => self.rotate_right(7),
            Operation::MovDn7 => self.rotate_right(8),
            Operation::MovDn8 => self.rotate_right(9),
            Operation::CSwap => self.op_cswap(err_ctx, tracer)?,
            Operation::CSwapW => self.op_cswapw(err_ctx, tracer)?,

            // ----- input / output ---------------------------------------------------------------
            Operation::Push(element) => self.op_push(*element, tracer),
            Operation::AdvPop => self.op_advpop(err_ctx, tracer)?,
            Operation::AdvPopW => self.op_advpopw(err_ctx, tracer)?,
            Operation::MLoadW => self.op_mloadw(err_ctx, tracer)?,
            Operation::MStoreW => self.op_mstorew(err_ctx, tracer)?,
            Operation::MLoad => self.op_mload(err_ctx, tracer)?,
            Operation::MStore => self.op_mstore(err_ctx, tracer)?,
            Operation::MStream => self.op_mstream(err_ctx, tracer)?,
            Operation::Pipe => self.op_pipe(err_ctx, tracer)?,

            // ----- cryptographic operations -----------------------------------------------------
            Operation::HPerm => self.op_hperm(tracer),
            Operation::MpVerify(err_code) => {
                self.op_mpverify(*err_code, program, tracer, err_ctx)?
            },
            Operation::MrUpdate => self.op_mrupdate(tracer, err_ctx)?,
            Operation::FriE2F4 => self.op_fri_ext2fold4(tracer)?,
            Operation::HornerBase => self.op_horner_eval_base(tracer, err_ctx)?,
            Operation::HornerExt => self.op_horner_eval_ext(tracer, err_ctx)?,
            Operation::EvalCircuit => self.op_eval_circuit(err_ctx)?,
        }

        Ok(())
    }
}
