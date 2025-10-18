use alloc::{sync::Arc, vec::Vec};

use miden_air::Felt;
use miden_core::{
    Program, ZERO,
    mast::{CallNode, MastForest, MastNodeExt, MastNodeId},
    stack::MIN_STACK_DEPTH,
    utils::range,
};

use crate::{
    AsyncHost, ContextId, ErrorContext, ExecutionError, FMP_MIN, SYSCALL_FMP_MIN,
    continuation_stack::ContinuationStack,
    err_ctx,
    fast::{
        ExecutionContextInfo, FastProcessor, INITIAL_STACK_TOP_IDX, STACK_BUFFER_SIZE, Tracer,
        trace_state::NodeExecutionState,
    },
};

impl FastProcessor {
    /// Executes a Call node from the start.
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    pub(super) fn start_call_node(
        &mut self,
        call_node: &CallNode,
        current_node_id: MastNodeId,
        program: &Program,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        tracer.start_clock_cycle(
            self,
            NodeExecutionState::Start(current_node_id),
            continuation_stack,
            current_forest,
        );

        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(current_node_id, current_forest, host)?;

        err_ctx!(current_forest, call_node, host);

        // call or syscall are not allowed inside a syscall
        if self.in_syscall {
            let instruction = if call_node.is_syscall() { "syscall" } else { "call" };
            return Err(ExecutionError::CallInSyscall(instruction));
        }

        let callee_hash = current_forest
            .get_node_by_id(call_node.callee())
            .ok_or(ExecutionError::MastNodeNotFoundInForest { node_id: call_node.callee() })?
            .digest();

        self.save_context_and_truncate_stack(tracer);

        if call_node.is_syscall() {
            // check if the callee is in the kernel
            if !program.kernel().contains_proc(callee_hash) {
                return Err(ExecutionError::syscall_target_not_in_kernel(callee_hash, &()));
            }

            // set the system registers to the syscall context
            self.ctx = ContextId::root();
            self.fmp = SYSCALL_FMP_MIN.into();
            self.in_syscall = true;
        } else {
            // set the system registers to the callee context. The value for the new context is
            // defined to be the value of the clock cycle for the following operation.
            self.ctx = (self.clk + 1).into();
            self.fmp = Felt::new(FMP_MIN);
            self.caller_hash = callee_hash;
        }

        // push the callee onto the continuation stack, and increment the clock (corresponding to
        // the row inserted for the CALL or SYSCALL operation added to the trace).
        continuation_stack.push_finish_call(current_node_id);
        continuation_stack.push_start_node(call_node.callee());

        // Corresponds to the CALL or SYSCALL operation added to the trace.
        self.increment_clk(tracer);

        Ok(())
    }

    /// Executes the finish phase of a Call node.
    #[inline(always)]
    pub(super) fn finish_call_node(
        &mut self,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        tracer.start_clock_cycle(
            self,
            NodeExecutionState::End(node_id),
            continuation_stack,
            current_forest,
        );

        let _call_node = current_forest[node_id].unwrap_call();
        err_ctx!(current_forest, _call_node, host);
        // when returning from a function call or a syscall, restore the
        // context of the
        // system registers and the operand stack to what it was prior
        // to the call.
        self.restore_context(tracer, &())?;

        // Corresponds to the row inserted for the END operation added to the trace.
        self.increment_clk(tracer);
        self.execute_after_exit_decorators(node_id, current_forest, host)
    }

    /// Executes a Dyn node from the start.
    #[inline(always)]
    pub(super) async fn start_dyn_node(
        &mut self,
        current_node_id: MastNodeId,
        current_forest: &mut Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        tracer.start_clock_cycle(
            self,
            NodeExecutionState::Start(current_node_id),
            continuation_stack,
            current_forest,
        );

        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(current_node_id, current_forest, host)?;

        // Corresponds to the row inserted for the DYN or DYNCALL operation
        // added to the trace.
        let dyn_node = current_forest[current_node_id].unwrap_dyn();

        // dyn calls are not allowed inside a syscall
        if dyn_node.is_dyncall() && self.in_syscall {
            return Err(ExecutionError::CallInSyscall("dyncall"));
        }

        err_ctx!(&current_forest, dyn_node, host);

        // Retrieve callee hash from memory, using stack top as the memory
        // address.
        let callee_hash = {
            let mem_addr = self.stack_get(0);
            let word = self
                .memory
                .read_word(self.ctx, mem_addr, self.clk, &())
                .map_err(ExecutionError::MemoryError)?;
            tracer.record_memory_read_word(word, mem_addr);

            word
        };

        // Drop the memory address from the stack. This needs to be done before saving the context.
        self.decrement_stack_size(tracer);

        // For dyncall, save the context and reset it.
        if dyn_node.is_dyncall() {
            self.save_context_and_truncate_stack(tracer);
            // The value for the new context is defined to be the value of the clock cycle for the
            // following operation.
            self.ctx = (self.clk + 1).into();
            self.fmp = Felt::new(FMP_MIN);
            self.caller_hash = callee_hash;
        };

        // Update continuation stack
        // -----------------------------
        continuation_stack.push_finish_dyn(current_node_id);

        // if the callee is not in the program's MAST forest, try to find a MAST forest for it in
        // the host (corresponding to an external library loaded in the host); if none are found,
        // return an error.
        match current_forest.find_procedure_root(callee_hash) {
            Some(callee_id) => {
                continuation_stack.push_start_node(callee_id);
            },
            None => {
                let (root_id, new_forest) = self
                    .load_mast_forest(
                        callee_hash,
                        host,
                        ExecutionError::dynamic_node_not_found,
                        &(),
                    )
                    .await?;

                // Push current forest to the continuation stack so that we can return to it
                continuation_stack.push_enter_forest(current_forest.clone());

                // Push the root node of the external MAST forest onto the continuation stack.
                continuation_stack.push_start_node(root_id);

                // Set the new MAST forest as current
                *current_forest = new_forest;
            },
        }

        // Increment the clock, corresponding to the row inserted for the DYN or DYNCALL operation
        // added to the trace.
        self.increment_clk(tracer);

        Ok(())
    }

    /// Executes the finish phase of a Dyn node.
    #[inline(always)]
    pub(super) fn finish_dyn_node(
        &mut self,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        continuation_stack: &mut ContinuationStack,
        host: &mut impl AsyncHost,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        tracer.start_clock_cycle(
            self,
            NodeExecutionState::End(node_id),
            continuation_stack,
            current_forest,
        );

        let dyn_node = current_forest[node_id].unwrap_dyn();
        err_ctx!(current_forest, dyn_node, host);
        // For dyncall, restore the context.
        if dyn_node.is_dyncall() {
            self.restore_context(tracer, &())?;
        }

        // Corresponds to the row inserted for the END operation added to
        // the trace.
        self.increment_clk(tracer);
        self.execute_after_exit_decorators(node_id, current_forest, host)
    }

    // HELPERS
    // ----------------------------------------------------------------------------------------------

    /// Saves the current execution context and truncates the stack to 16 elements in preparation to
    /// start a new execution context.
    fn save_context_and_truncate_stack(&mut self, tracer: &mut impl Tracer) {
        let overflow_stack = if self.stack_size() > MIN_STACK_DEPTH {
            // save the overflow stack, and zero out the buffer.
            //
            // Note: we need to zero the overflow buffer, since the new context expects ZERO's to be
            // pulled in if they decrement the stack size (e.g. by executing a `drop`).
            let overflow_stack =
                self.stack[self.stack_bot_idx..self.stack_top_idx - MIN_STACK_DEPTH].to_vec();
            self.stack[self.stack_bot_idx..self.stack_top_idx - MIN_STACK_DEPTH].fill(ZERO);

            overflow_stack
        } else {
            Vec::new()
        };

        self.stack_bot_idx = self.stack_top_idx - MIN_STACK_DEPTH;

        self.call_stack.push(ExecutionContextInfo {
            overflow_stack,
            ctx: self.ctx,
            fn_hash: self.caller_hash,
            fmp: self.fmp,
        });

        tracer.start_context();
    }

    /// Restores the execution context to the state it was in before the last `call`, `syscall` or
    /// `dyncall`.
    ///
    /// This includes restoring the overflow stack and the system parameters.
    ///
    /// # Errors
    /// - Returns an error if the overflow stack is larger than the space available in the stack
    ///   buffer.
    fn restore_context(
        &mut self,
        tracer: &mut impl Tracer,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        // when a call/dyncall/syscall node ends, stack depth must be exactly 16.
        if self.stack_size() > MIN_STACK_DEPTH {
            return Err(ExecutionError::invalid_stack_depth_on_return(self.stack_size(), err_ctx));
        }

        let ctx_info = self
            .call_stack
            .pop()
            .expect("execution context stack should never be empty when restoring context");

        // restore the overflow stack
        self.restore_overflow_stack(&ctx_info);

        // restore system parameters
        self.ctx = ctx_info.ctx;
        self.fmp = ctx_info.fmp;
        self.in_syscall = false;
        self.caller_hash = ctx_info.fn_hash;

        tracer.restore_context();

        Ok(())
    }

    /// Restores the overflow stack from a previous context.
    ///
    /// If necessary, moves the stack in the buffer to make room for the overflow stack to be
    /// restored.
    ///
    /// # Preconditions
    /// - The current stack depth is exactly `MIN_STACK_DEPTH` (16).
    #[inline(always)]
    fn restore_overflow_stack(&mut self, ctx_info: &ExecutionContextInfo) {
        let target_overflow_len = ctx_info.overflow_stack.len();

        // Check if there's enough room to restore the overflow stack in the current stack buffer.
        if target_overflow_len > self.stack_bot_idx {
            // There's not enough room to restore the overflow stack, so we have to move the
            // location of the stack in the buffer. We reset it so that after restoring the overflow
            // stack, the stack_bot_idx is at its original position (i.e. INITIAL_STACK_TOP_IDX -
            // 16).
            let new_stack_top_idx =
                core::cmp::min(INITIAL_STACK_TOP_IDX + target_overflow_len, STACK_BUFFER_SIZE - 1);

            self.reset_stack_in_buffer(new_stack_top_idx);
        }

        // Restore the overflow
        self.stack[range(self.stack_bot_idx - target_overflow_len, target_overflow_len)]
            .copy_from_slice(&ctx_info.overflow_stack);
        self.stack_bot_idx -= target_overflow_len;
    }
}
