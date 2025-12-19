use miden_core::{EventId, Felt, mast::MastForest, sys_events::SystemEvent};

use super::{super::ONE, ExecutionError, Process};
use crate::{
    SyncHost, errors::ErrorContext, operations::sys_ops::sys_event_handlers::handle_system_event,
};

pub(crate) mod sys_event_handlers;

// SYSTEM OPERATIONS
// ================================================================================================

impl Process {
    /// Pops a value off the stack and asserts that it is equal to ONE.
    ///
    /// # Errors
    /// Returns an error if the popped value is not ONE.
    pub(super) fn op_assert<H>(
        &mut self,
        err_code: Felt,
        program: &MastForest,
        host: &mut H,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError>
    where
        H: SyncHost,
    {
        if self.stack.get(0) != ONE {
            let process = &mut self.state();
            let clk = process.clk();
            let err = host.on_assert_failed(process, err_code);
            let err_msg = program.resolve_error_message(err_code);
            return Err(ExecutionError::failed_assertion(clk, err_code, err_msg, err, err_ctx));
        }
        self.stack.shift_left(1);
        Ok(())
    }

    // STACK DEPTH
    // --------------------------------------------------------------------------------------------

    /// Pushes the current depth of the stack (the depth before this operation is executed) onto
    /// the stack.
    pub(super) fn op_sdepth(&mut self) -> Result<(), ExecutionError> {
        let stack_depth = self.stack.depth();
        self.stack.set(0, Felt::new(stack_depth as u64));
        self.stack.shift_right(0);
        Ok(())
    }

    // CALLER
    // --------------------------------------------------------------------------------------------

    /// Overwrites the top four stack items with the hash of a function which initiated the current
    /// SYSCALL.
    ///
    /// # Errors
    /// Returns an error if the VM is not currently executing a SYSCALL block.
    pub(super) fn op_caller(&mut self) -> Result<(), ExecutionError> {
        let fn_hash = self.system.fn_hash();

        self.stack.set(0, fn_hash[3]);
        self.stack.set(1, fn_hash[2]);
        self.stack.set(2, fn_hash[1]);
        self.stack.set(3, fn_hash[0]);

        self.stack.copy_state(4);

        Ok(())
    }

    // CLOCK CYCLE
    // --------------------------------------------------------------------------------------------

    /// Pushes the current value of the clock cycle counter onto the stack. The clock cycle starts
    /// at 0 and is incremented with every operation executed by the VM, including control flow
    /// operations such as GRUOP, END etc.
    pub(super) fn op_clk(&mut self) -> Result<(), ExecutionError> {
        let clk = self.system.clk();
        self.stack.set(0, Felt::from(clk));
        self.stack.shift_right(0);
        Ok(())
    }

    // EVENTS
    // --------------------------------------------------------------------------------------------

    /// Forwards the emitted event id to the host. Reads the event ID from the top of the stack
    /// without consuming it.
    pub(super) fn op_emit<H>(
        &mut self,
        host: &mut H,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError>
    where
        H: SyncHost,
    {
        self.stack.copy_state(0);

        let mut process = self.state();
        let event_id = EventId::from_felt(process.get_stack_item(0));

        // If it's a system event, handle it directly. Otherwise, forward it to the host.
        if let Some(system_event) = SystemEvent::from_event_id(event_id) {
            handle_system_event(&mut process, system_event, err_ctx)
        } else {
            let clk = process.clk();
            let mutations = host.on_event(&process).map_err(|err| {
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
