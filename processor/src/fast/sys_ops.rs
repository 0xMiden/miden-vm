use miden_core::{Felt, ReducedEventID, mast::MastForest, sys_events::SystemEvent};

use super::{ExecutionError, FastProcessor, ONE};
use crate::{
    AsyncHost, BaseHost, ErrorContext, FMP_MIN,
    operations::sys_ops::sys_event_handlers::handle_system_event, system::FMP_MAX,
};

impl FastProcessor {
    /// Analogous to `Process::op_assert`.
    #[inline(always)]
    pub fn op_assert(
        &mut self,
        err_code: Felt,
        host: &mut impl BaseHost,
        program: &MastForest,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        if self.stack_get(0) != ONE {
            let process = &mut self.state();
            host.on_assert_failed(process, err_code);
            let err_msg = program.resolve_error_message(err_code);
            return Err(ExecutionError::failed_assertion(
                process.clk(),
                err_code,
                err_msg,
                err_ctx,
            ));
        }
        self.decrement_stack_size();
        Ok(())
    }

    /// Analogous to `Process::op_fmpadd`.
    pub fn op_fmpadd(&mut self) {
        let fmp = self.fmp;
        let top = self.stack_get_mut(0);

        *top += fmp;
    }

    /// Analogous to `Process::op_fmpupdate`.
    pub fn op_fmpupdate(&mut self) -> Result<(), ExecutionError> {
        let top = self.stack_get(0);

        let new_fmp = self.fmp + top;
        let new_fmp_int = new_fmp.as_int();
        if !(FMP_MIN..=FMP_MAX).contains(&new_fmp_int) {
            return Err(ExecutionError::InvalidFmpValue(self.fmp, new_fmp));
        }

        self.fmp = new_fmp;
        self.decrement_stack_size();
        Ok(())
    }

    /// Analogous to `Process::op_sdepth`.
    pub fn op_sdepth(&mut self) {
        let depth = self.stack_depth();
        self.increment_stack_size();
        self.stack_write(0, depth.into());
    }

    /// Analogous to `Process::op_caller`.
    pub fn op_caller(&mut self) -> Result<(), ExecutionError> {
        if !self.in_syscall {
            return Err(ExecutionError::CallerNotInSyscall);
        }

        let caller_hash = self.caller_hash;
        self.stack_write_word(0, &caller_hash);

        Ok(())
    }

    /// Analogous to `Process::op_clk`.
    pub fn op_clk(&mut self) -> Result<(), ExecutionError> {
        self.increment_stack_size();
        self.stack_write(0, self.clk.into());
        Ok(())
    }

    /// Analogous to `Process::op_emit` with EventTable reverse lookup.
    #[inline(always)]
    pub async fn op_emit(
        &mut self,
        reduced_event_id: ReducedEventID,
        program: &MastForest,
        host: &mut impl AsyncHost,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        let mut process = self.state();
        let event_felt = reduced_event_id.as_felt();
        
        // Attempt EventTable reverse lookup to get EventId from ReducedEventID
        let _resolved_event_id = program.event_table().lookup_by_reduced_id(reduced_event_id);
        
        // Note: EventTable reverse lookup is now available for enhanced event handling.
        // Resolved EventId can be used by event handlers or debugging tools when needed.
        
        // If it's a system event, handle it directly. Otherwise, forward it to the host.
        if let Some(system_event) = SystemEvent::from_felt_id(event_felt) {
            handle_system_event(&mut process, system_event, err_ctx)
        } else {
            let clk = process.clk();
            let mutations = host
                .on_event(&process, event_felt)
                .await
                .map_err(|err| ExecutionError::event_error(err, event_felt, err_ctx))?;
            self.advice
                .apply_mutations(mutations)
                .map_err(|err| ExecutionError::advice_error(err, clk, err_ctx))?;
            Ok(())
        }
    }
}
