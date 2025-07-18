use miden_core::{Felt, mast::MastForest, sys_events::SystemEvent};

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
        op_idx: usize,
        host: &mut impl BaseHost,
        program: &MastForest,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        if self.stack_get(0) != ONE {
            let process = &mut self.state(op_idx);
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
    pub fn op_clk(&mut self, op_idx: usize) -> Result<(), ExecutionError> {
        self.increment_stack_size();
        self.stack_write(0, (self.clk + op_idx).into());
        Ok(())
    }

    /// Analogous to `Process::op_emit`.
    #[inline(always)]
    pub async fn op_emit(
        &mut self,
        event_id: u32,
        op_idx: usize,
        host: &mut impl AsyncHost,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        let mut process = self.state(op_idx);
        // If it's a system event, handle it directly. Otherwise, forward it to the host.
        if let Some(system_event) = SystemEvent::from_event_id(event_id) {
            handle_system_event(&mut process, system_event, err_ctx)
        } else {
            let clk = process.clk();
            let mutations = host
                .on_event(&process, event_id)
                .await
                .map_err(|err| ExecutionError::event_error(err, event_id, err_ctx))?;
            self.advice
                .apply_mutations(mutations)
                .map_err(|err| ExecutionError::advice_error(err, clk, err_ctx))?;
            Ok(())
        }
    }
}
