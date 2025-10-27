use miden_core::{EventId, Felt, mast::MastForest, sys_events::SystemEvent};

use super::{
    super::{
        ONE,
        system::{FMP_MAX, FMP_MIN},
    },
    ExecutionError, Process,
};
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
            host.on_assert_failed(process, err_code);
            let err_msg = program.resolve_error_message(err_code);
            return Err(ExecutionError::failed_assertion(
                process.clk(),
                err_code,
                err_msg,
                err_ctx,
            ));
        }
        self.stack.shift_left(1);
        Ok(())
    }

    // FREE MEMORY POINTER
    // --------------------------------------------------------------------------------------------

    /// Pops an element off the stack, adds the current value of the `fmp` register to it, and
    /// pushes the result back onto the stack.
    pub(super) fn op_fmpadd(&mut self) -> Result<(), ExecutionError> {
        let offset = self.stack.get(0);
        let fmp = self.system.fmp();

        self.stack.set(0, fmp + offset);
        self.stack.copy_state(1);

        Ok(())
    }

    /// Pops an element off the stack and adds it to the current value of `fmp` register.
    ///
    /// # Errors
    /// Returns an error if the new value of `fmp` register is greater than or equal to 3 * 2^30.
    pub(super) fn op_fmpupdate(&mut self) -> Result<(), ExecutionError> {
        let offset = self.stack.get(0);
        let fmp = self.system.fmp();

        let new_fmp = fmp + offset;
        if new_fmp.as_int() < FMP_MIN || new_fmp.as_int() > FMP_MAX {
            return Err(ExecutionError::InvalidFmpValue(fmp, new_fmp));
        }

        self.system.set_fmp(new_fmp);
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
        if !self.system.in_syscall() {
            return Err(ExecutionError::CallerNotInSyscall);
        }

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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::mast::MastForest;

    use super::{
        super::{MIN_STACK_DEPTH, Operation},
        FMP_MAX, FMP_MIN, Felt, Process,
    };
    use crate::{DefaultHost, ONE, StackInputs, ZERO};

    const MAX_PROC_LOCALS: u64 = 2_u64.pow(31) - 1;

    #[test]
    fn op_assert() {
        let mut host = DefaultHost::default();
        // calling assert with a minimum stack should be an ok, as long as the top value is ONE
        let mut process = Process::new_dummy_with_empty_stack();
        let program = &MastForest::default();

        process.execute_op(Operation::Push(ONE), program, &mut host).unwrap();
        process.execute_op(Operation::Swap, program, &mut host).unwrap();
        process.execute_op(Operation::Drop, program, &mut host).unwrap();

        assert!(process.execute_op(Operation::Assert(ZERO), program, &mut host).is_ok());
    }

    #[test]
    fn op_fmpupdate() {
        let mut host = DefaultHost::default();
        let mut process = Process::new_dummy_with_empty_stack();
        let program = &MastForest::default();

        // initial value of fmp register should be 2^30
        assert_eq!(Felt::new(2_u64.pow(30)), process.system.fmp());

        // increment fmp register
        process.execute_op(Operation::Push(Felt::new(2)), program, &mut host).unwrap();
        process.execute_op(Operation::FmpUpdate, program, &mut host).unwrap();
        assert_eq!(Felt::new(FMP_MIN + 2), process.system.fmp());

        // increment fmp register again
        process.execute_op(Operation::Push(Felt::new(3)), program, &mut host).unwrap();
        process.execute_op(Operation::FmpUpdate, program, &mut host).unwrap();
        assert_eq!(Felt::new(FMP_MIN + 5), process.system.fmp());

        // decrement fmp register
        process.execute_op(Operation::Push(-Felt::new(3)), program, &mut host).unwrap();
        process.execute_op(Operation::FmpUpdate, program, &mut host).unwrap();
        assert_eq!(Felt::new(FMP_MIN + 2), process.system.fmp());

        // decrementing beyond the minimum fmp value should be an error
        process.execute_op(Operation::Push(-Felt::new(3)), program, &mut host).unwrap();
        assert!(process.execute_op(Operation::FmpUpdate, program, &mut host).is_err());

        // going up to the max fmp value should be OK
        let stack = StackInputs::try_from_ints([MAX_PROC_LOCALS]).unwrap();
        let mut process = Process::new_dummy(stack);
        process.execute_op(Operation::FmpUpdate, program, &mut host).unwrap();
        assert_eq!(Felt::new(FMP_MAX), process.system.fmp());

        // but going beyond that should be an error
        let stack = StackInputs::try_from_ints([MAX_PROC_LOCALS + 1]).unwrap();
        let mut process = Process::new_dummy(stack);
        assert!(process.execute_op(Operation::FmpUpdate, program, &mut host).is_err());

        // should not affect the rest of the stack state
        let stack = StackInputs::try_from_ints([2, 3]).unwrap();
        let mut process = Process::new_dummy(stack);
        process.execute_op(Operation::FmpUpdate, program, &mut host).unwrap();

        let expected = build_expected_stack(&[2]);
        assert_eq!(expected, process.stack.trace_state());

        // calling fmpupdate with a minimum stack should be ok
        let mut process = Process::new_dummy_with_empty_stack();
        assert!(process.execute_op(Operation::FmpUpdate, program, &mut host).is_ok());
    }

    #[test]
    fn op_fmpadd() {
        let mut host = DefaultHost::default();
        let mut process = Process::new_dummy_with_empty_stack();
        let program = &MastForest::default();

        // set value of fmp register
        process.execute_op(Operation::Push(Felt::new(2)), program, &mut host).unwrap();
        process.execute_op(Operation::FmpUpdate, program, &mut host).unwrap();

        // compute address of the first local
        process.execute_op(Operation::Push(-ONE), program, &mut host).unwrap();
        process.execute_op(Operation::FmpAdd, program, &mut host).unwrap();

        let expected = build_expected_stack(&[FMP_MIN + 1]);
        assert_eq!(expected, process.stack.trace_state());

        // compute address of second local (also make sure that rest of stack is not affected)
        process.execute_op(Operation::Push(-Felt::new(2)), program, &mut host).unwrap();
        process.execute_op(Operation::FmpAdd, program, &mut host).unwrap();

        let expected = build_expected_stack(&[FMP_MIN, FMP_MIN + 1]);
        assert_eq!(expected, process.stack.trace_state());
    }

    #[test]
    fn op_sdepth() {
        let mut host = DefaultHost::default();
        // stack is empty
        let mut process = Process::new_dummy_with_empty_stack();
        let program = &MastForest::default();

        process.execute_op(Operation::SDepth, program, &mut host).unwrap();
        let expected = build_expected_stack(&[MIN_STACK_DEPTH as u64]);
        assert_eq!(expected, process.stack.trace_state());
        assert_eq!(MIN_STACK_DEPTH + 1, process.stack.depth());

        // stack has one item
        process.execute_op(Operation::SDepth, program, &mut host).unwrap();
        let expected = build_expected_stack(&[MIN_STACK_DEPTH as u64 + 1, MIN_STACK_DEPTH as u64]);
        assert_eq!(expected, process.stack.trace_state());
        assert_eq!(MIN_STACK_DEPTH + 2, process.stack.depth());

        // stack has 3 items
        process.execute_op(Operation::Pad, program, &mut host).unwrap();
        process.execute_op(Operation::SDepth, program, &mut host).unwrap();
        let expected = build_expected_stack(&[
            MIN_STACK_DEPTH as u64 + 3,
            0,
            MIN_STACK_DEPTH as u64 + 1,
            MIN_STACK_DEPTH as u64,
        ]);
        assert_eq!(expected, process.stack.trace_state());
        assert_eq!(MIN_STACK_DEPTH + 4, process.stack.depth());
    }

    #[test]
    fn op_clk() {
        let mut host = DefaultHost::default();
        let mut process = Process::new_dummy_with_empty_stack();
        let program = &MastForest::default();

        // initial value of clk register should be 1.
        process.execute_op(Operation::Clk, program, &mut host).unwrap();
        let expected = build_expected_stack(&[1]);
        assert_eq!(expected, process.stack.trace_state());

        // increment clk register.
        process.execute_op(Operation::Push(Felt::new(2)), program, &mut host).unwrap();
        process.execute_op(Operation::Clk, program, &mut host).unwrap();
        let expected = build_expected_stack(&[3, 2, 1]);
        assert_eq!(expected, process.stack.trace_state());

        // increment clk register again.
        process.execute_op(Operation::Push(Felt::new(3)), program, &mut host).unwrap();
        process.execute_op(Operation::Clk, program, &mut host).unwrap();
        let expected = build_expected_stack(&[5, 3, 3, 2, 1]);
        assert_eq!(expected, process.stack.trace_state());
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    fn build_expected_stack(values: &[u64]) -> [Felt; 16] {
        let mut expected = [ZERO; 16];
        for (&value, result) in values.iter().zip(expected.iter_mut()) {
            *result = Felt::new(value);
        }
        expected
    }
}
