use miden_core::{mast::MastForest, stack::MIN_STACK_DEPTH};

use super::{Felt, FieldElement, Operation, Process, SyncHost};
use crate::errors::OperationError;

mod circuit_eval;
mod crypto_ops;
mod ext2_ops;
mod field_ops;
mod fri_ops;
mod horner_ops;
mod io_ops;
mod stack_ops;
pub(crate) mod sys_ops;
mod u32_ops;
pub(crate) mod utils;

#[cfg(test)]
use super::Kernel;

// OPERATION DISPATCHER
// ================================================================================================

impl Process {
    /// Executes the specified operation.
    pub(super) fn execute_op(
        &mut self,
        op: Operation,
        program: &MastForest,
        host: &mut impl SyncHost,
    ) -> Result<(), OperationError> {
        // make sure there is enough memory allocated to hold the execution trace
        self.ensure_trace_capacity();

        // execute the operation
        match op {
            // ----- system operations ------------------------------------------------------------
            Operation::Noop => self.stack.copy_state(0),
            Operation::Assert(err_code) => self.op_assert(err_code, program, host)?,

            Operation::SDepth => self.op_sdepth()?,
            Operation::Caller => self.op_caller()?,

            Operation::Clk => self.op_clk()?,
            Operation::Emit => self.op_emit(host)?,

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
            Operation::Add => self.op_add()?,
            Operation::Neg => self.op_neg()?,
            Operation::Mul => self.op_mul()?,
            Operation::Inv => self.op_inv()?,
            Operation::Incr => self.op_incr()?,

            Operation::And => self.op_and()?,
            Operation::Or => self.op_or()?,
            Operation::Not => self.op_not()?,

            Operation::Eq => self.op_eq()?,
            Operation::Eqz => self.op_eqz()?,

            Operation::Expacc => self.op_expacc()?,

            // ----- ext2 operations --------------------------------------------------------------
            Operation::Ext2Mul => self.op_ext2mul()?,

            // ----- u32 operations ---------------------------------------------------------------
            Operation::U32split => self.op_u32split()?,
            Operation::U32add => self.op_u32add()?,
            Operation::U32add3 => self.op_u32add3()?,
            Operation::U32sub => self.op_u32sub()?,
            Operation::U32mul => self.op_u32mul()?,
            Operation::U32madd => self.op_u32madd()?,
            Operation::U32div => self.op_u32div()?,

            Operation::U32and => self.op_u32and()?,
            Operation::U32xor => self.op_u32xor()?,
            Operation::U32assert2(err_code) => self.op_u32assert2(err_code)?,

            // ----- stack manipulation -----------------------------------------------------------
            Operation::Pad => self.op_pad()?,
            Operation::Drop => self.op_drop()?,

            Operation::Dup0 => self.op_dup(0)?,
            Operation::Dup1 => self.op_dup(1)?,
            Operation::Dup2 => self.op_dup(2)?,
            Operation::Dup3 => self.op_dup(3)?,
            Operation::Dup4 => self.op_dup(4)?,
            Operation::Dup5 => self.op_dup(5)?,
            Operation::Dup6 => self.op_dup(6)?,
            Operation::Dup7 => self.op_dup(7)?,
            Operation::Dup9 => self.op_dup(9)?,
            Operation::Dup11 => self.op_dup(11)?,
            Operation::Dup13 => self.op_dup(13)?,
            Operation::Dup15 => self.op_dup(15)?,

            Operation::Swap => self.op_swap()?,
            Operation::SwapW => self.op_swapw()?,
            Operation::SwapW2 => self.op_swapw2()?,
            Operation::SwapW3 => self.op_swapw3()?,
            Operation::SwapDW => self.op_swapdw()?,

            Operation::MovUp2 => self.op_movup(2)?,
            Operation::MovUp3 => self.op_movup(3)?,
            Operation::MovUp4 => self.op_movup(4)?,
            Operation::MovUp5 => self.op_movup(5)?,
            Operation::MovUp6 => self.op_movup(6)?,
            Operation::MovUp7 => self.op_movup(7)?,
            Operation::MovUp8 => self.op_movup(8)?,

            Operation::MovDn2 => self.op_movdn(2)?,
            Operation::MovDn3 => self.op_movdn(3)?,
            Operation::MovDn4 => self.op_movdn(4)?,
            Operation::MovDn5 => self.op_movdn(5)?,
            Operation::MovDn6 => self.op_movdn(6)?,
            Operation::MovDn7 => self.op_movdn(7)?,
            Operation::MovDn8 => self.op_movdn(8)?,

            Operation::CSwap => self.op_cswap()?,
            Operation::CSwapW => self.op_cswapw()?,

            // ----- input / output ---------------------------------------------------------------
            Operation::Push(value) => self.op_push(value)?,

            Operation::AdvPop => self.op_advpop()?,
            Operation::AdvPopW => self.op_advpopw()?,

            Operation::MLoadW => self.op_mloadw()?,
            Operation::MStoreW => self.op_mstorew()?,

            Operation::MLoad => self.op_mload()?,
            Operation::MStore => self.op_mstore()?,

            Operation::MStream => self.op_mstream()?,
            Operation::Pipe => self.op_pipe()?,

            // ----- cryptographic operations -----------------------------------------------------
            Operation::HPerm => self.op_hperm()?,
            Operation::MpVerify(err_code) => self.op_mpverify(err_code, program)?,
            Operation::MrUpdate => self.op_mrupdate()?,
            Operation::FriE2F4 => self.op_fri_ext2fold4()?,
            Operation::HornerBase => self.op_horner_eval_base()?,
            Operation::HornerExt => self.op_horner_eval_ext()?,
            Operation::EvalCircuit => self.op_eval_circuit()?,
            Operation::LogPrecompile => self.op_log_precompile()?,
        }

        self.advance_clock()?;

        Ok(())
    }

    /// Increments the clock cycle for all components of the process.
    pub(super) fn advance_clock(&mut self) -> Result<(), OperationError> {
        self.system.advance_clock(self.max_cycles)?;
        self.stack.advance_clock();
        Ok(())
    }

    /// Makes sure there is enough memory allocated for the trace to accommodate a new clock cycle.
    pub(super) fn ensure_trace_capacity(&mut self) {
        self.system.ensure_trace_capacity();
        self.stack.ensure_trace_capacity();
    }
}

#[cfg(test)]
pub mod testing {
    use miden_air::ExecutionOptions;
    use miden_core::{StackInputs, mast::MastForest};

    use super::*;
    use crate::{AdviceInputs, DefaultHost};

    impl Process {
        /// Instantiates a new blank process for testing purposes. The stack in the process is
        /// initialized with the provided values.
        pub fn new_dummy(stack_inputs: StackInputs) -> Self {
            let mut host = DefaultHost::default();
            let mut process = Self::new(
                Kernel::default(),
                stack_inputs,
                AdviceInputs::default(),
                ExecutionOptions::default(),
            );
            let program = &MastForest::default();
            process.execute_op(Operation::Noop, program, &mut host).unwrap();
            process
        }

        /// Instantiates a new blank process for testing purposes.
        pub fn new_dummy_with_empty_stack() -> Self {
            let stack = StackInputs::default();
            Self::new_dummy(stack)
        }

        /// Instantiates a new process with an advice stack for testing purposes.
        pub fn new_dummy_with_advice_stack(advice_stack: &[u64]) -> (Self, DefaultHost) {
            let stack_inputs = StackInputs::default();
            let advice_inputs =
                AdviceInputs::default().with_stack_values(advice_stack.iter().copied()).unwrap();
            let mut host = DefaultHost::default();
            let mut process = Self::new(
                Kernel::default(),
                stack_inputs,
                advice_inputs,
                ExecutionOptions::default(),
            );
            let program = &MastForest::default();
            process.execute_op(Operation::Noop, program, &mut host).unwrap();

            (process, host)
        }

        /// Instantiates a new blank process with one decoder trace row for testing purposes. This
        /// allows for setting helpers in the decoder when executing operations during tests.
        pub fn new_dummy_with_decoder_helpers_and_empty_stack() -> Self {
            let stack_inputs = StackInputs::default();
            Self::new_dummy_with_decoder_helpers(stack_inputs)
        }

        /// Instantiates a new blank process with one decoder trace row for testing purposes. This
        /// allows for setting helpers in the decoder when executing operations during tests.
        ///
        /// The stack in the process is initialized with the provided values.
        pub fn new_dummy_with_decoder_helpers(stack_inputs: StackInputs) -> Self {
            let advice_inputs = AdviceInputs::default();
            let (process, _) =
                Self::new_dummy_with_inputs_and_decoder_helpers(stack_inputs, advice_inputs);
            process
        }

        /// Instantiates a new process having Program inputs along with one decoder trace row
        /// for testing purposes.
        pub fn new_dummy_with_inputs_and_decoder_helpers(
            stack_inputs: StackInputs,
            advice_inputs: AdviceInputs,
        ) -> (Self, DefaultHost) {
            let mut host = DefaultHost::default();
            let mut process = Self::new(
                Kernel::default(),
                stack_inputs,
                advice_inputs,
                ExecutionOptions::default(),
            );
            let program = &MastForest::default();
            process.decoder.add_dummy_trace_row();
            process.execute_op(Operation::Noop, program, &mut host).unwrap();

            (process, host)
        }
    }
}
