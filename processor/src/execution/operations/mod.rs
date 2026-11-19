use crate::{
    Felt, ProcessorError,
    operation::Operation,
    processor::{Processor, StackInterface},
    tracer::{OperationHelperRegisters, Tracer},
};

mod crypto_ops;
mod eval_circuit;
mod field_ops;
mod fri_ops;
mod io_ops;
mod precompile_ops;
mod stack_ops;
mod sys_ops;
mod u32_ops;

#[cfg(test)]
pub(crate) use eval_circuit::eval_circuit_impl;

// CONSTANTS
// ================================================================================================

/// WORD_SIZE, but as a `Felt`.
const WORD_SIZE_FELT: Felt = Felt::new_unchecked(4);
/// The size of a double-word.
const DOUBLE_WORD_SIZE: Felt = Felt::new_unchecked(8);

// OPERATION HANDLER
// ================================================================================================

/// Executes the provided synchronous operation.
///
/// This excludes `Emit`, which must be executed asynchronously, as well as control flow
/// operations, which are never executed directly.
///
/// # Panics
/// - If a control flow operation is provided.
/// - If an `Emit` operation is provided.
#[inline(always)]
pub(crate) fn execute_op<P, T>(
    processor: &mut P,
    op: &Operation,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, ProcessorError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    let user_op_helpers = match op {
        // ----- system operations ------------------------------------------------------------
        Operation::Noop => OperationHelperRegisters::Empty,
        Operation::Assert(err_code) => sys_ops::op_assert(processor, *err_code)?,
        Operation::SDepth => sys_ops::op_sdepth(processor)?,
        Operation::Caller => sys_ops::op_caller(processor),
        Operation::Clk => sys_ops::op_clk(processor)?,
        Operation::Emit => {
            panic!("emit instruction requires async, so is not supported by execute_op()")
        },

        // ----- field operations -------------------------------------------------------------
        Operation::Add => field_ops::op_add(processor)?,
        Operation::Neg => field_ops::op_neg(processor),
        Operation::Mul => field_ops::op_mul(processor)?,
        Operation::Inv => field_ops::op_inv(processor)?,
        Operation::Incr => field_ops::op_incr(processor),
        Operation::And => field_ops::op_and(processor)?,
        Operation::Or => field_ops::op_or(processor)?,
        Operation::Not => field_ops::op_not(processor)?,
        Operation::Eq => field_ops::op_eq(processor)?,
        Operation::Eqz => field_ops::op_eqz(processor),
        Operation::Expacc => field_ops::op_expacc(processor),

        // ----- ext2 operations --------------------------------------------------------------
        Operation::Ext2Mul => field_ops::op_ext2mul(processor),

        // ----- u32 operations ---------------------------------------------------------------
        Operation::U32split => u32_ops::op_u32split(processor, tracer)?,
        Operation::U32add => u32_ops::op_u32add(processor, tracer)?,
        Operation::U32add3 => u32_ops::op_u32add3(processor, tracer)?,
        Operation::U32sub => u32_ops::op_u32sub(processor, tracer)?,
        Operation::U32mul => u32_ops::op_u32mul(processor, tracer)?,
        Operation::U32madd => u32_ops::op_u32madd(processor, tracer)?,
        Operation::U32div => u32_ops::op_u32div(processor, tracer)?,
        Operation::U32and => u32_ops::op_u32and(processor, tracer)?,
        Operation::U32xor => u32_ops::op_u32xor(processor, tracer)?,
        Operation::U32assert2(err_code) => u32_ops::op_u32assert2(processor, *err_code, tracer)?,

        // ----- stack manipulation -----------------------------------------------------------
        Operation::Pad => stack_ops::op_pad(processor)?,
        Operation::Drop => {
            processor.stack_mut().decrement_size()?;
            OperationHelperRegisters::Empty
        },
        Operation::Dup0 => stack_ops::dup_nth(processor, 0)?,
        Operation::Dup1 => stack_ops::dup_nth(processor, 1)?,
        Operation::Dup2 => stack_ops::dup_nth(processor, 2)?,
        Operation::Dup3 => stack_ops::dup_nth(processor, 3)?,
        Operation::Dup4 => stack_ops::dup_nth(processor, 4)?,
        Operation::Dup5 => stack_ops::dup_nth(processor, 5)?,
        Operation::Dup6 => stack_ops::dup_nth(processor, 6)?,
        Operation::Dup7 => stack_ops::dup_nth(processor, 7)?,
        Operation::Dup9 => stack_ops::dup_nth(processor, 9)?,
        Operation::Dup11 => stack_ops::dup_nth(processor, 11)?,
        Operation::Dup13 => stack_ops::dup_nth(processor, 13)?,
        Operation::Dup15 => stack_ops::dup_nth(processor, 15)?,
        Operation::Swap => stack_ops::op_swap(processor),
        Operation::SwapW => {
            processor.stack_mut().swapw_nth(1);
            OperationHelperRegisters::Empty
        },
        Operation::SwapW2 => {
            processor.stack_mut().swapw_nth(2);
            OperationHelperRegisters::Empty
        },
        Operation::SwapW3 => {
            processor.stack_mut().swapw_nth(3);
            OperationHelperRegisters::Empty
        },
        Operation::SwapDW => stack_ops::op_swap_double_word(processor),
        Operation::MovUp2 => {
            processor.stack_mut().rotate_left(3);
            OperationHelperRegisters::Empty
        },
        Operation::MovUp3 => {
            processor.stack_mut().rotate_left(4);
            OperationHelperRegisters::Empty
        },
        Operation::MovUp4 => {
            processor.stack_mut().rotate_left(5);
            OperationHelperRegisters::Empty
        },
        Operation::MovUp5 => {
            processor.stack_mut().rotate_left(6);
            OperationHelperRegisters::Empty
        },
        Operation::MovUp6 => {
            processor.stack_mut().rotate_left(7);
            OperationHelperRegisters::Empty
        },
        Operation::MovUp7 => {
            processor.stack_mut().rotate_left(8);
            OperationHelperRegisters::Empty
        },
        Operation::MovUp8 => {
            processor.stack_mut().rotate_left(9);
            OperationHelperRegisters::Empty
        },
        Operation::MovDn2 => {
            processor.stack_mut().rotate_right(3);
            OperationHelperRegisters::Empty
        },
        Operation::MovDn3 => {
            processor.stack_mut().rotate_right(4);
            OperationHelperRegisters::Empty
        },
        Operation::MovDn4 => {
            processor.stack_mut().rotate_right(5);
            OperationHelperRegisters::Empty
        },
        Operation::MovDn5 => {
            processor.stack_mut().rotate_right(6);
            OperationHelperRegisters::Empty
        },
        Operation::MovDn6 => {
            processor.stack_mut().rotate_right(7);
            OperationHelperRegisters::Empty
        },
        Operation::MovDn7 => {
            processor.stack_mut().rotate_right(8);
            OperationHelperRegisters::Empty
        },
        Operation::MovDn8 => {
            processor.stack_mut().rotate_right(9);
            OperationHelperRegisters::Empty
        },
        Operation::CSwap => stack_ops::op_cswap(processor)?,
        Operation::CSwapW => stack_ops::op_cswapw(processor)?,

        // ----- input / output ---------------------------------------------------------------
        Operation::Push(value) => stack_ops::op_push(processor, *value)?,
        Operation::AdvPop => io_ops::op_advpop(processor, tracer)?,
        Operation::AdvPopW => io_ops::op_advpopw(processor, tracer)?,
        Operation::MLoadW => io_ops::op_mloadw(processor, tracer)?,
        Operation::MStoreW => io_ops::op_mstorew(processor, tracer)?,
        Operation::MLoad => io_ops::op_mload(processor, tracer)?,
        Operation::MStore => io_ops::op_mstore(processor, tracer)?,
        Operation::MStream => io_ops::op_mstream(processor, tracer)?,
        Operation::Pipe => io_ops::op_pipe(processor, tracer)?,

        // ----- cryptographic operations -----------------------------------------------------
        Operation::Compress => crypto_ops::op_compress(processor, tracer)?,
        Operation::MpVerify(err_code) => crypto_ops::op_mpverify(processor, *err_code, tracer)?,
        Operation::MrUpdate => crypto_ops::op_mrupdate(processor, tracer)?,
        Operation::FriE2F4 => fri_ops::op_fri_ext2fold4(processor)?,
        Operation::HornerBase => crypto_ops::op_horner_eval_base(processor, tracer)?,
        Operation::HornerExt => crypto_ops::op_horner_eval_ext(processor, tracer)?,
        Operation::EvalCircuit => {
            eval_circuit::op_eval_circuit(processor, tracer)?;
            OperationHelperRegisters::Empty
        },
        Operation::CryptoStream => crypto_ops::op_aead_stream(processor, tracer)?,

        // ----- precompile accumulator operations --------------------------------------------
        Operation::LogDeferred => precompile_ops::op_log_deferred(processor, tracer)?,
        Operation::ClearDeferred => precompile_ops::op_clear_deferred(processor)?,
    };

    Ok(user_op_helpers)
}
