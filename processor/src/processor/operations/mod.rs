use miden_air::trace::decoder::NUM_USER_OP_HELPERS;
use miden_core::{Felt, Operation, mast::MastForest};

use crate::{
    BaseHost, ErrorContext, ExecutionError, OperationError,
    fast::Tracer,
    processor::{Processor, StackInterface},
};

mod crypto_ops;
mod field_ops;
mod fri_ops;
mod io_ops;
mod stack_ops;
mod sys_ops;
mod u32_ops;

/// Executes the provided synchronous operation.
///
/// This excludes `Emit`, which must be executed asynchronously, as well as control flow
/// operations, which are never executed directly.
///
/// # Panics
/// - If a control flow operation is provided.
/// - If an `Emit` operation is provided.
pub(super) fn execute_sync_op(
    processor: &mut impl Processor,
    op: &Operation,
    op_idx_in_block: usize,
    current_forest: &MastForest,
    host: &mut impl BaseHost,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<Option<[Felt; NUM_USER_OP_HELPERS]>, ExecutionError> {
    let mut user_op_helpers = None;

    match op {
        // ----- system operations ------------------------------------------------------------
        Operation::Noop => {
            // do nothing
        },
        Operation::Assert(err_code) => wrap_operation(
            sys_ops::op_assert(processor, *err_code, host, current_forest, tracer),
            err_ctx,
        )?,
        Operation::SDepth => wrap_operation(sys_ops::op_sdepth(processor, tracer), err_ctx)?,
        Operation::Caller => wrap_operation(sys_ops::op_caller(processor), err_ctx)?,
        Operation::Clk => wrap_operation(sys_ops::op_clk(processor, tracer), err_ctx)?,
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
        Operation::Add => wrap_operation(field_ops::op_add(processor, tracer), err_ctx)?,
        Operation::Neg => wrap_operation(field_ops::op_neg(processor), err_ctx)?,
        Operation::Mul => wrap_operation(field_ops::op_mul(processor, tracer), err_ctx)?,
        Operation::Inv => wrap_operation(field_ops::op_inv(processor), err_ctx)?,
        Operation::Incr => wrap_operation(field_ops::op_incr(processor), err_ctx)?,
        Operation::And => wrap_operation(field_ops::op_and(processor, tracer), err_ctx)?,
        Operation::Or => wrap_operation(field_ops::op_or(processor, tracer), err_ctx)?,
        Operation::Not => wrap_operation(field_ops::op_not(processor), err_ctx)?,
        Operation::Eq => {
            let eq_helpers = field_ops::op_eq(processor, tracer);
            user_op_helpers = Some(eq_helpers);
        },
        Operation::Eqz => {
            let eqz_helpers = field_ops::op_eqz(processor);
            user_op_helpers = Some(eqz_helpers);
        },
        Operation::Expacc => {
            let expacc_helpers = field_ops::op_expacc(processor);
            user_op_helpers = Some(expacc_helpers);
        },

        // ----- ext2 operations --------------------------------------------------------------
        Operation::Ext2Mul => wrap_operation(field_ops::op_ext2mul(processor), err_ctx)?,

        // ----- u32 operations ---------------------------------------------------------------
        Operation::U32split => {
            let u32split_helpers =
                wrap_operation(u32_ops::op_u32split(processor, tracer), err_ctx)?;
            user_op_helpers = Some(u32split_helpers);
        },
        Operation::U32add => {
            let u32add_helpers = wrap_operation(u32_ops::op_u32add(processor, tracer), err_ctx)?;
            user_op_helpers = Some(u32add_helpers);
        },
        Operation::U32add3 => {
            let u32add3_helpers = wrap_operation(u32_ops::op_u32add3(processor, tracer), err_ctx)?;
            user_op_helpers = Some(u32add3_helpers);
        },
        Operation::U32sub => {
            let u32sub_helpers =
                wrap_operation(u32_ops::op_u32sub(processor, op_idx_in_block, tracer), err_ctx)?;
            user_op_helpers = Some(u32sub_helpers);
        },
        Operation::U32mul => {
            let u32mul_helpers = wrap_operation(u32_ops::op_u32mul(processor, tracer), err_ctx)?;
            user_op_helpers = Some(u32mul_helpers);
        },
        Operation::U32madd => {
            let u32madd_helpers = wrap_operation(u32_ops::op_u32madd(processor, tracer), err_ctx)?;
            user_op_helpers = Some(u32madd_helpers);
        },
        Operation::U32div => {
            let u32div_helpers = wrap_operation(u32_ops::op_u32div(processor, tracer), err_ctx)?;
            user_op_helpers = Some(u32div_helpers);
        },
        Operation::U32and => wrap_operation(u32_ops::op_u32and(processor, tracer), err_ctx)?,
        Operation::U32xor => wrap_operation(u32_ops::op_u32xor(processor, tracer), err_ctx)?,
        Operation::U32assert2(err_code) => {
            let u32assert2_helpers =
                wrap_operation(u32_ops::op_u32assert2(processor, *err_code, tracer), err_ctx)?;
            user_op_helpers = Some(u32assert2_helpers);
        },

        // ----- stack manipulation -----------------------------------------------------------
        Operation::Pad => wrap_operation(stack_ops::op_pad(processor, tracer), err_ctx)?,
        Operation::Drop => processor.stack().decrement_size(tracer),
        Operation::Dup0 => wrap_operation(stack_ops::dup_nth(processor, 0, tracer), err_ctx)?,
        Operation::Dup1 => wrap_operation(stack_ops::dup_nth(processor, 1, tracer), err_ctx)?,
        Operation::Dup2 => wrap_operation(stack_ops::dup_nth(processor, 2, tracer), err_ctx)?,
        Operation::Dup3 => wrap_operation(stack_ops::dup_nth(processor, 3, tracer), err_ctx)?,
        Operation::Dup4 => wrap_operation(stack_ops::dup_nth(processor, 4, tracer), err_ctx)?,
        Operation::Dup5 => wrap_operation(stack_ops::dup_nth(processor, 5, tracer), err_ctx)?,
        Operation::Dup6 => wrap_operation(stack_ops::dup_nth(processor, 6, tracer), err_ctx)?,
        Operation::Dup7 => wrap_operation(stack_ops::dup_nth(processor, 7, tracer), err_ctx)?,
        Operation::Dup9 => wrap_operation(stack_ops::dup_nth(processor, 9, tracer), err_ctx)?,
        Operation::Dup11 => wrap_operation(stack_ops::dup_nth(processor, 11, tracer), err_ctx)?,
        Operation::Dup13 => wrap_operation(stack_ops::dup_nth(processor, 13, tracer), err_ctx)?,
        Operation::Dup15 => wrap_operation(stack_ops::dup_nth(processor, 15, tracer), err_ctx)?,
        Operation::Swap => wrap_operation(stack_ops::op_swap(processor), err_ctx)?,
        Operation::SwapW => processor.stack().swapw_nth(1),
        Operation::SwapW2 => processor.stack().swapw_nth(2),
        Operation::SwapW3 => processor.stack().swapw_nth(3),
        Operation::SwapDW => wrap_operation(stack_ops::op_swap_double_word(processor), err_ctx)?,
        Operation::MovUp2 => processor.stack().rotate_left(3),
        Operation::MovUp3 => processor.stack().rotate_left(4),
        Operation::MovUp4 => processor.stack().rotate_left(5),
        Operation::MovUp5 => processor.stack().rotate_left(6),
        Operation::MovUp6 => processor.stack().rotate_left(7),
        Operation::MovUp7 => processor.stack().rotate_left(8),
        Operation::MovUp8 => processor.stack().rotate_left(9),
        Operation::MovDn2 => processor.stack().rotate_right(3),
        Operation::MovDn3 => processor.stack().rotate_right(4),
        Operation::MovDn4 => processor.stack().rotate_right(5),
        Operation::MovDn5 => processor.stack().rotate_right(6),
        Operation::MovDn6 => processor.stack().rotate_right(7),
        Operation::MovDn7 => processor.stack().rotate_right(8),
        Operation::MovDn8 => processor.stack().rotate_right(9),
        Operation::CSwap => wrap_operation(stack_ops::op_cswap(processor, tracer), err_ctx)?,
        Operation::CSwapW => wrap_operation(stack_ops::op_cswapw(processor, tracer), err_ctx)?,

        // ----- input / output ---------------------------------------------------------------
        Operation::Push(value) => {
            wrap_operation(stack_ops::op_push(processor, *value, tracer), err_ctx)?
        },
        Operation::AdvPop => wrap_operation(io_ops::op_advpop(processor, tracer), err_ctx)?,
        Operation::AdvPopW => wrap_operation(io_ops::op_advpopw(processor, tracer), err_ctx)?,
        Operation::MLoadW => wrap_operation(io_ops::op_mloadw(processor, tracer), err_ctx)?,
        Operation::MStoreW => wrap_operation(io_ops::op_mstorew(processor, tracer), err_ctx)?,
        Operation::MLoad => wrap_operation(io_ops::op_mload(processor, tracer), err_ctx)?,
        Operation::MStore => wrap_operation(io_ops::op_mstore(processor, tracer), err_ctx)?,
        Operation::MStream => wrap_operation(io_ops::op_mstream(processor, tracer), err_ctx)?,
        Operation::Pipe => wrap_operation(io_ops::op_pipe(processor, tracer), err_ctx)?,

        // ----- cryptographic operations -----------------------------------------------------
        Operation::HPerm => {
            let hperm_helpers = crypto_ops::op_hperm(processor, tracer);
            user_op_helpers = Some(hperm_helpers);
        },
        Operation::MpVerify(err_code) => {
            let mpverify_helpers = wrap_operation(
                crypto_ops::op_mpverify(processor, *err_code, current_forest, tracer),
                err_ctx,
            )?;
            user_op_helpers = Some(mpverify_helpers);
        },
        Operation::MrUpdate => {
            let mrupdate_helpers =
                wrap_operation(crypto_ops::op_mrupdate(processor, tracer), err_ctx)?;
            user_op_helpers = Some(mrupdate_helpers);
        },
        Operation::FriE2F4 => {
            let frie2f4_helpers =
                wrap_operation(fri_ops::op_fri_ext2fold4(processor, tracer), err_ctx)?;
            user_op_helpers = Some(frie2f4_helpers);
        },
        Operation::HornerBase => {
            let horner_base_helpers =
                wrap_operation(crypto_ops::op_horner_eval_base(processor, tracer), err_ctx)?;
            user_op_helpers = Some(horner_base_helpers);
        },
        Operation::HornerExt => {
            let horner_ext_helpers =
                wrap_operation(crypto_ops::op_horner_eval_ext(processor, tracer), err_ctx)?;
            user_op_helpers = Some(horner_ext_helpers);
        },
        Operation::EvalCircuit => {
            processor.op_eval_circuit(err_ctx, tracer)?;
        },
        Operation::LogPrecompile => {
            let log_precompile_helpers = crypto_ops::op_log_precompile(processor, tracer);
            user_op_helpers = Some(log_precompile_helpers);
        },
    }

    Ok(user_op_helpers)
}

fn wrap_operation<T>(
    result: Result<T, OperationError>,
    err_ctx: &impl ErrorContext,
) -> Result<T, ExecutionError> {
    result.map_err(|err| ExecutionError::from_operation(err_ctx, err))
}
