use miden_air::trace::decoder::NUM_USER_OP_HELPERS;
use miden_core::{Felt, Operation, mast::MastForest};

use crate::{
    BaseHost, ErrorContext, ExecutionError,
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
        Operation::Assert(err_code) => {
            sys_ops::op_assert(processor, *err_code, host, current_forest, err_ctx, tracer)?
        },
        Operation::FmpAdd => sys_ops::op_fmpadd(processor),
        Operation::FmpUpdate => sys_ops::op_fmpupdate(processor, tracer)?,
        Operation::SDepth => sys_ops::op_sdepth(processor, tracer)?,
        Operation::Caller => sys_ops::op_caller(processor)?,
        Operation::Clk => sys_ops::op_clk(processor, tracer)?,
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
        Operation::Add => field_ops::op_add(processor, tracer),
        Operation::Neg => field_ops::op_neg(processor),
        Operation::Mul => field_ops::op_mul(processor, tracer),
        Operation::Inv => field_ops::op_inv(processor, err_ctx)?,
        Operation::Incr => field_ops::op_incr(processor),
        Operation::And => field_ops::op_and(processor, err_ctx, tracer)?,
        Operation::Or => field_ops::op_or(processor, err_ctx, tracer)?,
        Operation::Not => field_ops::op_not(processor, err_ctx)?,
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
        Operation::Ext2Mul => field_ops::op_ext2mul(processor),

        // ----- u32 operations ---------------------------------------------------------------
        Operation::U32split => {
            let u32split_helpers = u32_ops::op_u32split(processor, tracer)?;
            user_op_helpers = Some(u32split_helpers);
        },
        Operation::U32add => {
            let u32add_helpers = u32_ops::op_u32add(processor, err_ctx, tracer)?;
            user_op_helpers = Some(u32add_helpers);
        },
        Operation::U32add3 => {
            let u32add3_helpers = u32_ops::op_u32add3(processor, err_ctx, tracer)?;
            user_op_helpers = Some(u32add3_helpers);
        },
        Operation::U32sub => {
            let u32sub_helpers = u32_ops::op_u32sub(processor, op_idx_in_block, err_ctx, tracer)?;
            user_op_helpers = Some(u32sub_helpers);
        },
        Operation::U32mul => {
            let u32mul_helpers = u32_ops::op_u32mul(processor, err_ctx, tracer)?;
            user_op_helpers = Some(u32mul_helpers);
        },
        Operation::U32madd => {
            let u32madd_helpers = u32_ops::op_u32madd(processor, err_ctx, tracer)?;
            user_op_helpers = Some(u32madd_helpers);
        },
        Operation::U32div => {
            let u32div_helpers = u32_ops::op_u32div(processor, err_ctx, tracer)?;
            user_op_helpers = Some(u32div_helpers);
        },
        Operation::U32and => u32_ops::op_u32and(processor, err_ctx, tracer)?,
        Operation::U32xor => u32_ops::op_u32xor(processor, err_ctx, tracer)?,
        Operation::U32assert2(err_code) => {
            let u32assert2_helpers = u32_ops::op_u32assert2(processor, *err_code, err_ctx, tracer)?;
            user_op_helpers = Some(u32assert2_helpers);
        },

        // ----- stack manipulation -----------------------------------------------------------
        Operation::Pad => stack_ops::op_pad(processor, tracer)?,
        Operation::Drop => processor.stack().decrement_size(tracer),
        Operation::Dup0 => stack_ops::dup_nth(processor, 0, tracer)?,
        Operation::Dup1 => stack_ops::dup_nth(processor, 1, tracer)?,
        Operation::Dup2 => stack_ops::dup_nth(processor, 2, tracer)?,
        Operation::Dup3 => stack_ops::dup_nth(processor, 3, tracer)?,
        Operation::Dup4 => stack_ops::dup_nth(processor, 4, tracer)?,
        Operation::Dup5 => stack_ops::dup_nth(processor, 5, tracer)?,
        Operation::Dup6 => stack_ops::dup_nth(processor, 6, tracer)?,
        Operation::Dup7 => stack_ops::dup_nth(processor, 7, tracer)?,
        Operation::Dup9 => stack_ops::dup_nth(processor, 9, tracer)?,
        Operation::Dup11 => stack_ops::dup_nth(processor, 11, tracer)?,
        Operation::Dup13 => stack_ops::dup_nth(processor, 13, tracer)?,
        Operation::Dup15 => stack_ops::dup_nth(processor, 15, tracer)?,
        Operation::Swap => stack_ops::op_swap(processor),
        Operation::SwapW => processor.stack().swapw_nth(1),
        Operation::SwapW2 => processor.stack().swapw_nth(2),
        Operation::SwapW3 => processor.stack().swapw_nth(3),
        Operation::SwapDW => stack_ops::op_swap_double_word(processor),
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
        Operation::CSwap => stack_ops::op_cswap(processor, err_ctx, tracer)?,
        Operation::CSwapW => stack_ops::op_cswapw(processor, err_ctx, tracer)?,

        // ----- input / output ---------------------------------------------------------------
        Operation::Push(value) => stack_ops::op_push(processor, *value, tracer)?,
        Operation::AdvPop => io_ops::op_advpop(processor, err_ctx, tracer)?,
        Operation::AdvPopW => io_ops::op_advpopw(processor, err_ctx, tracer)?,
        Operation::MLoadW => io_ops::op_mloadw(processor, err_ctx, tracer)?,
        Operation::MStoreW => io_ops::op_mstorew(processor, err_ctx, tracer)?,
        Operation::MLoad => io_ops::op_mload(processor, err_ctx, tracer)?,
        Operation::MStore => io_ops::op_mstore(processor, err_ctx, tracer)?,
        Operation::MStream => io_ops::op_mstream(processor, err_ctx, tracer)?,
        Operation::Pipe => io_ops::op_pipe(processor, err_ctx, tracer)?,
        Operation::CryptoStream => io_ops::op_crypto_stream(processor, err_ctx, tracer)?,

        // ----- cryptographic operations -----------------------------------------------------
        Operation::HPerm => {
            let hperm_helpers = crypto_ops::op_hperm(processor, tracer);
            user_op_helpers = Some(hperm_helpers);
        },
        Operation::MpVerify(err_code) => {
            let mpverify_helpers =
                crypto_ops::op_mpverify(processor, *err_code, current_forest, err_ctx, tracer)?;
            user_op_helpers = Some(mpverify_helpers);
        },
        Operation::MrUpdate => {
            let mrupdate_helpers = crypto_ops::op_mrupdate(processor, err_ctx, tracer)?;
            user_op_helpers = Some(mrupdate_helpers);
        },
        Operation::FriE2F4 => {
            let frie2f4_helpers = fri_ops::op_fri_ext2fold4(processor, tracer)?;
            user_op_helpers = Some(frie2f4_helpers);
        },
        Operation::HornerBase => {
            let horner_base_helpers = crypto_ops::op_horner_eval_base(processor, err_ctx, tracer)?;
            user_op_helpers = Some(horner_base_helpers);
        },
        Operation::HornerExt => {
            let horner_ext_helpers = crypto_ops::op_horner_eval_ext(processor, err_ctx, tracer)?;
            user_op_helpers = Some(horner_ext_helpers);
        },
        Operation::EvalCircuit => {
            processor.op_eval_circuit(err_ctx, tracer)?;
        },
    }

    Ok(user_op_helpers)
}
