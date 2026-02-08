use crate::{
    ExecutionError, Felt, Host,
    errors::MapExecErrWithOpIdx,
    mast::{MastForest, MastNodeId},
    operation::Operation,
    processor::{Processor, StackInterface},
    tracer::{OperationHelperRegisters, Tracer},
};

mod crypto_ops;
mod field_ops;
mod fri_ops;
mod io_ops;
mod stack_ops;
mod sys_ops;
mod u32_ops;

// CONSTANTS
// ================================================================================================

/// WORD_SIZE, but as a `Felt`.
const WORD_SIZE_FELT: Felt = Felt::new(4);
/// The size of a double-word.
const DOUBLE_WORD_SIZE: Felt = Felt::new(8);

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
    op_idx: usize,
    current_forest: &MastForest,
    node_id: MastNodeId,
    host: &mut impl Host,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, ExecutionError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    let user_op_helpers = match op {
        // ----- system operations ------------------------------------------------------------
        Operation::Noop => OperationHelperRegisters::Empty,
        Operation::Assert(err_code) => {
            sys_ops::op_assert(processor, *err_code, current_forest, tracer)
                .map_exec_err_with_op_idx(current_forest, node_id, host, op_idx)?
        },
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
        Operation::Inv => field_ops::op_inv(processor).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::Incr => field_ops::op_incr(processor),
        Operation::And => field_ops::op_and(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::Or => field_ops::op_or(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::Not => field_ops::op_not(processor).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::Eq => field_ops::op_eq(processor, tracer),
        Operation::Eqz => field_ops::op_eqz(processor),
        Operation::Expacc => field_ops::op_expacc(processor),

        // ----- ext2 operations --------------------------------------------------------------
        Operation::Ext2Mul => field_ops::op_ext2mul(processor),

        // ----- u32 operations ---------------------------------------------------------------
        Operation::U32split => u32_ops::op_u32split(processor, tracer)?,
        Operation::U32add => u32_ops::op_u32add(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::U32add3 => u32_ops::op_u32add3(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::U32sub => u32_ops::op_u32sub(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::U32mul => u32_ops::op_u32mul(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::U32madd => u32_ops::op_u32madd(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::U32div => u32_ops::op_u32div(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::U32and => u32_ops::op_u32and(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::U32xor => u32_ops::op_u32xor(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::U32assert2(err_code) => u32_ops::op_u32assert2(processor, *err_code, tracer)
            .map_exec_err_with_op_idx(current_forest, node_id, host, op_idx)?,

        // ----- stack manipulation -----------------------------------------------------------
        Operation::Pad => stack_ops::op_pad(processor, tracer)?,
        Operation::Drop => {
            processor.stack_mut().decrement_size(tracer);
            OperationHelperRegisters::Empty
        },
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
        Operation::CSwap => stack_ops::op_cswap(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::CSwapW => stack_ops::op_cswapw(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,

        // ----- input / output ---------------------------------------------------------------
        Operation::Push(value) => stack_ops::op_push(processor, *value, tracer)?,
        Operation::AdvPop => io_ops::op_advpop(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::AdvPopW => io_ops::op_advpopw(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::MLoadW => io_ops::op_mloadw(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::MStoreW => io_ops::op_mstorew(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::MLoad => io_ops::op_mload(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::MStore => io_ops::op_mstore(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::MStream => io_ops::op_mstream(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,
        Operation::Pipe => io_ops::op_pipe(processor, tracer).map_exec_err_with_op_idx(
            current_forest,
            node_id,
            host,
            op_idx,
        )?,

        // ----- cryptographic operations -----------------------------------------------------
        Operation::HPerm => crypto_ops::op_hperm(processor, tracer),
        Operation::MpVerify(err_code) => {
            crypto_ops::op_mpverify(processor, *err_code, current_forest, tracer)
                .map_exec_err_with_op_idx(current_forest, node_id, host, op_idx)?
        },
        Operation::MrUpdate => crypto_ops::op_mrupdate(processor, tracer)
            .map_exec_err_with_op_idx(current_forest, node_id, host, op_idx)?,
        Operation::FriE2F4 => fri_ops::op_fri_ext2fold4(processor, tracer)
            .map_exec_err_with_op_idx(current_forest, node_id, host, op_idx)?,
        Operation::HornerBase => crypto_ops::op_horner_eval_base(processor, tracer)
            .map_exec_err_with_op_idx(current_forest, node_id, host, op_idx)?,
        Operation::HornerExt => crypto_ops::op_horner_eval_ext(processor, tracer)
            .map_exec_err_with_op_idx(current_forest, node_id, host, op_idx)?,
        Operation::EvalCircuit => {
            processor.op_eval_circuit(tracer).map_exec_err_with_op_idx(
                current_forest,
                node_id,
                host,
                op_idx,
            )?;
            OperationHelperRegisters::Empty
        },
        Operation::LogPrecompile => crypto_ops::op_log_precompile(processor, tracer),
        Operation::CryptoStream => crypto_ops::op_crypto_stream(processor, tracer)
            .map_exec_err_with_op_idx(current_forest, node_id, host, op_idx)?,
    };

    Ok(user_op_helpers)
}
