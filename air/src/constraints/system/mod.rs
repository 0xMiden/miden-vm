//! System constraints module.
//!
//! This module contains constraints for the system component of the Miden VM,
//! which manages execution context and function hash system columns transitions.
//!
//! ## System Columns
//!
//! - `clk`: VM execution clock (clk[0] = 0, clk' = clk + 1)
//! - `ctx`: Execution context ID (determines memory context isolation)
//! - `fn_hash[0..4]`: Current function digest (identifies executing procedure)
//!
//! ## Context Transitions
//!
//! | Operation           | ctx'              | Description               |
//! |---------------------|-------------------|---------------------------|
//! | CALL or DYNCALL     | clk + 1           | Create new context        |
//! | SYSCALL             | 0                 | Return to kernel context  |
//! | END                 | (from block stack)| Restore previous context  |
//! | Other ops           | ctx               | Unchanged                 |
//!
//! ## Function Hash Transitions
//!
//! | Operation                          | fn_hash'           | Description                 |
//! |------------------------------------|--------------------|-----------------------------|
//! | CALL or DYNCALL                    | decoder_h[0..4]    | Load new procedure hash     |
//! | END                                | (from block stack) | Restore previous hash       |
//! | Other ops (incl. DYN, SYSCALL)     | fn_hash            | Unchanged                   |
//!
//! Note: END operation's restoration is handled by the block stack table (bus-based),
//! not by these constraints. These constraints only handle the non-END cases.

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::{AirBuilder, LiftedAirBuilder};

use crate::{
    MainTraceRow,
    constraints::op_flags::{ExprDecoderAccess, OpFlags},
    trace::decoder::HASHER_STATE_OFFSET,
};

// ENTRY POINTS
// ================================================================================================

/// Enforces system constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: LiftedAirBuilder,
{
    enforce_clock_constraint(builder, local, next);
    enforce_ctx_constraints(builder, local, next);
    enforce_fn_hash_constraints(builder, local, next);
}

// CONSTRAINT HELPERS
// ================================================================================================

/// Enforces the clock constraint: clk' = clk + 1.
pub(crate) fn enforce_clock_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: LiftedAirBuilder,
{
    builder.when_first_row().assert_zero(local.clk.clone());

    builder
        .when_transition()
        .assert_eq(next.clk.clone(), local.clk.clone() + AB::Expr::ONE);
}

/// Enforces execution context transition constraints.
pub(crate) fn enforce_ctx_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: LiftedAirBuilder,
{
    let ctx: AB::Expr = local.ctx.clone().into();
    let ctx_next: AB::Expr = next.ctx.clone().into();
    let clk: AB::Expr = local.clk.clone().into();

    let op_flags = OpFlags::new(ExprDecoderAccess::new(local));
    let f_call = op_flags.call();
    let f_syscall = op_flags.syscall();
    let f_dyncall = op_flags.dyncall();
    let f_end = op_flags.end();

    let call_dyncall_flag = f_call.clone() + f_dyncall.clone();
    let expected_new_ctx = clk + AB::Expr::ONE;
    builder
        .when_transition()
        .assert_zero(call_dyncall_flag * (ctx_next.clone() - expected_new_ctx));

    builder.when_transition().assert_zero(f_syscall.clone() * ctx_next.clone());

    let change_ctx_flag = f_call + f_syscall + f_dyncall + f_end;
    let default_flag = AB::Expr::ONE - change_ctx_flag;
    builder.when_transition().assert_zero(default_flag * (ctx_next - ctx));
}

/// Enforces function hash transition constraints.
pub(crate) fn enforce_fn_hash_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: LiftedAirBuilder,
{
    let op_flags = OpFlags::new(ExprDecoderAccess::new(local));
    let f_call = op_flags.call();
    let f_dyncall = op_flags.dyncall();
    let f_end = op_flags.end();

    let f_load = f_call.clone() + f_dyncall.clone();
    let f_preserve = AB::Expr::ONE - (f_load.clone() + f_end);

    builder
        .when_transition()
        .when(f_load.clone())
        .assert_zeros(core::array::from_fn::<_, 4, _>(|i| {
            let fn_hash_i_next: AB::Expr = next.fn_hash[i].clone().into();
            let decoder_h_i: AB::Expr = local.decoder[HASHER_STATE_OFFSET + i].clone().into();
            fn_hash_i_next - decoder_h_i
        }));

    builder.when_transition().when(f_preserve.clone()).assert_zeros(
        core::array::from_fn::<_, 4, _>(|i| {
            let fn_hash_i: AB::Expr = local.fn_hash[i].clone().into();
            let fn_hash_i_next: AB::Expr = next.fn_hash[i].clone().into();
            fn_hash_i_next - fn_hash_i
        }),
    );
}
