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

use miden_crypto::stark::air::AirBuilder;

use crate::{
    MainTraceRow, MidenAirBuilder,
    constraints::{
        constants::F_1,
        op_flags::{ExprDecoderAccess, OpFlags},
        utils::BoolNot,
    },
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
    AB: MidenAirBuilder,
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
    AB: MidenAirBuilder,
{
    builder.when_first_row().assert_zero(local.clk);

    builder.when_transition().assert_eq(next.clk, local.clk + F_1);
}

/// Enforces execution context transition constraints.
pub(crate) fn enforce_ctx_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    let ctx = local.ctx;
    let ctx_next = next.ctx;
    let clk = local.clk;

    let op_flags = OpFlags::new(ExprDecoderAccess::new(local));
    let f_call = op_flags.call();
    let f_syscall = op_flags.syscall();
    let f_dyncall = op_flags.dyncall();
    let f_end = op_flags.end();

    let call_dyncall_flag = f_call.clone() + f_dyncall.clone();
    let change_ctx_flag = f_call + f_syscall.clone() + f_dyncall + f_end;
    let default_flag = change_ctx_flag.not();

    {
        let builder = &mut builder.when_transition();
        builder.when(call_dyncall_flag).assert_eq(ctx_next, clk + F_1);
        builder.when(f_syscall).assert_zero(ctx_next);
        builder.when(default_flag).assert_eq(ctx_next, ctx);
    }
}

/// Enforces function hash transition constraints.
pub(crate) fn enforce_fn_hash_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    let op_flags = OpFlags::new(ExprDecoderAccess::new(local));
    let f_call = op_flags.call();
    let f_dyncall = op_flags.dyncall();
    let f_end = op_flags.end();

    let f_load = f_call.clone() + f_dyncall.clone();
    let f_preserve = (f_load.clone() + f_end).not();

    {
        let builder = &mut builder.when_transition();

        {
            let builder = &mut builder.when(f_load);
            for i in 0..4 {
                builder.assert_eq(next.fn_hash[i], local.decoder[HASHER_STATE_OFFSET + i]);
            }
        }

        {
            let builder = &mut builder.when(f_preserve);
            for i in 0..4 {
                builder.assert_eq(next.fn_hash[i], local.fn_hash[i]);
            }
        }
    }
}
