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
use miden_crypto::stark::air::MidenAirBuilder;

use crate::{
    MainTraceRow,
    constraints::{
        op_flags::{ExprDecoderAccess, OpFlags},
        tagging::TaggingAirBuilderExt,
    },
    trace::decoder::HASHER_STATE_OFFSET,
};

// TAGGING CONSTANTS
// ================================================================================================

const SYSTEM_CLK_BASE_ID: usize = 0;
const SYSTEM_CLK_NAMES: [&str; 2] = ["system.clk.first_row", "system.clk.transition"];

const SYSTEM_CTX_BASE_ID: usize = 2;
const SYSTEM_CTX_NAMES: [&str; 3] =
    ["system.ctx.call_dyncall", "system.ctx.syscall", "system.ctx.default"];

const SYSTEM_FN_HASH_BASE_ID: usize = SYSTEM_CTX_BASE_ID + 3;
const SYSTEM_FN_HASH_LOAD_NAMESPACE: &str = "system.fn_hash.load";
const SYSTEM_FN_HASH_PRESERVE_NAMESPACE: &str = "system.fn_hash.preserve";

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
    builder.tagged(SYSTEM_CLK_BASE_ID, SYSTEM_CLK_NAMES[0], |builder| {
        builder.when_first_row().assert_zero(local.clk.clone());
    });

    builder.tagged(SYSTEM_CLK_BASE_ID + 1, SYSTEM_CLK_NAMES[1], |builder| {
        builder
            .when_transition()
            .assert_eq(next.clk.clone(), local.clk.clone() + AB::Expr::ONE);
    });
}

/// Enforces execution context transition constraints.
pub(crate) fn enforce_ctx_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
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
    builder.tagged(SYSTEM_CTX_BASE_ID, SYSTEM_CTX_NAMES[0], |builder| {
        builder
            .when_transition()
            .assert_zero(call_dyncall_flag * (ctx_next.clone() - expected_new_ctx));
    });

    builder.tagged(SYSTEM_CTX_BASE_ID + 1, SYSTEM_CTX_NAMES[1], |builder| {
        builder.when_transition().assert_zero(f_syscall.clone() * ctx_next.clone());
    });

    let change_ctx_flag = f_call + f_syscall + f_dyncall + f_end;
    let default_flag = AB::Expr::ONE - change_ctx_flag;
    builder.tagged(SYSTEM_CTX_BASE_ID + 2, SYSTEM_CTX_NAMES[2], |builder| {
        builder.when_transition().assert_zero(default_flag * (ctx_next - ctx));
    });
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
    let f_preserve = AB::Expr::ONE - (f_load.clone() + f_end);

    let load_ids: [usize; 4] = core::array::from_fn(|i| SYSTEM_FN_HASH_BASE_ID + i);
    builder.tagged_list(load_ids, SYSTEM_FN_HASH_LOAD_NAMESPACE, |builder| {
        builder.when_transition().when(f_load.clone()).assert_zeros(
            core::array::from_fn::<_, 4, _>(|i| {
                let fn_hash_i_next: AB::Expr = next.fn_hash[i].clone().into();
                let decoder_h_i: AB::Expr = local.decoder[HASHER_STATE_OFFSET + i].clone().into();
                fn_hash_i_next - decoder_h_i
            }),
        );
    });

    let preserve_ids: [usize; 4] = core::array::from_fn(|i| SYSTEM_FN_HASH_BASE_ID + 4 + i);
    builder.tagged_list(preserve_ids, SYSTEM_FN_HASH_PRESERVE_NAMESPACE, |builder| {
        builder
            .when_transition()
            .when(f_preserve.clone())
            .assert_zeros(core::array::from_fn::<_, 4, _>(|i| {
                let fn_hash_i: AB::Expr = local.fn_hash[i].clone().into();
                let fn_hash_i_next: AB::Expr = next.fn_hash[i].clone().into();
                fn_hash_i_next - fn_hash_i
            }));
    });
}
