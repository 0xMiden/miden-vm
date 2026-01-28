//! System constraints module.
//!
//! This module contains constraints for the system component of the Miden VM,
//! which manages execution context and function hash transitions.
//!
//! ## System Columns
//!
//! - `clk`: VM execution clock (clk[0] = 0, clk' = clk + 1)
//! - `ctx`: Execution context ID (determines memory isolation)
//! - `fn_hash[0..4]`: Current function digest (identifies executing procedure)
//!
//! ## Context Transitions
//!
//! | Operation | ctx' | Description |
//! |-----------|------|-------------|
//! | CALL/DYNCALL | clk + 1 | Create new context |
//! | SYSCALL | 0 | Return to kernel context |
//! | END | (from block stack) | Restore previous context |
//! | Others | ctx | Unchanged |
//!
//! ## Function Hash Transitions
//!
//! | Operation | fn_hash' | Description |
//! |-----------|----------|-------------|
//! | CALL/DYNCALL | decoder_h[0..4] | Load new procedure hash |
//! | END | (from block stack) | Restore previous hash |
//! | Others | fn_hash | Unchanged (including DYN, SYSCALL) |
//!
//! Note: END operation's restoration is handled by the block stack table (bus-based),
//! not by these constraints. These constraints only handle the non-END cases.

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use super::stack::op_flags::OpFlags;
use crate::{MainTraceRow, trace::decoder::HASHER_STATE_OFFSET};

#[cfg(test)]
pub mod tests;

// CONSTANTS
// ================================================================================================

/// Number of system constraints.
/// - 3 ctx transition constraints (CALL/DYNCALL, SYSCALL, default)
/// - 8 fn_hash transition constraints (4 for CALL/DYNCALL load, 4 for default preserve)
#[allow(dead_code)]
pub const NUM_CONSTRAINTS: usize = 11;

/// The degrees of the system constraints.
#[allow(dead_code)]
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    // ctx transitions
    6, // ctx' = clk + 1 when CALL + DYNCALL (degree 5 flags + degree 1)
    5, // ctx' = 0 when SYSCALL (degree 4 flag + degree 1)
    6, // ctx' = ctx when default (degree 5 composite + degree 1)
    // fn_hash transitions for CALL/DYNCALL
    6, 6, 6, 6, // fn_hash[i]' = decoder_h[i] (degree 5 flags + degree 1)
    // fn_hash default (preserve)
    6, 6, 6, 6, // fn_hash[i]' = fn_hash[i] (degree 5 composite + degree 1)
];

// ENTRY POINTS
// ================================================================================================

/// Enforces system main-trace constraints (entry point).
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    enforce_clock_constraint(builder, local, next);
    enforce_ctx_constraints(builder, local, next, op_flags);
    enforce_fn_hash_constraints(builder, local, next, op_flags);
}

// CONSTRAINT HELPERS
// ================================================================================================

/// Enforces the clock constraint: clk' = clk + 1
///
/// The clock must increment by 1 at each step, ensuring proper sequencing of operations.
fn enforce_clock_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // Clock boundary constraint: clk[0] = 0
    builder.when_first_row().assert_zero(local.clk.clone());

    // Clock transition constraint: clk' = clk + 1
    let one_expr: AB::Expr = AB::F::ONE.into();
    builder
        .when_transition()
        .assert_eq(next.clk.clone(), local.clk.clone() + one_expr);
}

/// Enforces execution context transition constraints.
///
/// The execution context determines memory isolation boundaries:
/// - ctx = 0: Kernel/root context
/// - ctx > 0: User contexts (one per CALL/DYNCALL)
///
/// Transitions:
/// - CALL/DYNCALL: ctx' = clk + 1 (create new context)
/// - SYSCALL: ctx' = 0 (return to kernel)
/// - END: handled by block stack table (not constrained here)
/// - Others: ctx' = ctx (unchanged)
fn enforce_ctx_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let ctx: AB::Expr = local.ctx.clone().into();
    let ctx_next: AB::Expr = next.ctx.clone().into();
    let clk: AB::Expr = local.clk.clone().into();

    let f_call = op_flags.call();
    let f_syscall = op_flags.syscall();
    let f_dyncall = op_flags.dyncall();
    let f_end = op_flags.end();

    // Constraint 1: CALL/DYNCALL creates new context (ctx' = clk + 1)
    let call_dyncall_flag = f_call.clone() + f_dyncall.clone();
    let expected_new_ctx = clk + AB::Expr::ONE;
    builder
        .when_transition()
        .assert_zero(call_dyncall_flag * (ctx_next.clone() - expected_new_ctx));

    // Constraint 2: SYSCALL returns to kernel context (ctx' = 0)
    builder.when_transition().assert_zero(f_syscall.clone() * ctx_next.clone());

    // Constraint 3: Default - context unchanged
    // Applies when not CALL, SYSCALL, DYNCALL, or END
    // Note: END is excluded because it restores ctx from block stack (bus-based)
    let change_ctx_flag = f_call + f_syscall + f_dyncall + f_end;
    let default_flag = AB::Expr::ONE - change_ctx_flag;
    builder.when_transition().assert_zero(default_flag * (ctx_next - ctx));
}

/// Enforces function hash transition constraints.
///
/// The function hash identifies the currently executing procedure and is used for authorization
/// via the `caller` instruction.
///
/// Transitions:
/// - CALL/DYNCALL: fn_hash' = decoder_h[0..4] (load new procedure hash)
/// - END: handled by block stack table (not constrained here)
/// - Others: fn_hash' = fn_hash (unchanged, including DYN, SYSCALL)
fn enforce_fn_hash_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let is_transition = builder.is_transition();

    let f_call = op_flags.call();
    let f_dyncall = op_flags.dyncall();
    let f_end = op_flags.end();

    // Flag for loading new fn_hash (CALL or DYNCALL)
    let load_flag = f_call.clone() + f_dyncall.clone();

    // Flag for preserving fn_hash (everything except CALL, DYNCALL, END)
    // END restores from block stack table, so it's excluded from default
    let preserve_flag = AB::Expr::ONE - (f_call + f_dyncall + f_end);

    // Decoder hasher columns h0-h3 contain the target procedure hash:
    // `decoder[HASHER_STATE_OFFSET + i] = h[i]`.
    //
    // Use combined gates to share `is_transition * load_flag` and `is_transition * preserve_flag`
    // across the 4 lane constraints.
    let load_gate = is_transition.clone() * load_flag;
    builder.when(load_gate).assert_zeros(core::array::from_fn::<_, 4, _>(|i| {
        let fn_hash_i_next: AB::Expr = next.fn_hash[i].clone().into();
        let decoder_h_i: AB::Expr = local.decoder[HASHER_STATE_OFFSET + i].clone().into();
        fn_hash_i_next - decoder_h_i
    }));

    let preserve_gate = is_transition * preserve_flag;
    builder.when(preserve_gate).assert_zeros(core::array::from_fn::<_, 4, _>(|i| {
        let fn_hash_i: AB::Expr = local.fn_hash[i].clone().into();
        let fn_hash_i_next: AB::Expr = next.fn_hash[i].clone().into();
        fn_hash_i_next - fn_hash_i
    }));
}
