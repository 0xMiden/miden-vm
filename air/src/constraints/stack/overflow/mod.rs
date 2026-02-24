//! Stack overflow constraints.
//!
//! This module contains constraints for the stack overflow table bookkeeping columns.
//! The stack overflow table tracks items that have "overflowed" below the visible 16-element
//! stack window.
//!
//! ## Columns
//!
//! - `b0`: Stack depth (always >= 16)
//! - `b1`: Address of the top row in the overflow table (clk value when item was pushed)
//! - `h0`: Overflow flag helper = 1/(b0 - 16) when b0 > 16, else 0
//!
//! ## Constraints
//!
//! 1. **Stack depth transition** (degree 7):
//!    - No shift: depth stays the same
//!    - Right shift: depth increases by 1
//!    - Left shift with non-empty overflow: depth decreases by 1 (we pop from the overflow table)
//!    - CALL/SYSCALL/DYNCALL: depth resets to 16
//!
//! 2. **Overflow flag** (degree 3):
//!    - When overflow table is empty (b0 = 16), h0 must be 0
//!    - When overflow table has values (b0 > 16), h0 = 1/(b0 - 16)
//!
//! 3. **Overflow index** (degree 7, 8):
//!    - On right shift: b1' = clk (record when item was pushed)
//!    - On left shift with depth = 16: stack[15]' = 0 (no item to restore)

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::{
    MainTraceRow,
    constraints::{
        op_flags::OpFlags,
        tagging::{TaggingAirBuilderExt, manifest::TAG_STACK_OVERFLOW_BASE},
    },
    trace::{
        decoder::{IS_CALL_FLAG_COL_IDX, IS_SYSCALL_FLAG_COL_IDX},
        stack::{B0_COL_IDX, B1_COL_IDX},
    },
};

// CONSTANTS
// ================================================================================================

/// Base tag ID for stack overflow constraints.
const STACK_OVERFLOW_BASE_ID: usize = TAG_STACK_OVERFLOW_BASE;

/// Tag namespaces for stack overflow constraints (boundary + transition).
const STACK_OVERFLOW_NAMES: [&str; 8] = [
    "stack.overflow.depth.first_row",
    "stack.overflow.depth.last_row",
    "stack.overflow.addr.first_row",
    "stack.overflow.addr.last_row",
    "stack.overflow.depth.transition",
    "stack.overflow.flag.transition",
    "stack.overflow.addr.transition",
    "stack.overflow.zero_insert.transition",
];

// ENTRY POINTS
// ================================================================================================

/// Enforces all stack overflow constraints.
///
/// This function enforces:
/// 1. Stack depth transitions correctly based on the operation type
/// 2. Overflow flag h0 is set correctly
/// 3. Overflow bookkeeping index b1 is updated correctly on shifts
/// 4. Last stack item is zeroed on left shift when depth = 16
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // Boundary constraints: stack depth and overflow pointer must start/end clean.
    let sixteen: AB::Expr = AB::Expr::from_u16(16);
    let zero: AB::Expr = AB::Expr::ZERO;
    builder.tagged(STACK_OVERFLOW_BASE_ID, STACK_OVERFLOW_NAMES[0], |builder| {
        builder
            .when_first_row()
            .assert_zero(local.stack[B0_COL_IDX].clone().into() - sixteen.clone());
    });
    builder.tagged(STACK_OVERFLOW_BASE_ID + 1, STACK_OVERFLOW_NAMES[1], |builder| {
        builder
            .when_last_row()
            .assert_zero(local.stack[B0_COL_IDX].clone().into() - sixteen);
    });
    builder.tagged(STACK_OVERFLOW_BASE_ID + 2, STACK_OVERFLOW_NAMES[2], |builder| {
        builder
            .when_first_row()
            .assert_zero(local.stack[B1_COL_IDX].clone().into() - zero.clone());
    });
    builder.tagged(STACK_OVERFLOW_BASE_ID + 3, STACK_OVERFLOW_NAMES[3], |builder| {
        builder
            .when_last_row()
            .assert_zero(local.stack[B1_COL_IDX].clone().into() - zero);
    });

    // Transition constraints: depth bookkeeping, overflow flag, and pointer updates.
    enforce_stack_depth_constraints(builder, local, next, op_flags);
    enforce_overflow_flag_constraints(builder, local, op_flags);
    enforce_overflow_index_constraints(builder, local, next, op_flags);
}

// CONSTRAINT HELPERS
// ================================================================================================

/// Enforces stack depth transition constraints.
///
/// The stack depth (b0) changes based on the operation:
/// - No shift operations: depth unchanged
/// - Right shift operations: depth += 1
/// - Left shift operations with non-empty overflow: depth -= 1 (we pop from the overflow table)
/// - CALL/SYSCALL/DYNCALL: depth = 16 (reset)
///
/// The END operation exiting a CALL/SYSCALL block is handled separately via multiset constraints.
fn enforce_stack_depth_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let depth: AB::Expr = local.stack[B0_COL_IDX].clone().into();
    let depth_next: AB::Expr = next.stack[B0_COL_IDX].clone().into();

    // Flag for CALL, DYNCALL, or SYSCALL operations
    let call_or_dyncall_or_syscall = op_flags.call() + op_flags.dyncall() + op_flags.syscall();

    // Flag for END operation that ends a CALL/DYNCALL or SYSCALL block
    let is_call_or_dyncall_end: AB::Expr = local.decoder[IS_CALL_FLAG_COL_IDX].clone().into();
    let is_syscall_end: AB::Expr = local.decoder[IS_SYSCALL_FLAG_COL_IDX].clone().into();
    let call_or_dyncall_or_syscall_end = op_flags.end() * (is_call_or_dyncall_end + is_syscall_end);

    // Invariants relied on here:
    // - Aggregate left_shift/right_shift flags are 0 on CALL/SYSCALL/END rows.
    // - DYNCALL is excluded from the aggregate left_shift flag (its stack effect is handled via
    //   per-position left_shift_at flags plus the call-entry depth reset).
    //
    // We have three regimes:
    //
    // 1) CALL/SYSCALL/DYNCALL entry: force b0' = 16 (handled by call_part below).
    // 2) END-of-call: depth restoration is validated by block stack constraints; we don't enforce
    //    the shift law here.
    // 3) All other rows ("normal ops"): depth follows the shift law b0' - b0 + f_shl * f_ov - f_shr
    //    = 0.
    //
    // Why we mask only the (b0' - b0) term:
    //
    // - On CALL/SYSCALL/END rows, the aggregate shift flags are 0 by construction. (CALL/SYSCALL
    //   are explicitly no-shift ops; END sets left_shift only for loop exits; DYNCALL is
    //   intentionally excluded from the aggregate left_shift flag.)
    // - Therefore, the shift terms already vanish on those rows, and masking them would only
    //   increase polynomial degree.
    // - We still need to suppress the raw (b0' - b0) term on END-of-call rows, hence the mask.
    let normal_mask =
        AB::Expr::ONE - call_or_dyncall_or_syscall.clone() - call_or_dyncall_or_syscall_end;
    let depth_delta_part = (depth_next.clone() - depth.clone()) * normal_mask;

    // Left shift with non-empty overflow: when f_shl=1 and f_ov=1, depth must decrement by 1.
    // This contributes +1 to the LHS, enforcing b0' = b0 - 1.
    let left_shift_part = op_flags.left_shift() * op_flags.overflow();

    // Right shift: when f_shr=1, depth must increment by 1.
    // This contributes -1 to the LHS, enforcing b0' = b0 + 1.
    let right_shift_part = op_flags.right_shift();

    // CALL/SYSCALL/DYNCALL: depth resets to 16 when entering a new context.
    let call_part = call_or_dyncall_or_syscall * (depth_next - AB::Expr::from_u16(16));

    // Combined constraint: normal depth update + shift effects + call reset = 0.
    builder.tagged(STACK_OVERFLOW_BASE_ID + 4, STACK_OVERFLOW_NAMES[4], |builder| {
        builder
            .when_transition()
            .assert_zero(depth_delta_part + left_shift_part - right_shift_part + call_part);
    });
}

/// Enforces overflow flag constraints.
///
/// The overflow flag h0 must satisfy:
/// - (1 - overflow) * (b0 - 16) = 0
///
/// This ensures:
/// - When b0 = 16 (no overflow): the constraint is satisfied for any h0
/// - When b0 > 16 (overflow): h0 must be set such that overflow = (b0 - 16) * h0 = 1
fn enforce_overflow_flag_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let depth: AB::Expr = local.stack[B0_COL_IDX].clone().into();

    // (1 - overflow) * (depth - 16) = 0
    // When depth > 16, overflow must be 1 (meaning h0 = 1/(depth - 16))
    // When depth = 16, this constraint is satisfied regardless of overflow
    let constraint = (AB::Expr::ONE - op_flags.overflow()) * (depth - AB::Expr::from_u16(16));

    builder.tagged(STACK_OVERFLOW_BASE_ID + 5, STACK_OVERFLOW_NAMES[5], |builder| {
        builder.when_transition().assert_zero(constraint);
    });
}

/// Enforces overflow bookkeeping index constraints.
///
/// Two constraints:
/// 1. On right shift: b1' = clk (record the clock cycle when item was pushed to overflow)
/// 2. On left shift with depth = 16: stack[15]' = 0 (no item to restore from overflow)
fn enforce_overflow_index_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let overflow_addr_next: AB::Expr = next.stack[B1_COL_IDX].clone().into();
    let clk: AB::Expr = local.clk.clone().into();
    let last_stack_item_next: AB::Expr = next.stack[15].clone().into();

    // On right shift, the overflow address should be set to current clk
    let right_shift_constraint = (overflow_addr_next - clk) * op_flags.right_shift();
    builder.tagged(STACK_OVERFLOW_BASE_ID + 6, STACK_OVERFLOW_NAMES[6], |builder| {
        builder.when_transition().assert_zero(right_shift_constraint);
    });

    // On left shift when depth = 16 (no overflow), last stack item should be zero
    let left_shift_constraint =
        (AB::Expr::ONE - op_flags.overflow()) * op_flags.left_shift() * last_stack_item_next;
    builder.tagged(STACK_OVERFLOW_BASE_ID + 7, STACK_OVERFLOW_NAMES[7], |builder| {
        builder.when_transition().assert_zero(left_shift_constraint);
    });
}
