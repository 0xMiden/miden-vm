//! Stack overflow table bus constraint.
//!
//! This module enforces the running product constraint for the stack overflow table (p1).
//! The stack overflow table tracks values that overflow from the 16-element operand stack.
//!
//! The bus accumulator p1 uses a multiset check:
//! - Boundary: p1[0] = 1 and p1[last] = 1 (enforced by the wrapper AIR)
//! - Transition: p1' * requests = p1 * responses
//!
//! Where:
//! - Responses (adding rows): When right_shift, a row is added with (clk, s15, b1)
//! - Requests (removing rows): When (left_shift OR dyncall) AND non_empty_overflow, a row is
//!   removed with (b1, s15', b1') or (b1, s15', hasher_state[5]) for dyncall
//!
//! ## Row Encoding
//!
//! Each row in the overflow table is encoded as:
//! `alpha + beta^0 * clk + beta^1 * val + beta^2 * prev`

use miden_crypto::stark::air::{ExtensionBuilder, WindowAccess};

use crate::{
    MainTraceRow, MidenAirBuilder,
    constraints::{bus::indices::P1_STACK, constants::F_16, op_flags::OpFlags, utils::BoolNot},
    trace::{
        Challenges,
        decoder::HASHER_STATE_RANGE,
        stack::{B0_COL_IDX, B1_COL_IDX, H0_COL_IDX},
    },
};

// ENTRY POINTS
// ================================================================================================

/// Enforces the stack overflow table bus constraint.
///
/// This constraint tracks overflow table operations using a running product:
/// - Adding rows when right_shift (element pushed off stack position 15)
/// - Removing rows when (left_shift OR dyncall) AND overflow is non-empty
pub fn enforce_bus<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    challenges: &Challenges<AB::ExprEF>,
) where
    AB: MidenAirBuilder,
{
    // Auxiliary trace must be present.

    // Extract auxiliary trace values.
    let (p1_local, p1_next) = {
        let aux = builder.permutation();
        let aux_local = aux.current_slice();
        let aux_next = aux.next_slice();
        (aux_local[P1_STACK], aux_next[P1_STACK])
    };

    // ============================================================================================
    // TRANSITION CONSTRAINT
    // ============================================================================================

    // -------------------------------------------------------------------------
    // Stack and bookkeeping column values
    // -------------------------------------------------------------------------

    // Current row values
    let clk: AB::Expr = local.clk.into();
    let s15: AB::Expr = local.stack[15].into();
    let b0: AB::Expr = local.stack[B0_COL_IDX].into();
    let b1: AB::Expr = local.stack[B1_COL_IDX].into();
    let h0: AB::Expr = local.stack[H0_COL_IDX].into();

    // Next row values (needed for removal)
    let s15_next: AB::Expr = next.stack[15].into();
    let b1_next: AB::Expr = next.stack[B1_COL_IDX].into();

    // Hasher state element 5, used by DYNCALL to store the new overflow table pointer.
    let hasher_state_5: AB::Expr = local.decoder[HASHER_STATE_RANGE.start + 5].into();

    // -------------------------------------------------------------------------
    // Overflow condition: (b0 - 16) * h0 = 1 when overflow is non-empty
    // -------------------------------------------------------------------------

    let is_non_empty_overflow: AB::Expr = (b0 - F_16) * h0;

    // -------------------------------------------------------------------------
    // Operation flags
    // -------------------------------------------------------------------------

    let right_shift = op_flags.right_shift();
    let left_shift = op_flags.left_shift();
    let dyncall = op_flags.dyncall();

    // -------------------------------------------------------------------------
    // Row value encoding: alpha + beta^0 * clk + beta^1 * val + beta^2 * prev
    // -------------------------------------------------------------------------

    // Response row value (adding to table during right_shift):
    let response_row = challenges.encode([clk.clone(), s15.clone(), b1.clone()]);

    // Request row value for left_shift (removing from table):
    let request_row_left = challenges.encode([b1.clone(), s15_next.clone(), b1_next.clone()]);

    // Request row value for dyncall (removing from table):
    let request_row_dyncall =
        challenges.encode([b1.clone(), s15_next.clone(), hasher_state_5.clone()]);

    // -------------------------------------------------------------------------
    // Compute response and request terms
    // -------------------------------------------------------------------------

    // Response: right_shift * response_row + (1 - right_shift)
    let response: AB::ExprEF = response_row * right_shift.clone() + right_shift.not();

    // Request flags
    let left_flag: AB::Expr = left_shift * is_non_empty_overflow.clone();
    let dyncall_flag: AB::Expr = dyncall * is_non_empty_overflow;
    let request_flag_sum: AB::Expr = left_flag.clone() + dyncall_flag.clone();

    // Request: left_flag * left_value + dyncall_flag * dyncall_value + (1 - sum(flags))
    let request: AB::ExprEF = request_row_left * left_flag.clone()
        + request_row_dyncall * dyncall_flag.clone()
        + request_flag_sum.not();

    // -------------------------------------------------------------------------
    // Main running product constraint
    // -------------------------------------------------------------------------

    let lhs = p1_next.into() * request;
    let rhs = p1_local.into() * response;

    builder.when_transition().assert_eq_ext(lhs, rhs);
}
