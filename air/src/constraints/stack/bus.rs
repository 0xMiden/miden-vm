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
//! `alphas[0] + alphas[1] * clk + alphas[2] * val + alphas[3] * prev`

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::{air::MidenAirBuilder, matrix::Matrix};

use crate::{
    MainTraceRow,
    constraints::{
        bus::{MessageEncoder, indices::P1_STACK},
        op_flags::OpFlags,
        tagging::TaggingAirBuilderExt,
    },
    trace::{
        decoder::HASHER_STATE_RANGE,
        stack::{B0_COL_IDX, B1_COL_IDX, H0_COL_IDX},
    },
};

/// Tag ID and namespace for the stack overflow bus transition constraint.
const STACK_OVERFLOW_BUS_ID: usize = 41;
const STACK_OVERFLOW_BUS_NAME: &str = "stack.overflow.bus.transition";

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
) where
    AB: MidenAirBuilder,
{
    // Auxiliary trace must be present.
    debug_assert!(
        builder.permutation().height() > 0,
        "Auxiliary trace must be present for stack overflow bus constraint"
    );

    // Extract auxiliary trace values and randomness.
    let (p1_local, p1_next, encoder) = {
        let aux = builder.permutation();
        let aux_local = aux.row_slice(0).expect("Matrix should have at least 1 row");
        let aux_next = aux.row_slice(1).expect("Matrix should have at least 2 rows");
        let p1_local = aux_local[P1_STACK];
        let p1_next = aux_next[P1_STACK];

        let challenges = builder.permutation_randomness();
        // We need 3 betas for row encoding: (clk, val, prev).
        let encoder = MessageEncoder::<AB, 3>::from_challenges(challenges);
        (p1_local, p1_next, encoder)
    };

    let one_ef = AB::ExprEF::ONE;

    // ============================================================================================
    // TRANSITION CONSTRAINT
    // ============================================================================================

    // -------------------------------------------------------------------------
    // Stack and bookkeeping column values
    // -------------------------------------------------------------------------

    // Current row values
    let clk: AB::Expr = local.clk.clone().into();
    let s15: AB::Expr = local.stack[15].clone().into();
    let b0: AB::Expr = local.stack[B0_COL_IDX].clone().into();
    let b1: AB::Expr = local.stack[B1_COL_IDX].clone().into();
    let h0: AB::Expr = local.stack[H0_COL_IDX].clone().into();

    // Next row values (needed for removal)
    let s15_next: AB::Expr = next.stack[15].clone().into();
    let b1_next: AB::Expr = next.stack[B1_COL_IDX].clone().into();

    // Hasher state element 5, used by DYNCALL to store the new overflow table pointer.
    let hasher_state_5: AB::Expr = local.decoder[HASHER_STATE_RANGE.start + 5].clone().into();

    // -------------------------------------------------------------------------
    // Overflow condition: (b0 - 16) * h0 = 1 when overflow is non-empty
    // -------------------------------------------------------------------------

    let sixteen = AB::Expr::from_u16(16);
    let is_non_empty_overflow: AB::Expr = (b0 - sixteen) * h0;

    // -------------------------------------------------------------------------
    // Operation flags
    // -------------------------------------------------------------------------

    let right_shift = op_flags.right_shift();
    let left_shift = op_flags.left_shift();
    let dyncall = op_flags.dyncall();

    // -------------------------------------------------------------------------
    // Row value encoding: alphas[0] + alphas[1] * clk + alphas[2] * val + alphas[3] * prev
    // -------------------------------------------------------------------------

    // Response row value (adding to table during right_shift):
    let response_row = encoder.encode([clk.clone(), s15.clone(), b1.clone()]);

    // Request row value for left_shift (removing from table):
    let request_row_left = encoder.encode([b1.clone(), s15_next.clone(), b1_next.clone()]);

    // Request row value for dyncall (removing from table):
    let request_row_dyncall =
        encoder.encode([b1.clone(), s15_next.clone(), hasher_state_5.clone()]);

    // -------------------------------------------------------------------------
    // Compute response and request terms
    // -------------------------------------------------------------------------

    // Response: right_shift * response_row + (1 - right_shift)
    let response: AB::ExprEF = response_row * right_shift.clone() + (one_ef.clone() - right_shift);

    // Request flags
    let left_flag: AB::Expr = left_shift * is_non_empty_overflow.clone();
    let dyncall_flag: AB::Expr = dyncall * is_non_empty_overflow;
    let request_flag_sum: AB::Expr = left_flag.clone() + dyncall_flag.clone();

    // Request: left_flag * left_value + dyncall_flag * dyncall_value + (1 - sum(flags))
    let request: AB::ExprEF = request_row_left * left_flag.clone()
        + request_row_dyncall * dyncall_flag.clone()
        + (one_ef.clone() - request_flag_sum);

    // -------------------------------------------------------------------------
    // Main running product constraint
    // -------------------------------------------------------------------------

    let lhs = p1_next.into() * request;
    let rhs = p1_local.into() * response;

    builder.tagged(STACK_OVERFLOW_BUS_ID, STACK_OVERFLOW_BUS_NAME, |builder| {
        builder.when_transition().assert_zero_ext(lhs - rhs);
    });
}
