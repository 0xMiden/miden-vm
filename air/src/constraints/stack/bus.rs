//! Stack overflow table bus constraint.
//!
//! This module enforces the running product constraint for the stack overflow table (s_aux).
//! The stack overflow table tracks values that overflow from the 16-element operand stack.
//!
//! The bus accumulator s_aux uses a multiset check:
//! - Boundary: s_aux[0] = 1 and s_aux[last] = 1
//! - Transition: s_aux' * requests = s_aux * responses
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
use miden_crypto::stark::air::MidenAirBuilder;
use p3_matrix::Matrix;

use super::op_flags::OpFlags;
use crate::{
    Felt, MainTraceRow,
    constraints::bus::indices::S_AUX_STACK,
    trace::{
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
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Auxiliary trace must be present.
    debug_assert!(
        builder.permutation().height() > 0,
        "Auxiliary trace must be present for stack overflow bus constraint"
    );

    // Extract auxiliary trace values and randomness.
    let (s_local_val, s_next_val, alphas) = {
        let aux = builder.permutation();
        let aux_local = aux.row_slice(0).expect("Matrix should have at least 1 row");
        let aux_next = aux.row_slice(1).expect("Matrix should have at least 2 rows");
        let s_local = aux_local[S_AUX_STACK];
        let s_next = aux_next[S_AUX_STACK];

        let challenges = builder.permutation_randomness();
        // We need 4 random elements for row encoding
        let alphas: [_; 4] = [challenges[0], challenges[1], challenges[2], challenges[3]];
        (s_local, s_next, alphas)
    };

    // ============================================================================================
    // BOUNDARY CONSTRAINTS
    // ============================================================================================

    // s_aux must start and end at 1
    let one_ef = AB::ExprEF::ONE;
    builder.when_first_row().assert_eq_ext(s_local_val.into(), one_ef.clone());
    builder.when_last_row().assert_eq_ext(s_local_val.into(), one_ef.clone());

    // ============================================================================================
    // TRANSITION CONSTRAINT
    // ============================================================================================

    let s_local = s_local_val;
    let s_next = s_next_val;

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
    //
    // During DYNCALL, the processor stores b1' (new parent overflow address) in hasher_state[5]
    // because the normal b1' location is used for other purposes during the call setup.
    // This is specific to DYNCALL - regular left_shift operations use next.stack[B1_COL_IDX].
    //
    // See: processor/src/stack/aux_trace.rs - DYNCALL uses decoder_hasher_state_element(5, i)
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
    // Row = (clk, s15, b1) - the value s15 being pushed, with clock and previous top address
    let response_row = alphas[0].into()
        + alphas[1].into() * clk.clone()
        + alphas[2].into() * s15.clone()
        + alphas[3].into() * b1.clone();

    // Request row value for left_shift (removing from table):
    // Row = (b1, s15', b1') - using current b1 as clk, next s15 as val, next b1 as prev
    let request_row_left = alphas[0].into()
        + alphas[1].into() * b1.clone()
        + alphas[2].into() * s15_next.clone()
        + alphas[3].into() * b1_next.clone();

    // Request row value for dyncall (removing from table):
    // Row = (b1, s15', hasher_state[5]) - uses hasher state instead of b1' for prev
    let request_row_dyncall = alphas[0].into()
        + alphas[1].into() * b1.clone()
        + alphas[2].into() * s15_next.clone()
        + alphas[3].into() * hasher_state_5.clone();

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

    // s_aux' * requests = s_aux * responses
    // Rearranged: s_aux' * requests - s_aux * responses = 0
    let lhs = s_next.into() * request;
    let rhs = s_local.into() * response;

    builder.when_transition().assert_zero_ext(lhs - rhs);
}
