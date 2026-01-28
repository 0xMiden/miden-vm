//! Range checker bus constraint.
//!
//! This module enforces the LogUp multiset constraint for the range checker bus (b_range).
//! The range checker validates that values are within [0, 2^16) by tracking requests
//! from stack and memory components against the range table responses.
//!
//! ## LogUp Protocol
//!
//! The bus accumulator b_range uses the LogUp protocol:
//! - Boundary: b_range[0] = 0 and b_range[last] = 0
//! - Transition: b_range' = b_range + responses - requests
//!
//! Where requests come from stack (4 lookups) and memory (2 lookups), and
//! responses come from the range table (V column with multiplicity).

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;
use p3_matrix::Matrix;

use crate::{Felt, MainTraceRow, constraints::bus::indices::B_RANGE};

// ENTRY POINTS
// ================================================================================================

/// Enforces the range checker bus constraint for LogUp checks.
///
/// This constraint tracks range check requests from other components (stack and memory)
/// using the LogUp protocol. The bus accumulator b_range must start and end at 0,
/// and transitions according to the LogUp update rule.
///
/// ## Constraint Degree
///
/// This is a degree-9 constraint due to the product of denominators.
///
/// ## Lookups
///
/// - **Stack lookups (4)**: decoder[10..13] contain values being range-checked
/// - **Memory lookups (2)**: chiplets[14..15] contain memory address components
/// - **Range response**: range[1] (V column) with multiplicity range[0]
pub fn enforce_bus<AB>(builder: &mut AB, local: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder<F = Felt>,
{
    // Auxiliary trace must be present.
    debug_assert!(
        builder.permutation().height() > 0,
        "Auxiliary trace must be present for range checker bus constraint"
    );

    // Extract auxiliary trace values and randomness.
    let (b_local_val, b_next_val, alpha_val) = {
        let aux = builder.permutation();
        let aux_local = aux.row_slice(0).expect("Matrix should have at least 1 row");
        let aux_next = aux.row_slice(1).expect("Matrix should have at least 2 rows");
        let b_local = aux_local[B_RANGE];
        let b_next = aux_next[B_RANGE];

        let challenges = builder.permutation_randomness();
        let alpha = challenges[0];
        (b_local, b_next, alpha)
    };

    // ============================================================================================
    // BOUNDARY CONSTRAINTS
    // ============================================================================================

    // b_range must start and end at 0
    builder.when_first_row().assert_zero_ext(b_local_val.into());
    builder.when_last_row().assert_zero_ext(b_local_val.into());

    // ============================================================================================
    // TRANSITION CONSTRAINT
    // ============================================================================================

    let alpha = &alpha_val;
    let b_local = b_local_val;
    let b_next = b_next_val;

    // ---------------------------------------------------------------------------
    // Lookup denominators
    // ---------------------------------------------------------------------------

    // Memory lookups: mv0 = alpha + chiplets[14], mv1 = alpha + chiplets[15]
    let mv0: AB::ExprEF = (*alpha).into() + local.chiplets[14].clone().into();
    let mv1: AB::ExprEF = (*alpha).into() + local.chiplets[15].clone().into();

    // Stack lookups: sv0-sv3 = alpha + decoder[10-13]
    let sv0: AB::ExprEF = (*alpha).into() + local.decoder[10].clone().into();
    let sv1: AB::ExprEF = (*alpha).into() + local.decoder[11].clone().into();
    let sv2: AB::ExprEF = (*alpha).into() + local.decoder[12].clone().into();
    let sv3: AB::ExprEF = (*alpha).into() + local.decoder[13].clone().into();

    // Range check value: alpha + range[1]
    let range_check: AB::ExprEF = (*alpha).into() + local.range[1].clone().into();

    // Combined lookup denominators
    let memory_lookups = mv0.clone() * mv1.clone();
    let stack_lookups = sv0.clone() * sv1.clone() * sv2.clone() * sv3.clone();
    let lookups = range_check.clone() * stack_lookups.clone() * memory_lookups.clone();

    // ---------------------------------------------------------------------------
    // Conditional flags
    // ---------------------------------------------------------------------------

    // u32_rc_op = decoder[7] * (1 - decoder[6]) * (1 - decoder[5])
    // Active when stack is performing range-checked u32 operations
    let not_4: AB::Expr = AB::Expr::ONE - local.decoder[5].clone().into();
    let not_5: AB::Expr = AB::Expr::ONE - local.decoder[6].clone().into();
    let u32_rc_op: AB::Expr = local.decoder[7].clone().into() * not_5.clone() * not_4;
    let sflag_rc_mem = range_check.clone() * memory_lookups.clone() * u32_rc_op;

    // chiplets_memory_flag = chiplets[0] * chiplets[1] * (1 - chiplets[2])
    // Active when memory chiplet is performing operations
    let s_0: AB::Expr = local.chiplets[0].clone().into();
    let s_1: AB::Expr = local.chiplets[1].clone().into();
    let s_2: AB::Expr = local.chiplets[2].clone().into();
    let chiplets_memory_flag: AB::Expr = s_0 * s_1 * (AB::Expr::ONE - s_2);
    let mflag_rc_stack = range_check.clone() * stack_lookups.clone() * chiplets_memory_flag;

    // ---------------------------------------------------------------------------
    // LogUp transition terms
    // ---------------------------------------------------------------------------

    let b_next_term = b_next.into() * lookups.clone();
    let b_term = b_local.into() * lookups.clone();

    // Range check response (multiplicity * value)
    let rc_term = stack_lookups.clone() * memory_lookups.clone() * local.range[0].clone().into();

    // Stack lookup removal terms (when stack is requesting range checks)
    let s0_term = sflag_rc_mem.clone() * sv1.clone() * sv2.clone() * sv3.clone();
    let s1_term = sflag_rc_mem.clone() * sv0.clone() * sv2.clone() * sv3.clone();
    let s2_term = sflag_rc_mem.clone() * sv0.clone() * sv1.clone() * sv3.clone();
    let s3_term = sflag_rc_mem.clone() * sv0.clone() * sv1.clone() * sv2.clone();

    // Memory lookup removal terms (when memory is requesting range checks)
    let m0_term: AB::ExprEF = mflag_rc_stack.clone() * mv1.clone();
    let m1_term = mflag_rc_stack.clone() * mv0.clone();

    // ---------------------------------------------------------------------------
    // Main LogUp constraint
    // ---------------------------------------------------------------------------

    // b_next * lookups = b * lookups + rc_term - s0_term - s1_term - s2_term - s3_term - m0_term -
    // m1_term
    builder.when_transition().assert_zero_ext(
        b_next_term - b_term - rc_term + s0_term + s1_term + s2_term + s3_term + m0_term + m1_term,
    );
}
