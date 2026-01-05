//! Range Checker Constraints
//!
//! This module contains constraints for the range checker component:
//! - Boundary constraints: V[0] = 0, V[last] = 65535
//! - Transition constraint: V column changes by powers of 3 or stays constant (for padding)
//! - Bus constraint: LogUp multiset check for range check requests

use core::borrow::Borrow;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;
use p3_matrix::Matrix;

use crate::MainTraceRow;

/// Enforces boundary constraints for the range checker.
///
/// - First row: V[0] = 0 (range checker starts at 0)
/// - Last row: V[last] = 65535 (range checker ends at 2^16 - 1)
pub fn enforce_range_boundary_constraints<AB>(builder: &mut AB, local: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder,
{
    // First row: V[0] = 0
    builder.when_first_row().assert_zero(local.range[1].clone());

    // Last row: V[last] = 65535 (2^16 - 1)
    let sixty_five_k = AB::Expr::from_u32(65535);
    builder.when_last_row().assert_eq(local.range[1].clone(), sixty_five_k);
}

/// Enforces the transition constraint for the range checker V column.
///
/// The V column must change by one of: {0, 1, 3, 9, 27, 81, 243, 729, 2187}
/// - 0 allows V to stay constant during padding rows
/// - Others are powers of 3: {3^0, 3^1, 3^2, 3^3, 3^4, 3^5, 3^6, 3^7}
///
/// This is a degree-9 constraint.
pub fn enforce_range_transition_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    let change_v = next.range[1].clone() - local.range[1].clone();

    // Powers of 3: {1, 3, 9, 27, 81, 243, 729, 2187}
    let one_expr = AB::Expr::ONE;
    let three = AB::Expr::from_u16(3);
    let nine = AB::Expr::from_u16(9);
    let twenty_seven = AB::Expr::from_u16(27);
    let eighty_one = AB::Expr::from_u16(81);
    let two_forty_three = AB::Expr::from_u16(243);
    let seven_twenty_nine = AB::Expr::from_u16(729);
    let two_one_eight_seven = AB::Expr::from_u16(2187);

    // Note: Extra factor of change_v allows V to stay constant (change_v = 0) during padding
    builder.when_transition().assert_zero(
        change_v.clone()
            * (change_v.clone() - one_expr)
            * (change_v.clone() - three)
            * (change_v.clone() - nine)
            * (change_v.clone() - twenty_seven)
            * (change_v.clone() - eighty_one)
            * (change_v.clone() - two_forty_three)
            * (change_v.clone() - seven_twenty_nine)
            * (change_v.clone() - two_one_eight_seven),
    );
}

/// Enforces the range checker bus constraint for LogUp multiset checks.
///
/// This constraint tracks range check requests from other components (stack and memory)
/// using the LogUp protocol. The bus accumulator b_range must start and end at 0,
/// and transitions according to the LogUp update rule.
///
/// This is a degree-9 constraint.
pub fn enforce_range_bus_constraint<AB>(builder: &mut AB, local: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder,
{
    // In Miden VM, auxiliary trace is always present
    debug_assert!(
        builder.permutation().height() > 0,
        "Auxiliary trace must be present for range checker bus constraint"
    );

    let main = builder.main();
    let _next = main.row_slice(1).expect("Matrix should have at least 2 rows");
    let _next: &MainTraceRow<AB::Var> = (*_next).borrow();

    // Extract values needed for constraints
    let (b_local_val, b_next_val, alpha_val) = {
        let aux = builder.permutation();
        let aux_local = aux.row_slice(0).expect("Matrix should have at least 1 row");
        let aux_next = aux.row_slice(1).expect("Matrix should have at least 2 rows");
        // The range checker bus is at auxiliary trace index 4
        let b_local = aux_local[4];
        let b_next = aux_next[4];

        let challenges = builder.permutation_randomness();
        let alpha = challenges[0];
        (b_local, b_next, alpha)
    };

    // Boundary constraints: b_range must start and end at 0
    builder.when_first_row().assert_zero_ext(b_local_val.into());
    builder.when_last_row().assert_zero_ext(b_local_val.into());

    let alpha = &alpha_val;
    let b_local = b_local_val;
    let b_next = b_next_val;

    let one_expr = AB::Expr::ONE;

    // Denominators for LogUp
    // Memory lookups: mv0 = alpha + chiplets[14], mv1 = alpha + chiplets[15]
    let mv0 = (*alpha).into() + AB::ExprEF::from(local.chiplets[14].clone().into());
    let mv1 = (*alpha).into() + AB::ExprEF::from(local.chiplets[15].clone().into());

    // Stack lookups: sv0-sv3 = alpha + decoder[10-13]
    let sv0 = (*alpha).into() + AB::ExprEF::from(local.decoder[10].clone().into());
    let sv1 = (*alpha).into() + AB::ExprEF::from(local.decoder[11].clone().into());
    let sv2 = (*alpha).into() + AB::ExprEF::from(local.decoder[12].clone().into());
    let sv3 = (*alpha).into() + AB::ExprEF::from(local.decoder[13].clone().into());

    // Range check value: alpha + range[1]
    let range_check = (*alpha).into() + AB::ExprEF::from(local.range[1].clone().into());

    // Combined lookup denominators
    let memory_lookups = mv0.clone() * mv1.clone();
    let stack_lookups = sv0.clone() * sv1.clone() * sv2.clone() * sv3.clone();
    let lookups = range_check.clone() * stack_lookups.clone() * memory_lookups.clone();

    // Flags for conditional inclusion
    // u32_rc_op = decoder[7] * (1 - decoder[6]) * (1 - decoder[5])
    let one_ef = AB::ExprEF::from(one_expr.clone());
    let not_4 = one_ef.clone() - AB::ExprEF::from(local.decoder[5].clone().into());
    let not_5 = one_ef.clone() - AB::ExprEF::from(local.decoder[6].clone().into());
    let u32_rc_op = AB::ExprEF::from(local.decoder[7].clone().into()) * not_5 * not_4;
    let sflag_rc_mem = range_check.clone() * memory_lookups.clone() * u32_rc_op;

    // chiplets_memory_flag = chiplets[0] * chiplets[1] * (1 - chiplets[2])
    let s_0 = AB::ExprEF::from(local.chiplets[0].clone().into());
    let s_1 = AB::ExprEF::from(local.chiplets[1].clone().into());
    let s_2 = AB::ExprEF::from(local.chiplets[2].clone().into());
    let chiplets_memory_flag = s_0 * s_1 * (one_ef.clone() - s_2);
    let mflag_rc_stack = range_check.clone() * stack_lookups.clone() * chiplets_memory_flag;

    // LogUp transition constraint terms
    let b_next_term = b_next.into() * lookups.clone();
    let b_term = b_local.into() * lookups.clone();
    let rc_term = stack_lookups.clone()
        * memory_lookups.clone()
        * AB::ExprEF::from(local.range[0].clone().into());

    // Stack lookup removal terms
    let s0_term = sflag_rc_mem.clone() * sv1.clone() * sv2.clone() * sv3.clone();
    let s1_term = sflag_rc_mem.clone() * sv0.clone() * sv2.clone() * sv3.clone();
    let s2_term = sflag_rc_mem.clone() * sv0.clone() * sv1.clone() * sv3.clone();
    let s3_term = sflag_rc_mem.clone() * sv0.clone() * sv1.clone() * sv2.clone();

    // Memory lookup removal terms
    let m0_term: AB::ExprEF = mflag_rc_stack.clone() * mv1.clone();
    let m1_term = mflag_rc_stack.clone() * mv0.clone();

    // Main constraint: b_next * lookups = b * lookups + rc_term - s0_term - s1_term - s2_term -
    // s3_term - m0_term - m1_term
    builder.when_transition().assert_zero_ext(
        b_next_term - b_term - rc_term + s0_term + s1_term + s2_term + s3_term + m0_term + m1_term,
    );
}
