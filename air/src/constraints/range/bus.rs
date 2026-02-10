//! Range checker bus constraint.
//!
//! This module enforces the LogUp protocol for the range checker bus (b_range).
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
use miden_crypto::stark::{air::MidenAirBuilder, matrix::Matrix};

use crate::{
    MainTraceRow,
    trace::{
        CHIPLET_S0_COL_IDX, CHIPLET_S1_COL_IDX, CHIPLET_S2_COL_IDX, CHIPLETS_OFFSET,
        RANGE_CHECK_TRACE_OFFSET, chiplets, decoder, range,
    },
};

// CONSTANTS
// ================================================================================================

// --- SLICE-RELATIVE INDICES ---------------------------------------------------------------------
const STACK_LOOKUP_BASE: usize = decoder::USER_OP_HELPERS_OFFSET;
const OP_BIT_4_COL_IDX: usize = decoder::OP_BITS_RANGE.start + 4;
const OP_BIT_5_COL_IDX: usize = decoder::OP_BITS_RANGE.start + 5;
const OP_BIT_6_COL_IDX: usize = decoder::OP_BITS_RANGE.start + 6;
const CHIPLET_S0_IDX: usize = CHIPLET_S0_COL_IDX - CHIPLETS_OFFSET;
const CHIPLET_S1_IDX: usize = CHIPLET_S1_COL_IDX - CHIPLETS_OFFSET;
const CHIPLET_S2_IDX: usize = CHIPLET_S2_COL_IDX - CHIPLETS_OFFSET;
const MEMORY_D0_IDX: usize = chiplets::MEMORY_D0_COL_IDX - CHIPLETS_OFFSET;
const MEMORY_D1_IDX: usize = chiplets::MEMORY_D1_COL_IDX - CHIPLETS_OFFSET;
const RANGE_M_COL_IDX: usize = range::M_COL_IDX - RANGE_CHECK_TRACE_OFFSET;
const RANGE_V_COL_IDX: usize = range::V_COL_IDX - RANGE_CHECK_TRACE_OFFSET;

// ENTRY POINTS
// ================================================================================================

/// Enforces the range checker bus constraint for LogUp checks.
///
/// This constraint tracks range check requests from other components (stack and memory)
/// using the LogUp protocol. The bus accumulator b_range must start and end at 0,
/// and transition according to the LogUp update rule.
///
/// ## Constraint Degree
///
/// This is a degree-9 constraint.
///
/// ## Lookups
///
/// - Stack lookups (4): decoder helper columns (USER_OP_HELPERS_OFFSET..+4)
/// - Memory lookups (2): memory delta limbs (MEMORY_D0, MEMORY_D1)
/// - Range response: range V column with multiplicity range M column
pub fn enforce_bus<AB>(builder: &mut AB, local: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder,
{
    // In Miden VM, auxiliary trace is always present
    debug_assert!(
        builder.permutation().height() > 0,
        "Auxiliary trace must be present for range checker bus constraint"
    );

    // Extract values needed for constraints
    let (b_local_val, b_next_val, alpha_val) = {
        let aux = builder.permutation();
        let aux_local = aux.row_slice(0).expect("Matrix should have at least 1 row");
        let aux_next = aux.row_slice(1).expect("Matrix should have at least 2 rows");
        let b_local = aux_local[range::B_RANGE_COL_IDX];
        let b_next = aux_next[range::B_RANGE_COL_IDX];

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
    // Memory lookups: mv0 = alpha + chiplets[MEMORY_D0], mv1 = alpha + chiplets[MEMORY_D1]
    let mv0 = (*alpha).into() + AB::ExprEF::from(local.chiplets[MEMORY_D0_IDX].clone().into());
    let mv1 = (*alpha).into() + AB::ExprEF::from(local.chiplets[MEMORY_D1_IDX].clone().into());

    // Stack lookups: sv0-sv3 = alpha + decoder helper columns
    let sv0 = (*alpha).into() + AB::ExprEF::from(local.decoder[STACK_LOOKUP_BASE].clone().into());
    let sv1 =
        (*alpha).into() + AB::ExprEF::from(local.decoder[STACK_LOOKUP_BASE + 1].clone().into());
    let sv2 =
        (*alpha).into() + AB::ExprEF::from(local.decoder[STACK_LOOKUP_BASE + 2].clone().into());
    let sv3 =
        (*alpha).into() + AB::ExprEF::from(local.decoder[STACK_LOOKUP_BASE + 3].clone().into());

    // Range check value: alpha + range V column
    let range_check =
        (*alpha).into() + AB::ExprEF::from(local.range[RANGE_V_COL_IDX].clone().into());

    // Combined lookup denominators
    let memory_lookups = mv0.clone() * mv1.clone();
    let stack_lookups = sv0.clone() * sv1.clone() * sv2.clone() * sv3.clone();
    let lookups = range_check.clone() * stack_lookups.clone() * memory_lookups.clone();

    // Flags for conditional inclusion
    // u32_rc_op = op_bit[6] * (1 - op_bit[5]) * (1 - op_bit[4])
    let one_ef = AB::ExprEF::from(one_expr);
    let not_4 = one_ef.clone() - AB::ExprEF::from(local.decoder[OP_BIT_4_COL_IDX].clone().into());
    let not_5 = one_ef.clone() - AB::ExprEF::from(local.decoder[OP_BIT_5_COL_IDX].clone().into());
    let u32_rc_op =
        AB::ExprEF::from(local.decoder[OP_BIT_6_COL_IDX].clone().into()) * not_5 * not_4;
    let sflag_rc_mem = range_check.clone() * memory_lookups.clone() * u32_rc_op;

    // chiplets_memory_flag = s0 * s1 * (1 - s2)
    let s_0 = AB::ExprEF::from(local.chiplets[CHIPLET_S0_IDX].clone().into());
    let s_1 = AB::ExprEF::from(local.chiplets[CHIPLET_S1_IDX].clone().into());
    let s_2 = AB::ExprEF::from(local.chiplets[CHIPLET_S2_IDX].clone().into());
    let chiplets_memory_flag = s_0 * s_1 * (one_ef - s_2);
    let mflag_rc_stack = range_check * stack_lookups.clone() * chiplets_memory_flag;

    // LogUp transition constraint terms
    let b_next_term = b_next.into() * lookups.clone();
    let b_term = b_local.into() * lookups;
    let rc_term = stack_lookups
        * memory_lookups
        * AB::ExprEF::from(local.range[RANGE_M_COL_IDX].clone().into());

    // Stack lookup removal terms
    let s0_term = sflag_rc_mem.clone() * sv1.clone() * sv2.clone() * sv3.clone();
    let s1_term = sflag_rc_mem.clone() * sv0.clone() * sv2.clone() * sv3.clone();
    let s2_term = sflag_rc_mem.clone() * sv0.clone() * sv1.clone() * sv3;
    let s3_term = sflag_rc_mem * sv0 * sv1 * sv2;

    // Memory lookup removal terms
    let m0_term: AB::ExprEF = mflag_rc_stack.clone() * mv1;
    let m1_term = mflag_rc_stack * mv0;

    // Main constraint: b_next * lookups = b * lookups + rc_term - s0_term - s1_term - s2_term -
    // s3_term - m0_term - m1_term
    builder.when_transition().assert_zero_ext(
        b_next_term - b_term - rc_term + s0_term + s1_term + s2_term + s3_term + m0_term + m1_term,
    );
}
