//! Range checker bus constraint.
//!
//! This module enforces the LogUp protocol for the range checker bus (b_range).
//! The range checker validates that values are within [0, 2^16) by tracking requests
//! from stack and memory components against the range table responses.
//!
//! ## LogUp Protocol
//!
//! The bus accumulator b_range uses the LogUp protocol:
//! - Boundary: b_range[0] = 0 and b_range[last] = 0 (enforced by the wrapper AIR)
//! - Transition: b_range' = b_range + responses - requests
//!
//! Where requests come from stack (4 lookups) and memory (2 lookups), and
//! responses come from the range table (V column with multiplicity).

use miden_crypto::stark::air::{ExtensionBuilder, WindowAccess};

use crate::{
    MainCols, MidenAirBuilder,
    constraints::{chiplets::selectors::ChipletSelectors, op_flags::OpFlags},
    trace::{Challenges, bus_types::RANGE_CHECK_BUS, range},
};

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
pub fn enforce_bus<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    challenges: &Challenges<AB::ExprEF>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // In Miden VM, auxiliary trace is always present

    // Extract values needed for constraints
    let aux = builder.permutation();
    let aux_local = aux.current_slice();
    let aux_next = aux.next_slice();
    let b_local = aux_local[range::B_RANGE_COL_IDX];
    let b_next = aux_next[range::B_RANGE_COL_IDX];

    let alpha = &challenges.bus_prefix[RANGE_CHECK_BUS];

    // Denominators for LogUp
    let mem = local.memory();
    let mv0: AB::ExprEF = alpha.clone() + mem.d0.into();
    let mv1: AB::ExprEF = alpha.clone() + mem.d1.into();

    // Stack lookups: sv0-sv3 = alpha + decoder helper columns
    let helpers = local.decoder.user_op_helpers();
    let sv0: AB::ExprEF = alpha.clone() + helpers[0].into();
    let sv1: AB::ExprEF = alpha.clone() + helpers[1].into();
    let sv2: AB::ExprEF = alpha.clone() + helpers[2].into();
    let sv3: AB::ExprEF = alpha.clone() + helpers[3].into();

    // Range check value: alpha + range V column
    let range_check: AB::ExprEF = alpha.clone() + local.range.value.into();

    // Combined lookup denominators
    let memory_lookups = mv0.clone() * mv1.clone();
    let stack_lookups = sv0.clone() * sv1.clone() * sv2.clone() * sv3.clone();
    let lookups = range_check.clone() * stack_lookups.clone() * memory_lookups.clone();

    // Flags for conditional inclusion
    let u32_rc_op = op_flags.u32_rc_op();
    let sflag_rc_mem = range_check.clone() * memory_lookups.clone() * u32_rc_op;

    // chiplets_memory_flag = s0 * s1 * (1 - s2), i.e. memory is active
    let chiplets_memory_flag = selectors.memory.is_active.clone();
    let mflag_rc_stack = range_check * stack_lookups.clone() * chiplets_memory_flag;

    // LogUp transition constraint terms
    let b_next_term = b_next.into() * lookups.clone();
    let b_term = b_local.into() * lookups;
    let rc_term = stack_lookups * memory_lookups * local.range.multiplicity.into();

    // Stack lookup removal terms
    let s0_term = sflag_rc_mem.clone() * sv1.clone() * sv2.clone() * sv3.clone();
    let s1_term = sflag_rc_mem.clone() * sv0.clone() * sv2.clone() * sv3.clone();
    let s2_term = sflag_rc_mem.clone() * sv0.clone() * sv1.clone() * sv3;
    let s3_term = sflag_rc_mem * sv0 * sv1 * sv2;

    // Memory lookup removal terms
    let m0_term = mflag_rc_stack.clone() * mv1;
    let m1_term = mflag_rc_stack * mv0;

    // Main constraint: b_next * lookups = b * lookups + rc_term - s0_term - s1_term - s2_term -
    // s3_term - m0_term - m1_term
    builder.when_transition().assert_zero_ext(
        b_next_term - b_term - rc_term + s0_term + s1_term + s2_term + s3_term + m0_term + m1_term,
    );
}
