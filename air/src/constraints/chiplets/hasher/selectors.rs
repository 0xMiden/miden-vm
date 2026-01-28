//! Hasher chiplet selector consistency constraints.
//!
//! This module enforces constraints on the selector columns `s[0..2]` that control
//! hasher operation modes. These constraints ensure:
//!
//! 1. **Booleanity**: Selector values are binary (0 or 1)
//! 2. **Stability**: Selectors remain unchanged except at cycle boundaries
//! 3. **Sequencing**: After absorb operations, computation continues properly
//! 4. **Validity**: Invalid selector combinations are rejected
//!
//! ## Selector Encodings on Row 31
//!
//! | Operation | s0 | s1 | s2 | Description |
//! |-----------|----|----|----|--------------------|
//! | ABP       | 1  | 0  | 0  | Absorb for linear hash |
//! | HOUT      | 0  | 0  | 0  | Output digest |
//! | SOUT      | 0  | 0  | 1  | Output full state |
//! | MPA       | 1  | 0  | 1  | Merkle path absorb |
//! | MVA       | 1  | 1  | 0  | Merkle verify absorb |
//! | MUA       | 1  | 1  | 1  | Merkle update absorb |

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use super::{
    flags::{f_abp, f_continuation, f_out, f_out_next},
    periodic::{P_CYCLE_ROW_30, P_CYCLE_ROW_31},
};
use crate::Felt;

// CONSTRAINT HELPERS
// ================================================================================================

/// Enforces selector consistency constraints for the hasher chiplet.
///
/// ## Constraints
///
/// 1. **Selector stability**: `s[1]` and `s[2]` must remain unchanged across rows, except:
///    - On output rows (HOUT/SOUT on row 31), where selectors can change for the next cycle.
///    - On lookahead rows (row 30 when next row is output), to prepare output selectors.
///
/// 2. **Continuation sequencing**: After ABP/MPA/MVA/MUA (absorb operations on row 31), the next
///    cycle must continue hashing, so `s[0]' = 0`.
///
/// 3. **Invalid combination rejection**: On row 31, if `s[0]=0` then `s[1]` must also be 0. This
///    prevents invalid selector states like `(0,1,0)` or `(0,1,1)`.
///
/// ## Degree Analysis
///
/// - Stability constraint: ~5 (transition_flag * stability_gate * delta)
/// - Continuation constraint: ~5 (transition_flag * f_cont * s0')
/// - Invalid rejection: ~4 (hasher_flag * cycle_row_31 * (1-s0) * s1)
pub fn enforce_selector_consistency<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    s0: AB::Expr,
    s1: AB::Expr,
    s2: AB::Expr,
    s0_next: AB::Expr,
    s1_next: AB::Expr,
    s2_next: AB::Expr,
    periodic: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder<F = Felt>,
{
    let transition_flag = hasher_flag.clone() * builder.is_transition();

    // Periodic values (base field)
    let cycle_row_30: AB::Expr = periodic[P_CYCLE_ROW_30].into();
    let cycle_row_31: AB::Expr = periodic[P_CYCLE_ROW_31].into();

    let one: AB::Expr = AB::Expr::ONE;

    // -------------------------------------------------------------------------
    // Compute flags
    // -------------------------------------------------------------------------

    // f_out: output row (HOUT or SOUT) = row31 & !s0 & !s1
    let flag_out = f_out(cycle_row_31.clone(), s0.clone(), s1.clone());

    // f_out_next: lookahead on row30 for next row being output
    let flag_out_next = f_out_next(cycle_row_30.clone(), s0_next.clone(), s1_next.clone());

    // f_continuation: ABP/MPA/MVA/MUA - operations that continue to next cycle
    let flag_abp = f_abp(cycle_row_31.clone(), s0.clone(), s1.clone(), s2.clone());
    let flag_cont = f_continuation(
        flag_abp,
        super::flags::f_mpa(cycle_row_31.clone(), s0.clone(), s1.clone(), s2.clone()),
        super::flags::f_mva(cycle_row_31.clone(), s0.clone(), s1.clone(), s2.clone()),
        super::flags::f_mua(cycle_row_31.clone(), s0.clone(), s1.clone(), s2.clone()),
    );

    // -------------------------------------------------------------------------
    // Constraint 1: Selector stability
    // -------------------------------------------------------------------------
    // s[1] and s[2] unchanged unless f_out or f_out_next.
    // Constraint: (1 - f_out - f_out_next) * (s[i]' - s[i]) = 0
    // Note: f_out and f_out_next are mutually exclusive (row30 vs row31), so no overlap.
    let stability_gate = one.clone() - flag_out.clone() - flag_out_next.clone();

    // Use a combined gate to share `transition_flag * stability_gate` across both stability
    // constraints.
    let gate = transition_flag.clone() * stability_gate;
    builder
        .when(gate)
        .assert_zeros([s1_next.clone() - s1.clone(), s2_next.clone() - s2.clone()]);

    // Continuation constraint: transition_flag * flag_cont * s0' = 0.
    // (Single constraint, so no batching benefit beyond using `.when(gate)`.)
    let gate = transition_flag * flag_cont;
    builder.when(gate).assert_zero(s0_next.clone());

    // -------------------------------------------------------------------------
    // Constraint 3: Invalid selector rejection
    // -------------------------------------------------------------------------
    // On row31, if s0 = 0 then s1 must be 0. This prevents (0,1,*) combinations.
    // Constraint: row31 * (1 - s0) * s1 = 0
    builder
        .assert_zero(hasher_flag * cycle_row_31.clone() * (one.clone() - s0.clone()) * s1.clone());
}

/// Enforces that selector columns are binary.
///
/// This is called from the main permutation constraint with the step gate.
///
/// ## Degree
/// 2 per constraint (quadratic: x * (x - 1))
pub fn enforce_selector_booleanity<AB>(
    builder: &mut AB,
    step_gate: AB::Expr,
    s0: AB::Var,
    s1: AB::Var,
    s2: AB::Var,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    let mut b_bool = builder.when(step_gate);
    b_bool.assert_bools([s0, s1, s2]);
}
