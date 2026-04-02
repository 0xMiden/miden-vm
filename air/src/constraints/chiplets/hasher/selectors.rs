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

use miden_crypto::stark::air::AirBuilder;

use super::HasherFlags;
use crate::{MidenAirBuilder, constraints::utils::BoolNot, trace::HasherCols};

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
pub(super) fn enforce_selector_consistency<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    cols: &HasherCols<AB::Var>,
    cols_next: &HasherCols<AB::Var>,
    flags: &HasherFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let s0: AB::Expr = cols.selectors[0].into();
    let s1: AB::Expr = cols.selectors[1].into();
    let s2: AB::Expr = cols.selectors[2].into();
    let s0_next: AB::Expr = cols_next.selectors[0].into();
    let s1_next: AB::Expr = cols_next.selectors[1].into();
    let s2_next: AB::Expr = cols_next.selectors[2].into();

    let builder = &mut builder.when(hasher_flag);

    // -------------------------------------------------------------------------
    // Constraint 1: Selector stability
    // -------------------------------------------------------------------------
    // s[1] and s[2] unchanged unless f_out or f_out_next.
    // Constraint: (1 - f_out - f_out_next) * (s[i]' - s[i]) = 0
    // Note: f_out and f_out_next are mutually exclusive (row30 vs row31), so no overlap.
    // f_out and f_out_next are mutually exclusive (row30 vs row31), so their sum is binary.
    let stability_gate = (flags.f_out.clone() + flags.f_out_next.clone()).not();

    // Selector stability: s1, s2 unchanged outside output boundaries.
    {
        let builder = &mut builder.when(stability_gate);
        builder.assert_eq(s1_next, s1.clone());
        builder.assert_eq(s2_next, s2);
    }

    // Continuation constraint: s0' = 0 after absorb operations.
    builder.when(flags.f_continuation()).assert_zero(s0_next);

    // -------------------------------------------------------------------------
    // Constraint 3: Invalid selector combinations rejection
    // -------------------------------------------------------------------------
    // On row31, if s0 = 0 then s1 must be 0. This prevents (0,1,*) combinations.
    // Constraint: row31 * (1 - s0) * s1 = 0
    builder.when(flags.cycle_row_31.clone()).when(s0.not()).assert_zero(s1);
}
