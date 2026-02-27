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

use super::{HasherColumns, HasherFlags};
use crate::{
    Felt,
    constraints::tagging::{
        TagGroup, TaggingAirBuilderExt, tagged_assert_zero, tagged_assert_zero_integrity,
        tagged_assert_zeros,
    },
};

// TAGGING NAMESPACES
// ================================================================================================

const SELECTOR_BOOL_NAMESPACE: &str = "chiplets.hasher.selectors.binary";
const SELECTOR_STABILITY_NAMESPACE: &str = "chiplets.hasher.selectors.stability";
const SELECTOR_CONT_NAMESPACE: &str = "chiplets.hasher.selectors.continuation";
const SELECTOR_INVALID_NAMESPACE: &str = "chiplets.hasher.selectors.invalid";

const SELECTOR_BOOL_NAMES: [&str; 3] = [SELECTOR_BOOL_NAMESPACE; 3];
const SELECTOR_CONSIST_NAMES: [&str; 4] = [
    SELECTOR_STABILITY_NAMESPACE,
    SELECTOR_STABILITY_NAMESPACE,
    SELECTOR_CONT_NAMESPACE,
    SELECTOR_INVALID_NAMESPACE,
];

const SELECTOR_BOOL_TAGS: TagGroup = TagGroup {
    base: super::HASHER_SELECTOR_BOOL_BASE_ID,
    names: &SELECTOR_BOOL_NAMES,
};
const SELECTOR_CONSIST_TAGS: TagGroup = TagGroup {
    base: super::HASHER_SELECTOR_CONSIST_BASE_ID,
    names: &SELECTOR_CONSIST_NAMES,
};

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
    cols: &HasherColumns<AB::Expr>,
    cols_next: &HasherColumns<AB::Expr>,
    flags: &HasherFlags<AB::Expr>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let one: AB::Expr = AB::Expr::ONE;

    // -------------------------------------------------------------------------
    // Constraint 1: Selector stability
    // -------------------------------------------------------------------------
    // s[1] and s[2] unchanged unless f_out or f_out_next.
    // Constraint: (1 - f_out - f_out_next) * (s[i]' - s[i]) = 0
    // Note: f_out and f_out_next are mutually exclusive (row30 vs row31), so no overlap.
    let stability_gate = one.clone() - flags.f_out.clone() - flags.f_out_next.clone();

    // Use a combined gate to share `hasher_flag * stability_gate` across both stability
    // constraints.
    let gate = hasher_flag.clone() * stability_gate;
    let mut idx = 0;
    tagged_assert_zeros(
        builder,
        &SELECTOR_CONSIST_TAGS,
        &mut idx,
        SELECTOR_STABILITY_NAMESPACE,
        [
            gate.clone() * (cols_next.s1.clone() - cols.s1.clone()),
            gate * (cols_next.s2.clone() - cols.s2.clone()),
        ],
    );

    // Continuation constraint: hasher_flag * flag_cont * s0' = 0.
    // (Single constraint, so no batching benefit beyond using `.when(gate)`.)
    let gate = hasher_flag.clone() * flags.f_continuation();
    tagged_assert_zero(builder, &SELECTOR_CONSIST_TAGS, &mut idx, gate * cols_next.s0.clone());

    // -------------------------------------------------------------------------
    // Constraint 3: Invalid selector combinations rejection
    // -------------------------------------------------------------------------
    // On row31, if s0 = 0 then s1 must be 0. This prevents (0,1,*) combinations.
    // Constraint: row31 * (1 - s0) * s1 = 0
    tagged_assert_zero_integrity(
        builder,
        &SELECTOR_CONSIST_TAGS,
        &mut idx,
        hasher_flag
            * flags.cycle_row_31.clone()
            * (one.clone() - cols.s0.clone())
            * cols.s1.clone(),
    );
}

/// Enforces that selector columns are binary.
///
/// This is called from the main permutation constraint with the step gate.
pub fn enforce_selector_booleanity<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    s0: AB::Var,
    s1: AB::Var,
    s2: AB::Var,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let s0: AB::Expr = s0.into();
    let s1: AB::Expr = s1.into();
    let s2: AB::Expr = s2.into();
    let mut idx = 0;
    tagged_assert_zeros(
        builder,
        &SELECTOR_BOOL_TAGS,
        &mut idx,
        SELECTOR_BOOL_NAMESPACE,
        [
            hasher_flag.clone() * s0.clone() * (s0 - AB::Expr::ONE),
            hasher_flag.clone() * s1.clone() * (s1 - AB::Expr::ONE),
            hasher_flag * s2.clone() * (s2 - AB::Expr::ONE),
        ],
    );
}
