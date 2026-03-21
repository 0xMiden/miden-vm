//! Hasher chiplet selector and structural constraints.
//!
//! In the controller/permutation split architecture, this module enforces:
//!
//! 1. **Selector booleanity**: s0, s1, s2 are binary
//! 2. **Controller adjacency**: input row (s0=1) must be followed by output row (s0=0, s1=0)
//! 3. **Perm segment selectors**: unconstrained (don't-care); all perm logic uses perm_seg +
//!    periodic columns
//! 4. **Perm segment booleanity and monotonicity**: perm_seg is binary and non-decreasing
//! 5. **Structural confinement**: is_start/is_final confined to correct row types
//! 6. **Lifecycle booleanity**: is_start and is_final are binary on their respective row types

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::AirBuilder;

use super::HasherColumns;
use crate::{
    Felt,
    constraints::tagging::{
        TagGroup, TaggingAirBuilderExt, tagged_assert_zero, tagged_assert_zero_integrity,
        tagged_assert_zeros, tagged_assert_zeros_integrity,
    },
};

// TAGGING NAMESPACES
// ================================================================================================

const SELECTOR_BOOL_NAMESPACE: &str = "chiplets.hasher.selectors.binary";
const CONTROLLER_ADJ_NAMESPACE: &str = "chiplets.hasher.selectors.adjacency";
const CONTROLLER_PAIRING_NAMESPACE: &str = "chiplets.hasher.selectors.pairing";
const PERM_SEG_NAMESPACE: &str = "chiplets.hasher.selectors.perm_seg";
const STRUCTURAL_NAMESPACE: &str = "chiplets.hasher.selectors.structural";
const LIFECYCLE_NAMESPACE: &str = "chiplets.hasher.selectors.lifecycle";

const SELECTOR_BOOL_NAMES: [&str; 3] = [SELECTOR_BOOL_NAMESPACE; 3];
const PERM_SEG_NAMES: [&str; 7] = [PERM_SEG_NAMESPACE; 7];
const STRUCTURAL_NAMES: [&str; 5] = [STRUCTURAL_NAMESPACE; 5];
const LIFECYCLE_NAMES: [&str; 2] = [LIFECYCLE_NAMESPACE; 2];
const CONTROLLER_ADJ_NAMES: [&str; 2] = [CONTROLLER_ADJ_NAMESPACE; 2];
const CONTROLLER_PAIRING_NAMES: [&str; 4] = [CONTROLLER_PAIRING_NAMESPACE; 4];

const SELECTOR_BOOL_TAGS: TagGroup = TagGroup {
    base: super::HASHER_SELECTOR_BOOL_BASE_ID,
    names: &SELECTOR_BOOL_NAMES,
};
const PERM_SEG_TAGS: TagGroup = TagGroup {
    base: super::HASHER_PERM_SEG_BASE_ID,
    names: &PERM_SEG_NAMES,
};
const STRUCTURAL_TAGS: TagGroup = TagGroup {
    base: super::HASHER_STRUCTURAL_BASE_ID,
    names: &STRUCTURAL_NAMES,
};
const LIFECYCLE_TAGS: TagGroup = TagGroup {
    base: super::HASHER_LIFECYCLE_BASE_ID,
    names: &LIFECYCLE_NAMES,
};
const CONTROLLER_ADJ_TAGS: TagGroup = TagGroup {
    base: super::HASHER_CONTROLLER_ADJ_BASE_ID,
    names: &CONTROLLER_ADJ_NAMES,
};
const CONTROLLER_PAIRING_TAGS: TagGroup = TagGroup {
    base: super::HASHER_CONTROLLER_PAIRING_BASE_ID,
    names: &CONTROLLER_PAIRING_NAMES,
};

// CONSTRAINT FUNCTIONS
// ================================================================================================

/// Enforces that selector columns are binary on controller rows.
///
/// On perm segment rows (perm_seg=1), selectors s0/s1/s2 are unconstrained (don't-care)
/// because no consumer reads them in a security-relevant way -- all perm segment logic
/// uses `perm_seg` + periodic columns instead.
pub fn enforce_selector_booleanity<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    cols: &HasherColumns<AB::Expr>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let controller_gate = hasher_flag * cols.controller_flag();
    let mut idx = 0;
    tagged_assert_zeros_integrity(
        builder,
        &SELECTOR_BOOL_TAGS,
        &mut idx,
        SELECTOR_BOOL_NAMESPACE,
        [
            controller_gate.clone() * cols.s0.clone() * (cols.s0.clone() - AB::Expr::ONE),
            controller_gate.clone() * cols.s1.clone() * (cols.s1.clone() - AB::Expr::ONE),
            controller_gate * cols.s2.clone() * (cols.s2.clone() - AB::Expr::ONE),
        ],
    );
}

/// Enforces controller row adjacency: input row must be followed by output row.
///
/// When perm_seg=0 and s0=1 (controller input row), the next row must have s0=0 and s1=0
/// (controller output row).
///
/// Constraints:
/// - `controller_flag * s0 * s0_next = 0`  (next s0 must be 0)
/// - `controller_flag * s0 * s1_next = 0`  (next s1 must be 0)
pub fn enforce_controller_adjacency<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    cols: &HasherColumns<AB::Expr>,
    cols_next: &HasherColumns<AB::Expr>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let gate = hasher_flag * cols.controller_flag() * cols.s0.clone();

    let mut idx = 0;
    tagged_assert_zeros(
        builder,
        &CONTROLLER_ADJ_TAGS,
        &mut idx,
        CONTROLLER_ADJ_NAMESPACE,
        [gate.clone() * cols_next.s0.clone(), gate * cols_next.s1.clone()],
    );
}

/// Enforces perm_seg booleanity, segment ordering, and cycle alignment.
///
/// Constraints:
/// - `(1 - hasher_flag) * perm_seg = 0` (perm_seg can only be non-zero on hasher rows)
/// - `hasher_flag * perm_seg * (perm_seg - 1) = 0` (booleanity)
/// - `hasher_flag * hasher_flag_next * perm_seg * (1 - perm_seg_next) = 0`
///   (monotonicity: once 1, stays 1 within hasher rows)
/// - `hasher_flag * hasher_flag_next * (1 - perm_seg) * perm_seg_next * (1 - cycle_row_31) = 0`
///   (0->1 transition can happen only after cycle row 31, i.e. first perm row is cycle row 0)
/// - `hasher_flag * (1 - hasher_flag_next) * perm_seg * (1 - cycle_row_31) = 0`
///   (if hasher ends while in perm segment, it must end on cycle row 31)
/// - `hasher_flag * (1 - hasher_flag_next) * (1 - perm_seg) = 0`
///   (hasher region cannot end while still in controller section)
/// - `hasher_flag * perm_seg * (1 - cycle_row_31) * (node_index_next - node_index) = 0`
///   (multiplicity is constant within a 32-row permutation cycle)
///
/// The controller region (perm_seg=0) precedes the permutation segment (perm_seg=1).
/// Once perm_seg transitions to 1, it cannot go back to 0.
pub fn enforce_perm_seg_constraints<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    hasher_flag_next: AB::Expr,
    cols: &HasherColumns<AB::Expr>,
    cols_next: &HasherColumns<AB::Expr>,
    cycle_row_31: AB::Expr,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let mut idx = 0;

    // Confinement: perm_seg can only be non-zero on hasher rows. This makes `perm_seg`
    // a sound stand-alone gate for permutation constraints, without multiplying by
    // `hasher_flag` in the high-degree Poseidon2 transition constraints.
    tagged_assert_zero_integrity(
        builder,
        &PERM_SEG_TAGS,
        &mut idx,
        (AB::Expr::ONE - hasher_flag.clone()) * cols.perm_seg.clone(),
    );

    // Booleanity
    tagged_assert_zero_integrity(
        builder,
        &PERM_SEG_TAGS,
        &mut idx,
        hasher_flag.clone() * cols.perm_seg.clone() * (cols.perm_seg.clone() - AB::Expr::ONE),
    );

    // Monotonicity: once in perm segment (perm_seg=1), cannot return to controller (perm_seg=0).
    // Gate by hasher_flag_next to avoid firing at the hasher-to-bitwise boundary, where
    // perm_seg_next reads garbage from the next chiplet's columns.
    tagged_assert_zero(
        builder,
        &PERM_SEG_TAGS,
        &mut idx,
        hasher_flag.clone()
            * hasher_flag_next.clone()
            * cols.perm_seg.clone()
            * (AB::Expr::ONE - cols_next.perm_seg.clone()),
    );

    // Rising-edge alignment: entering perm segment (0->1) can happen only after cycle row 31.
    // This ensures the first perm row is aligned with cycle row 0.
    tagged_assert_zero(
        builder,
        &PERM_SEG_TAGS,
        &mut idx,
        hasher_flag.clone()
            * hasher_flag_next.clone()
            * (AB::Expr::ONE - cols.perm_seg.clone())
            * cols_next.perm_seg.clone()
            * (AB::Expr::ONE - cycle_row_31.clone()),
    );

    // Exit safety: if the hasher segment ends while in perm segment, the last hasher row must
    // be cycle row 31. This prevents cross-chiplet next-row reads from firing under perm gates.
    tagged_assert_zero(
        builder,
        &PERM_SEG_TAGS,
        &mut idx,
        hasher_flag.clone()
            * (AB::Expr::ONE - hasher_flag_next.clone())
            * cols.perm_seg.clone()
            * (AB::Expr::ONE - cycle_row_31.clone()),
    );

    // If the hasher segment ends, it must not end while still in the controller section.
    tagged_assert_zero(
        builder,
        &PERM_SEG_TAGS,
        &mut idx,
        hasher_flag.clone()
            * (AB::Expr::ONE - hasher_flag_next)
            * (AB::Expr::ONE - cols.perm_seg.clone()),
    );

    // Multiplicity constancy within perm cycles: on perm segment rows that are NOT the
    // cycle boundary (row 31), node_index must stay constant. This ensures each 32-row
    // cycle has a single multiplicity value.
    // Degree: hasher_flag(1) * perm_seg(1) * (1-cycle_row_31)(1) * diff(1) = 4.
    tagged_assert_zero(
        builder,
        &PERM_SEG_TAGS,
        &mut idx,
        hasher_flag
            * cols.perm_seg.clone()
            * (AB::Expr::ONE - cycle_row_31)
            * (cols_next.node_index.clone() - cols.node_index.clone()),
    );
}

/// Enforces structural confinement of is_start and is_final.
///
/// Confines is_start and is_final to their valid row types.
///
/// is_start is confined to controller input rows (s0=1, perm_seg=0):
/// - `(1 - s0) * is_start = 0` -- zero when s0=0 (output, padding rows in controller)
/// - `perm_seg * is_start = 0` -- zero on perm segment rows (where s0 is unconstrained)
///
/// is_final is confined to controller output rows (s0=0, s1=0, perm_seg=0):
/// - `s0 * is_final = 0` -- zero on input rows (s0=1)
/// - `(1-s0) * s1 * is_final = 0` -- zero on padding rows (s0=0, s1=1)
/// - `perm_seg * is_final = 0` -- zero on perm segment rows (where s0/s1 are unconstrained)
pub fn enforce_structural_confinement<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    cols: &HasherColumns<AB::Expr>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let mut idx = 0;
    tagged_assert_zeros_integrity(
        builder,
        &STRUCTURAL_TAGS,
        &mut idx,
        STRUCTURAL_NAMESPACE,
        [
            // is_start zero when s0=0 (controller output and padding rows)
            hasher_flag.clone() * (AB::Expr::ONE - cols.s0.clone()) * cols.is_start.clone(),
            // is_start zero on perm segment rows
            hasher_flag.clone() * cols.perm_seg.clone() * cols.is_start.clone(),
            // is_final zero on input rows (s0=1)
            hasher_flag.clone() * cols.s0.clone() * cols.is_final.clone(),
            // is_final zero on padding rows (s0=0, s1=1)
            hasher_flag.clone()
                * (AB::Expr::ONE - cols.s0.clone())
                * cols.s1.clone()
                * cols.is_final.clone(),
            // is_final zero on perm segment rows
            hasher_flag * cols.perm_seg.clone() * cols.is_final.clone(),
        ],
    );
}

/// Enforces booleanity of is_start and is_final on their respective row types.
///
/// The structural confinement constraints already ensure is_start=0 and is_final=0 on rows
/// where they don't apply, so booleanity only needs to fire on the correct row types:
///
/// - `hasher_flag * s0 * is_start * (is_start - 1) = 0`  (on input rows; s0=1 excludes output and
///   perm rows)
/// - `hasher_flag * (1-s0) * (1-s1) * is_final * (is_final - 1) = 0`  (on output rows;
///   (1-s0)*(1-s1) excludes input and perm rows)
pub fn enforce_lifecycle_booleanity<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    cols: &HasherColumns<AB::Expr>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let mut idx = 0;
    tagged_assert_zeros_integrity(
        builder,
        &LIFECYCLE_TAGS,
        &mut idx,
        LIFECYCLE_NAMESPACE,
        [
            // is_start booleanity on input rows (degree 4: hasher * s0 * is_start * (is_start-1))
            hasher_flag.clone()
                * cols.s0.clone()
                * cols.is_start.clone()
                * (cols.is_start.clone() - AB::Expr::ONE),
            // is_final booleanity on output rows (degree 5: hasher * (1-s0) * (1-s1) * is_final *
            // (is_final-1))
            hasher_flag
                * (AB::Expr::ONE - cols.s0.clone())
                * (AB::Expr::ONE - cols.s1.clone())
                * cols.is_final.clone()
                * (cols.is_final.clone() - AB::Expr::ONE),
        ],
    );
}

/// Enforces well-formed controller structure.
///
/// 1. **First-row boundary**: first row is a controller input (`s0=1`, `perm_seg=0`).
///
/// 2. **Output non-adjacency**: A controller output row cannot be followed by another output row.
///    Combined with the adjacency constraint (input -> output), this guarantees strictly
///    alternating (input, output) pairs.
///
/// 3-4. **Padding stability**: Once a padding row appears (s0=0, s1=1, perm_seg=0), the next
///    controller row must also be padding. This prevents operations from appearing after padding.
///    Specifically: (3) blocks input rows (s0_next=1) and (4) blocks output rows (s1_next=0)
///    after padding within the controller region.
pub fn enforce_controller_pairing<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    cols: &HasherColumns<AB::Expr>,
    cols_next: &HasherColumns<AB::Expr>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // 1. First-row boundary: row 0 must be a controller input row.
    // Enforce both s0=1 and perm_seg=0 in a single constraint:
    // (1 - s0) + perm_seg = 0.
    builder.tagged(CONTROLLER_PAIRING_TAGS.base, CONTROLLER_PAIRING_NAMES[0], |builder| {
        builder
            .when_first_row()
            .when(hasher_flag.clone())
            .assert_zero((AB::Expr::ONE - cols.s0.clone()) + cols.perm_seg.clone());
    });

    // 2. Output non-adjacency: output row cannot be followed by another output row.
    // Degree: 7 (hasher * ctrl * (1-s0) * (1-s1) * ctrl_next * (1-s0_next) * (1-s1_next))
    let output_flag = hasher_flag.clone()
        * cols.controller_flag()
        * (AB::Expr::ONE - cols.s0.clone())
        * (AB::Expr::ONE - cols.s1.clone());
    let next_is_output = cols_next.controller_flag()
        * (AB::Expr::ONE - cols_next.s0.clone())
        * (AB::Expr::ONE - cols_next.s1.clone());
    let mut idx = 1; // skip index 0 (used by first-row above)
    tagged_assert_zero(builder, &CONTROLLER_PAIRING_TAGS, &mut idx, output_flag * next_is_output);

    // 3-4. Padding stability: a padding row (perm_seg=0, s0=0, s1=1) can only be followed
    // by another padding row or a perm segment row. This is enforced with two constraints:
    // (3) no input row after padding: padding_flag * (1-perm_seg_next) * s0_next = 0
    // (4) no output row after padding: padding_flag * (1-perm_seg_next) * (1-s1_next) = 0
    // Together, the next controller row (if any) must have s0=0 AND s1=1 (= padding).
    // Degree: 5 each.
    let padding_flag =
        hasher_flag * cols.controller_flag() * (AB::Expr::ONE - cols.s0.clone()) * cols.s1.clone();
    let next_is_controller = cols_next.controller_flag();

    // (3) No input row (s0_next=1) after padding.
    tagged_assert_zero(
        builder,
        &CONTROLLER_PAIRING_TAGS,
        &mut idx,
        padding_flag.clone() * next_is_controller.clone() * cols_next.s0.clone(),
    );

    // (4) No output row (s1_next=0) after padding.
    tagged_assert_zero(
        builder,
        &CONTROLLER_PAIRING_TAGS,
        &mut idx,
        padding_flag * next_is_controller * (AB::Expr::ONE - cols_next.s1.clone()),
    );
}
