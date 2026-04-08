//! Hasher chiplet selector and structural constraints.
//!
//! In the controller/permutation split architecture, this module enforces:
//!
//! 1. **Selector booleanity**: s0, s1, s2 are binary
//! 2. **Controller adjacency**: input row (s0=1) must be followed by output row (s0=0, s1=0)
//! 3. **Perm segment selectors**: unconstrained (don't-care); all perm logic uses perm_seg +
//!    periodic columns
//! 4. **Perm segment booleanity and monotonicity**: perm_seg is binary and non-decreasing
//! 5. **Structural confinement**: is_boundary/direction_bit confined to correct row types
//! 6. **Lifecycle booleanity**: is_boundary is binary on boundary row types

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::AirBuilder;

use super::HasherExprs;
use crate::MidenAirBuilder;

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
    cols: &HasherExprs<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let controller_gate = hasher_flag * cols.controller_flag();
    builder
        .assert_zero(controller_gate.clone() * cols.s0.clone() * (cols.s0.clone() - AB::Expr::ONE));
    builder
        .assert_zero(controller_gate.clone() * cols.s1.clone() * (cols.s1.clone() - AB::Expr::ONE));
    builder.assert_zero(controller_gate * cols.s2.clone() * (cols.s2.clone() - AB::Expr::ONE));
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
    cols: &HasherExprs<AB::Expr>,
    cols_next: &HasherExprs<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let gate = hasher_flag * cols.controller_flag() * cols.s0.clone();

    builder.assert_zero(gate.clone() * cols_next.s0.clone());
    builder.assert_zero(gate * cols_next.s1.clone());
}

/// Enforces perm_seg booleanity, segment ordering, and cycle alignment.
///
/// Constraints:
/// - `(1 - hasher_flag) * perm_seg = 0` (perm_seg can only be non-zero on hasher rows)
/// - `hasher_flag * perm_seg * (perm_seg - 1) = 0` (booleanity)
/// - `hasher_flag * hasher_flag_next * perm_seg * (1 - perm_seg_next) = 0` (monotonicity: once 1,
///   stays 1 within hasher rows)
/// - `hasher_flag * hasher_flag_next * (1 - perm_seg) * perm_seg_next * not_boundary = 0` (0->1
///   transition can happen only after the cycle boundary row)
/// - `hasher_flag * (1 - hasher_flag_next) * perm_seg * not_boundary = 0` (if hasher ends while in
///   perm segment, it must end on the cycle boundary row)
/// - `hasher_flag * (1 - hasher_flag_next) * (1 - perm_seg) = 0` (hasher region cannot end while
///   still in controller section)
/// - `hasher_flag * perm_seg * not_boundary * (node_index_next - node_index) = 0` (multiplicity is
///   constant within a permutation cycle)
///
/// The `not_boundary` parameter equals `(1 - cycle_row_15)`, derived as the sum of
/// the 4 periodic step-type selectors. It is 1 on rows 0-14 and 0 on row 15.
///
/// The controller region (perm_seg=0) precedes the permutation segment (perm_seg=1).
/// Once perm_seg transitions to 1, it cannot go back to 0.
pub fn enforce_perm_seg_constraints<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    hasher_flag_next: AB::Expr,
    cols: &HasherExprs<AB::Expr>,
    cols_next: &HasherExprs<AB::Expr>,
    not_boundary: AB::Expr,
) where
    AB: MidenAirBuilder,
{
    // Confinement: perm_seg can only be non-zero on hasher rows. This makes `perm_seg`
    // a sound stand-alone gate for permutation constraints, without multiplying by
    // `hasher_flag` in the high-degree Poseidon2 transition constraints.
    builder.assert_zero((AB::Expr::ONE - hasher_flag.clone()) * cols.perm_seg.clone());

    // Booleanity
    builder.assert_zero(
        hasher_flag.clone() * cols.perm_seg.clone() * (cols.perm_seg.clone() - AB::Expr::ONE),
    );

    // Monotonicity: once in perm segment (perm_seg=1), cannot return to controller (perm_seg=0).
    // Gate by hasher_flag_next to avoid firing at the hasher-to-bitwise boundary, where
    // perm_seg_next reads garbage from the next chiplet's columns.
    builder.assert_zero(
        hasher_flag.clone()
            * hasher_flag_next.clone()
            * cols.perm_seg.clone()
            * (AB::Expr::ONE - cols_next.perm_seg.clone()),
    );

    // Rising-edge alignment: entering perm segment (0->1) can happen only after the cycle
    // boundary row (row 15). This ensures the first perm row is aligned with cycle row 0.
    builder.assert_zero(
        hasher_flag.clone()
            * hasher_flag_next.clone()
            * (AB::Expr::ONE - cols.perm_seg.clone())
            * cols_next.perm_seg.clone()
            * not_boundary.clone(),
    );

    // Exit safety: if the hasher segment ends while in perm segment, the last hasher row must
    // be the cycle boundary row (row 15). This prevents cross-chiplet next-row reads from
    // firing under perm gates.
    builder.assert_zero(
        hasher_flag.clone()
            * (AB::Expr::ONE - hasher_flag_next.clone())
            * cols.perm_seg.clone()
            * not_boundary.clone(),
    );

    // If the hasher segment ends, it must not end while still in the controller section.
    builder.assert_zero(
        hasher_flag.clone()
            * (AB::Expr::ONE - hasher_flag_next)
            * (AB::Expr::ONE - cols.perm_seg.clone()),
    );

    // Multiplicity constancy within perm cycles: on perm segment rows that are NOT the
    // cycle boundary (row 15), node_index must stay constant. This ensures each 16-row
    // cycle has a single multiplicity value.
    // Degree: hasher_flag(1) * perm_seg(1) * not_boundary(1) * diff(1) = 4.
    builder.assert_zero(
        hasher_flag
            * cols.perm_seg.clone()
            * not_boundary
            * (cols_next.node_index.clone() - cols.node_index.clone()),
    );
}

/// Ensures is_boundary and direction_bit are zero where they should not be active.
///
/// is_boundary can only be non-zero on controller input and output rows:
/// - zero on padding rows: `(1-s0) * s1 * is_boundary = 0`
/// - zero on perm segment rows: `perm_seg * is_boundary = 0`
///
/// direction_bit can only be non-zero on Merkle input/output controller rows:
/// - zero on padding rows: `(1-s0) * s1 * direction_bit = 0`
/// - zero on perm segment rows: `perm_seg * direction_bit = 0`
/// - zero on sponge (LINEAR_HASH) input rows: `f_sponge * direction_bit = 0`
/// - zero on RETURN_HASH output rows: `f_hout * direction_bit = 0`
/// - zero on HPERM final output (RETURN_STATE with is_boundary=1): `f_sout * is_boundary *
///   direction_bit = 0`
///
/// This keeps direction_bit unconstrained only where it is semantically needed: Merkle
/// input rows and non-final Merkle RETURN_STATE output rows.
pub fn enforce_structural_confinement<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    cols: &HasherExprs<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let f_sponge =
        cols.s0.clone() * (AB::Expr::ONE - cols.s1.clone()) * (AB::Expr::ONE - cols.s2.clone());
    let f_hout = (AB::Expr::ONE - cols.s0.clone())
        * (AB::Expr::ONE - cols.s1.clone())
        * (AB::Expr::ONE - cols.s2.clone());
    let f_sout =
        (AB::Expr::ONE - cols.s0.clone()) * (AB::Expr::ONE - cols.s1.clone()) * cols.s2.clone();

    // is_boundary zero on padding rows (s0=0, s1=1)
    builder.assert_zero(
        hasher_flag.clone()
            * (AB::Expr::ONE - cols.s0.clone())
            * cols.s1.clone()
            * cols.is_boundary.clone(),
    );
    // is_boundary zero on perm segment rows
    builder.assert_zero(hasher_flag.clone() * cols.perm_seg.clone() * cols.is_boundary.clone());
    // direction_bit zero on padding rows (s0=0, s1=1)
    builder.assert_zero(
        hasher_flag.clone()
            * (AB::Expr::ONE - cols.s0.clone())
            * cols.s1.clone()
            * cols.direction_bit.clone(),
    );
    // direction_bit zero on perm segment rows
    builder.assert_zero(hasher_flag.clone() * cols.perm_seg.clone() * cols.direction_bit.clone());
    // direction_bit zero on sponge (LINEAR_HASH) input rows
    builder.assert_zero(
        hasher_flag.clone() * cols.controller_flag() * f_sponge * cols.direction_bit.clone(),
    );
    // direction_bit zero on RETURN_HASH rows
    builder.assert_zero(
        hasher_flag.clone() * cols.controller_flag() * f_hout * cols.direction_bit.clone(),
    );
    // direction_bit zero on final RETURN_STATE boundary rows (HPERM final output)
    builder.assert_zero(
        hasher_flag
            * cols.controller_flag()
            * f_sout
            * cols.is_boundary.clone()
            * cols.direction_bit.clone(),
    );
}

/// Enforces booleanity of is_boundary on input and output row types.
///
/// The structural confinement constraints already ensure is_boundary=0 on padding and perm
/// rows, so booleanity only needs to fire on input and output rows:
///
/// - `hasher_flag * s0 * is_boundary * (is_boundary - 1) = 0`  (on input rows)
/// - `hasher_flag * (1-s0) * (1-s1) * is_boundary * (is_boundary - 1) = 0`  (on output rows)
pub fn enforce_lifecycle_booleanity<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    cols: &HasherExprs<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // is_boundary booleanity on input rows (degree 4: hasher * s0 * is_boundary *
    // (is_boundary-1))
    builder.assert_zero(
        hasher_flag.clone()
            * cols.s0.clone()
            * cols.is_boundary.clone()
            * (cols.is_boundary.clone() - AB::Expr::ONE),
    );
    // is_boundary booleanity on output rows (degree 5: hasher * (1-s0) * (1-s1) *
    // is_boundary * (is_boundary-1))
    builder.assert_zero(
        hasher_flag
            * (AB::Expr::ONE - cols.s0.clone())
            * (AB::Expr::ONE - cols.s1.clone())
            * cols.is_boundary.clone()
            * (cols.is_boundary.clone() - AB::Expr::ONE),
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
    cols: &HasherExprs<AB::Expr>,
    cols_next: &HasherExprs<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // 1. First-row boundary: row 0 must be a controller input row.
    // Enforce both s0=1 and perm_seg=0 in a single constraint:
    // s0 * (1 - perm_seg) = 1.
    //
    // This is stronger than (1 - s0) + perm_seg = 0 as s0 can carry witness
    // values on permutation rows: if perm_seg=1 the left-hand side is 0, so the
    // constraint cannot be satisfied; thus perm_seg=0 and s0=1.
    builder
        .when_first_row()
        .when(hasher_flag.clone())
        .assert_zero(cols.s0.clone() * (AB::Expr::ONE - cols.perm_seg.clone()) - AB::Expr::ONE);

    // 2. Output non-adjacency: output row cannot be followed by another output row.
    // Degree: 7 (hasher * ctrl * (1-s0) * (1-s1) * ctrl_next * (1-s0_next) * (1-s1_next))
    let output_flag = hasher_flag.clone()
        * cols.controller_flag()
        * (AB::Expr::ONE - cols.s0.clone())
        * (AB::Expr::ONE - cols.s1.clone());
    let next_is_output = cols_next.controller_flag()
        * (AB::Expr::ONE - cols_next.s0.clone())
        * (AB::Expr::ONE - cols_next.s1.clone());
    builder.assert_zero(output_flag * next_is_output);

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
    builder.assert_zero(padding_flag.clone() * next_is_controller.clone() * cols_next.s0.clone());

    // (4) No output row (s1_next=0) after padding.
    builder.assert_zero(padding_flag * next_is_controller * (AB::Expr::ONE - cols_next.s1.clone()));
}
