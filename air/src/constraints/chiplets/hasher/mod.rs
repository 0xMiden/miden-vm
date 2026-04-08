//! Hasher chiplet constraints.
//!
//! The hasher chiplet uses a dispatch/compute split architecture:
//! - The **hasher controller** (dispatch, `perm_seg=0`) records permutation requests as compact
//!   (input, output) row pairs and responds to the chiplets bus.
//! - The **hasher permutation segment** (compute, `perm_seg=1`) executes Poseidon2 permutations as
//!   16-row cycles, one per unique input state.
//!
//! A LogUp perm-link bus on the shared `v_wiring` column binds the two regions.
//!
//! ## Sub-modules
//!
//! - [`flags`]: Operation flag computation functions (pure selector expressions)
//! - [`selectors`]: Selector, structural, and lifecycle constraints
//! - [`state`]: Poseidon2 round transition constraints (permutation segment only)
//! - [`merkle`]: Merkle tree operation constraints (controller only)
//!
//! ## Column Layout (20 columns)
//!
//! | Column       | Purpose |
//! |--------------|---------|
//! | s0, s1, s2   | Selectors (operation type / row type) |
//! | h[0..12)     | Hasher state (RATE0, RATE1, CAP) |
//! | node_index   | Merkle tree node index on controller rows; reused for request multiplicity on perm segment rows |
//! | mrupdate_id  | Domain separator for sibling table |
//! | is_boundary  | 1 on boundary rows (first input or last output) |
//! | direction_bit| Merkle direction bit (0 on non-Merkle / perm rows) |
//! | perm_seg     | 0 = hasher controller, 1 = hasher permutation segment |

pub mod flags;
pub mod merkle;
pub mod selectors;
pub mod state;

use core::borrow::Borrow;

use miden_core::field::PrimeCharacteristicRing;

pub use crate::trace::chiplets::hasher::STATE_WIDTH;
use crate::{
    MainCols, MidenAirBuilder,
    constraints::chiplets::columns::{HasherCols, HasherPeriodicCols, PeriodicCols},
};

// HASHER EXPRESSION WRAPPER
// ================================================================================================

/// Expression-level view of hasher columns, created by converting from `HasherCols<AB::Var>`.
///
/// This provides the same field names as the old `HasherColumns<E>` type, allowing constraint
/// code to work with `AB::Expr` values.
pub struct HasherExprs<E> {
    pub s0: E,
    pub s1: E,
    pub s2: E,
    pub state: [E; STATE_WIDTH],
    pub node_index: E,
    pub mrupdate_id: E,
    pub is_boundary: E,
    pub direction_bit: E,
    pub perm_seg: E,
}

impl<E: Clone> HasherExprs<E> {
    #[inline]
    pub fn rate0(&self) -> [E; 4] {
        core::array::from_fn(|i| self.state[i].clone())
    }

    #[inline]
    pub fn rate1(&self) -> [E; 4] {
        core::array::from_fn(|i| self.state[4 + i].clone())
    }

    #[inline]
    pub fn capacity(&self) -> [E; 4] {
        core::array::from_fn(|i| self.state[8 + i].clone())
    }
}

impl<E: PrimeCharacteristicRing + Clone> HasherExprs<E> {
    /// Returns the controller flag (1 on controller rows, 0 on perm segment rows).
    #[inline]
    pub fn controller_flag(&self) -> E {
        E::ONE - self.perm_seg.clone()
    }
}

/// Convert `HasherCols<Var>` to `HasherExprs<Expr>` for use in constraint expressions.
fn hasher_exprs<AB: MidenAirBuilder>(cols: &HasherCols<AB::Var>) -> HasherExprs<AB::Expr> {
    HasherExprs {
        s0: cols.selectors[0].into(),
        s1: cols.selectors[1].into(),
        s2: cols.selectors[2].into(),
        state: core::array::from_fn(|i| cols.state[i].into()),
        node_index: cols.node_index.into(),
        mrupdate_id: cols.mrupdate_id.into(),
        is_boundary: cols.is_boundary.into(),
        direction_bit: cols.direction_bit.into(),
        perm_seg: cols.perm_seg.into(),
    }
}

// ENTRY POINT
// ================================================================================================

/// Enforce all hasher chiplet constraints.
///
/// The hasher chiplet is active when `chiplets[0] = 0` (i.e., `!s0` at the chiplet level).
pub fn enforce_hasher_constraints<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // Extract periodic columns into local copies to avoid borrow conflicts.
    let periodic_hasher: HasherPeriodicCols<AB::PeriodicVar> = {
        let periodic: &PeriodicCols<AB::PeriodicVar> = builder.periodic_values().borrow();
        periodic.hasher
    };

    let hasher_flag: AB::Expr =
        AB::Expr::ONE - Into::<AB::Expr>::into(local.chiplet_selectors()[0]);
    let cols = hasher_exprs::<AB>(local.hasher());
    let cols_next = hasher_exprs::<AB>(next.hasher());

    // --- Selector booleanity (controller rows only; perm segment selectors are don't-care) ---
    selectors::enforce_selector_booleanity(builder, hasher_flag.clone(), &cols);

    // --- perm_seg constraints ---
    let hasher_flag_next: AB::Expr =
        AB::Expr::ONE - Into::<AB::Expr>::into(next.chiplet_selectors()[0]);
    // Derive (1 - cycle_row_15) = selector_sum. The boundary row (row 15) is the
    // only row where all 4 selectors are 0. The perm_seg constraints use this in the
    // form (1 - cycle_row_N) to gate multiplicity constancy and cycle alignment.
    let selector_sum: AB::Expr = Into::<AB::Expr>::into(periodic_hasher.is_init_ext)
        + Into::<AB::Expr>::into(periodic_hasher.is_ext)
        + Into::<AB::Expr>::into(periodic_hasher.is_packed_int)
        + Into::<AB::Expr>::into(periodic_hasher.is_int_ext);
    selectors::enforce_perm_seg_constraints(
        builder,
        hasher_flag.clone(),
        hasher_flag_next,
        &cols,
        &cols_next,
        selector_sum,
    );

    // --- Structural confinement (is_boundary, direction_bit) ---
    selectors::enforce_structural_confinement(builder, hasher_flag.clone(), &cols);

    // --- Lifecycle booleanity ---
    selectors::enforce_lifecycle_booleanity(builder, hasher_flag.clone(), &cols);

    // --- Controller adjacency (input -> output) ---
    selectors::enforce_controller_adjacency(builder, hasher_flag.clone(), &cols, &cols_next);

    // --- Controller pairing (first-row boundary + output non-adjacency) ---
    selectors::enforce_controller_pairing(builder, hasher_flag.clone(), &cols, &cols_next);

    // --- Permutation step constraints (perm segment only) ---
    // Gate by perm_seg alone (degree 1), NOT hasher_flag * perm_seg (degree 2).
    // This is sound because `enforce_perm_seg_constraints` explicitly confines perm_seg to
    // hasher rows: (1 - hasher_flag) * perm_seg = 0. Keeping the gate at degree 1 is critical:
    // the S-box has degree 7, and with the periodic selector (degree 1), the total constraint
    // degree is 1 + 1 + 7 = 9, which matches the system's max degree.
    let perm_gate = cols.perm_seg.clone();
    // On permutation rows, s0/s1/s2 serve as witness columns for packed internal rounds.
    let witnesses: [AB::Expr; 3] = [cols.s0.clone(), cols.s1.clone(), cols.s2.clone()];
    state::enforce_permutation_steps(
        builder,
        perm_gate,
        &cols.state,
        &cols_next.state,
        &witnesses,
        &periodic_hasher,
    );

    // --- mrupdate_id constraints ---
    enforce_mrupdate_id_constraints(builder, hasher_flag.clone(), &cols, &cols_next);

    // --- Sponge capacity preservation ---
    enforce_respan_capacity(builder, hasher_flag.clone(), next, &cols, &cols_next);

    // --- Tree constraints ---
    merkle::enforce_node_index_constraints(builder, hasher_flag.clone(), &cols, &cols_next);
    merkle::enforce_merkle_input_state(builder, hasher_flag.clone(), &cols);
    merkle::enforce_merkle_digest_routing(builder, hasher_flag, &cols, &cols_next);
}

// INTERNAL CONSTRAINT FUNCTIONS
// ================================================================================================

/// Enforces mrupdate_id progression and zero-on-perm constraints.
///
/// On controller rows: mrupdate_id increments by 1 on MV start rows, stays constant otherwise.
/// On perm segment rows: mrupdate_id must be zero.
fn enforce_mrupdate_id_constraints<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    cols: &HasherExprs<AB::Expr>,
    cols_next: &HasherExprs<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let controller_flag = cols.controller_flag();
    let controller_flag_next = cols_next.controller_flag();

    // f_mv_start_next: MV input on next row with is_boundary=1.
    let f_mv_next = flags::f_mv(cols_next.s0.clone(), cols_next.s1.clone(), cols_next.s2.clone());
    let f_mv_start_next = f_mv_next * cols_next.is_boundary.clone();

    // On controller->controller transitions: id_next = id + f_mv_start_next.
    // controller_flag_next in the outer gate prevents firing at the controller->perm boundary.
    // Degree 7: hasher_flag(1) * controller_flag(1) * controller_flag_next(1)
    //           * (id_next - id - f_mv_start_next) where f_mv_start is degree 4.
    builder.assert_zero(
        hasher_flag.clone()
            * controller_flag
            * controller_flag_next
            * (cols_next.mrupdate_id.clone() - cols.mrupdate_id.clone() - f_mv_start_next),
    );

    // On perm segment rows: mrupdate_id = 0
    // Degree 3: hasher_flag(1) * perm_seg(1) * mrupdate_id(1).
    builder.assert_zero(hasher_flag * cols.perm_seg.clone() * cols.mrupdate_id.clone());
}

/// Enforces capacity preservation across LINEAR_HASH continuation boundaries.
///
/// When the next row is a LINEAR_HASH continuation input (f_sponge_next=1, is_boundary_next=0),
/// the capacity h[8..12] must be preserved from the current row to the next.
///
/// ## Gate (degree 7)
///
/// `hasher_flag * hasher_flag_next * f_sponge_next * (1 - is_boundary_next)` * state_diff
///
/// - `hasher_flag_next` ensures the next row's columns are hasher columns (not garbage from another
///   chiplet at a boundary).
/// - `f_sponge_next` is needed to restrict to LINEAR_HASH continuations only.
fn enforce_respan_capacity<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    next: &MainCols<AB::Var>,
    cols: &HasherExprs<AB::Expr>,
    cols_next: &HasherExprs<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // hasher_flag_next: next row is also a hasher row
    let hasher_flag_next: AB::Expr =
        AB::Expr::ONE - Into::<AB::Expr>::into(next.chiplet_selectors()[0]);

    // f_sponge_next: next row is a sponge-mode controller input (s0=1, s1=0, s2=0).
    // Must also check controller_flag_next because on perm rows s0/s1/s2 hold witness
    // values (not selectors), and a witness could accidentally match the sponge pattern.
    let controller_flag_next = cols_next.controller_flag();
    let f_sponge_next =
        flags::f_sponge(cols_next.s0.clone(), cols_next.s1.clone(), cols_next.s2.clone());

    // Gate degree: hasher_flag(1) * hasher_flag_next(1) * controller_flag_next(1)
    //              * f_sponge_next(3) * (1-is_boundary)(1) = 7.
    // Constraint degree: gate(7) * state_diff(1) = 8.
    let gate = hasher_flag
        * hasher_flag_next
        * controller_flag_next
        * f_sponge_next
        * (AB::Expr::ONE - cols_next.is_boundary.clone());

    state::enforce_respan_capacity_preservation(
        builder,
        gate,
        &cols.capacity(),
        &cols_next.capacity(),
    );
}
