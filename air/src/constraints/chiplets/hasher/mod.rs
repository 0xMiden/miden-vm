//! Hasher chiplet constraints.
//!
//! The hasher chiplet uses a dispatch/compute split architecture:
//! - The **hasher controller** (dispatch, `perm_seg=0`) records permutation requests as
//!   compact (input, output) row pairs and responds to the chiplets bus.
//! - The **hasher permutation segment** (compute, `perm_seg=1`) executes Poseidon2
//!   permutations as 32-row cycles, one per unique input state.
//!
//! A LogUp perm-link bus on the shared `v_wiring` column binds the two regions.
//!
//! ## Sub-modules
//!
//! - [`flags`]: Operation flag computation functions (pure selector expressions)
//! - [`periodic`]: Periodic column definitions (cycle markers, round constants)
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
//! | is_start     | 1 on first input of operation |
//! | is_final     | 1 on last output of operation |
//! | perm_seg     | 0 = hasher controller, 1 = hasher permutation segment |

pub mod flags;
pub mod merkle;
pub mod periodic;
pub mod selectors;
pub mod state;

use miden_core::field::PrimeCharacteristicRing;
pub use periodic::{STATE_WIDTH, periodic_columns};

use crate::{
    Felt, MainTraceRow,
    constraints::tagging::{
        TagGroup, TaggingAirBuilderExt, ids::TAG_CHIPLETS_BASE, tagged_assert_zero,
    },
    trace::{
        CHIPLETS_OFFSET,
        chiplets::{
            HASHER_IS_FINAL_COL_IDX, HASHER_IS_START_COL_IDX, HASHER_MRUPDATE_ID_COL_IDX,
            HASHER_NODE_INDEX_COL_IDX, HASHER_PERM_SEG_COL_IDX, HASHER_SELECTOR_COL_RANGE,
            HASHER_STATE_COL_RANGE,
        },
    },
};

// TAGGING IDS
// ================================================================================================

// Tag IDs must follow constraint emission order (ascending) in enforce_hasher_constraints.
// Emission order: selector_bool -> perm_seg -> structural -> lifecycle -> controller_adj
//   -> controller_pairing -> perm_steps(init,ext,int) -> mrupdate -> sponge_cap
//   -> output_idx -> merkle_index -> merkle_input_state
pub(super) const HASHER_BASE_ID: usize = TAG_CHIPLETS_BASE + 10;
pub(super) const HASHER_SELECTOR_BOOL_BASE_ID: usize = HASHER_BASE_ID;
pub(super) const HASHER_PERM_SEG_BASE_ID: usize = HASHER_SELECTOR_BOOL_BASE_ID + 3;
pub(super) const HASHER_STRUCTURAL_BASE_ID: usize = HASHER_PERM_SEG_BASE_ID + 7;
pub(super) const HASHER_LIFECYCLE_BASE_ID: usize = HASHER_STRUCTURAL_BASE_ID + 5;
pub(super) const HASHER_CONTROLLER_ADJ_BASE_ID: usize = HASHER_LIFECYCLE_BASE_ID + 2;
pub(super) const HASHER_CONTROLLER_PAIRING_BASE_ID: usize = HASHER_CONTROLLER_ADJ_BASE_ID + 2;
pub(super) const HASHER_PERM_INIT_BASE_ID: usize = HASHER_CONTROLLER_PAIRING_BASE_ID + 4;
pub(super) const HASHER_PERM_EXT_BASE_ID: usize = HASHER_PERM_INIT_BASE_ID + STATE_WIDTH;
pub(super) const HASHER_PERM_INT_BASE_ID: usize = HASHER_PERM_EXT_BASE_ID + STATE_WIDTH;
pub(super) const HASHER_MRUPDATE_ID_BASE_ID: usize = HASHER_PERM_INT_BASE_ID + STATE_WIDTH;
pub(super) const HASHER_SPONGE_CAP_BASE_ID: usize = HASHER_MRUPDATE_ID_BASE_ID + 2;
pub(super) const HASHER_OUTPUT_IDX_ID: usize = HASHER_SPONGE_CAP_BASE_ID + 4;
pub(super) const HASHER_MERKLE_INDEX_BASE_ID: usize = HASHER_OUTPUT_IDX_ID + 1;
pub(super) const HASHER_MERKLE_INPUT_STATE_BASE_ID: usize = HASHER_MERKLE_INDEX_BASE_ID + 3;

const OUTPUT_INDEX_NAMESPACE: &str = "chiplets.hasher.output.index";
const MRUPDATE_NAMESPACE: &str = "chiplets.hasher.mrupdate_id";

const MRUPDATE_NAMES: [&str; 2] = [MRUPDATE_NAMESPACE; 2];

const MRUPDATE_TAGS: TagGroup = TagGroup {
    base: HASHER_MRUPDATE_ID_BASE_ID,
    names: &MRUPDATE_NAMES,
};

// HASHER COLUMNS
// ================================================================================================

/// Typed access to hasher chiplet columns.
pub struct HasherColumns<E> {
    pub s0: E,
    pub s1: E,
    pub s2: E,
    pub state: [E; STATE_WIDTH],
    pub node_index: E,
    pub mrupdate_id: E,
    pub is_start: E,
    pub is_final: E,
    pub perm_seg: E,
}

// STATE REGION INDICES
// ================================================================================================

/// Start index of RATE0 region in the hasher state array.
const RATE0_START: usize = 0;
/// Start index of RATE1 region in the hasher state array.
const RATE1_START: usize = 4;
/// Start index of CAPACITY region in the hasher state array.
const CAPACITY_START: usize = 8;

impl<E: Clone> HasherColumns<E> {
    /// Extract hasher columns from a main trace row.
    pub fn from_row<V>(row: &MainTraceRow<V>) -> Self
    where
        V: Into<E> + Clone,
    {
        let s_start = HASHER_SELECTOR_COL_RANGE.start - CHIPLETS_OFFSET;
        let h_start = HASHER_STATE_COL_RANGE.start - CHIPLETS_OFFSET;
        let idx_col = HASHER_NODE_INDEX_COL_IDX - CHIPLETS_OFFSET;
        let mrupdate_col = HASHER_MRUPDATE_ID_COL_IDX - CHIPLETS_OFFSET;
        let is_start_col = HASHER_IS_START_COL_IDX - CHIPLETS_OFFSET;
        let is_final_col = HASHER_IS_FINAL_COL_IDX - CHIPLETS_OFFSET;
        let perm_seg_col = HASHER_PERM_SEG_COL_IDX - CHIPLETS_OFFSET;

        HasherColumns {
            s0: row.chiplets[s_start].clone().into(),
            s1: row.chiplets[s_start + 1].clone().into(),
            s2: row.chiplets[s_start + 2].clone().into(),
            state: core::array::from_fn(|i| row.chiplets[h_start + i].clone().into()),
            node_index: row.chiplets[idx_col].clone().into(),
            mrupdate_id: row.chiplets[mrupdate_col].clone().into(),
            is_start: row.chiplets[is_start_col].clone().into(),
            is_final: row.chiplets[is_final_col].clone().into(),
            perm_seg: row.chiplets[perm_seg_col].clone().into(),
        }
    }

    /// Returns the digest (first 4 state elements). Same as `rate0()` since the
    /// Poseidon2 digest is always in the first rate word.
    #[inline]
    #[allow(dead_code)]
    pub fn digest(&self) -> [E; 4] {
        self.rate0()
    }

    #[inline]
    #[allow(dead_code)]
    pub fn rate0(&self) -> [E; 4] {
        core::array::from_fn(|i| self.state[RATE0_START + i].clone())
    }

    #[inline]
    #[allow(dead_code)]
    pub fn rate1(&self) -> [E; 4] {
        core::array::from_fn(|i| self.state[RATE1_START + i].clone())
    }

    #[inline]
    pub fn capacity(&self) -> [E; 4] {
        core::array::from_fn(|i| self.state[CAPACITY_START + i].clone())
    }
}

impl<E: PrimeCharacteristicRing + Clone> HasherColumns<E> {
    /// Returns the controller flag (1 on controller rows, 0 on perm segment rows).
    #[inline]
    pub fn controller_flag(&self) -> E {
        E::ONE - self.perm_seg.clone()
    }
}

// ENTRY POINT
// ================================================================================================

/// Enforce all hasher chiplet constraints.
///
/// The hasher chiplet is active when `chiplets[0] = 0` (i.e., `!s0` at the chiplet level).
pub fn enforce_hasher_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let periodic: [AB::PeriodicVar; periodic::NUM_PERIODIC_COLUMNS] = {
        let periodic = builder.periodic_values();
        debug_assert!(
            periodic.len() >= periodic::NUM_PERIODIC_COLUMNS,
            "not enough periodic values for hasher constraints"
        );
        core::array::from_fn(|i| periodic[i])
    };

    let hasher_flag: AB::Expr = AB::Expr::ONE - local.chiplets[0].clone().into();
    let cols: HasherColumns<AB::Expr> = HasherColumns::from_row(local);
    let cols_next: HasherColumns<AB::Expr> = HasherColumns::from_row(next);

    // --- Selector booleanity (controller rows only; perm segment selectors are don't-care) ---
    selectors::enforce_selector_booleanity(builder, hasher_flag.clone(), &cols);

    // --- perm_seg constraints ---
    let hasher_flag_next: AB::Expr =
        AB::Expr::ONE - Into::<AB::Expr>::into(next.chiplets[0].clone());
    let cycle_row_31: AB::Expr = periodic[periodic::P_CYCLE_ROW_31].into();
    selectors::enforce_perm_seg_constraints(
        builder,
        hasher_flag.clone(),
        hasher_flag_next,
        &cols,
        &cols_next,
        cycle_row_31,
    );

    // --- Structural confinement (is_start, is_final) ---
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
    state::enforce_permutation_steps(builder, perm_gate, &cols.state, &cols_next.state, &periodic);

    // --- mrupdate_id constraints ---
    enforce_mrupdate_id_constraints(builder, hasher_flag.clone(), &cols, &cols_next);

    // --- Sponge capacity preservation ---
    enforce_respan_capacity(builder, hasher_flag.clone(), next, &cols, &cols_next);

    // --- Tree constraints ---
    merkle::enforce_node_index_constraints(builder, hasher_flag.clone(), &cols, &cols_next);
    merkle::enforce_merkle_input_state(builder, hasher_flag, &cols);
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
    cols: &HasherColumns<AB::Expr>,
    cols_next: &HasherColumns<AB::Expr>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let controller_flag = cols.controller_flag();
    let controller_flag_next = cols_next.controller_flag();

    // f_mv_start_next: MV input on next row with is_start=1.
    let f_mv_next = flags::f_mv(cols_next.s0.clone(), cols_next.s1.clone(), cols_next.s2.clone());
    let f_mv_start_next = f_mv_next * cols_next.is_start.clone();

    // On controller->controller transitions: id_next = id + f_mv_start_next.
    // controller_flag_next in the outer gate prevents firing at the controller->perm boundary.
    // Degree 7: hasher_flag(1) * controller_flag(1) * controller_flag_next(1)
    //           * (id_next - id - f_mv_start_next) where f_mv_start is degree 4.
    let mut idx = 0;
    tagged_assert_zero(
        builder,
        &MRUPDATE_TAGS,
        &mut idx,
        hasher_flag.clone()
            * controller_flag
            * controller_flag_next
            * (cols_next.mrupdate_id.clone() - cols.mrupdate_id.clone() - f_mv_start_next),
    );

    // On perm segment rows: mrupdate_id = 0
    // Degree 3: hasher_flag(1) * perm_seg(1) * mrupdate_id(1).
    tagged_assert_zero(
        builder,
        &MRUPDATE_TAGS,
        &mut idx,
        hasher_flag * cols.perm_seg.clone() * cols.mrupdate_id.clone(),
    );
}

/// Enforces capacity preservation across LINEAR_HASH continuation boundaries.
///
/// When the next row is a LINEAR_HASH continuation input (f_sponge_next=1, is_start_next=0),
/// the capacity h[8..12] must be preserved from the current row to the next.
///
/// ## Gate (degree 7)
///
/// `hasher_flag * hasher_flag_next * f_sponge_next * (1 - is_start_next)` * state_diff
///
/// - `hasher_flag_next` ensures the next row's columns are hasher columns (not garbage from another
///   chiplet at a boundary).
/// - `f_sponge_next` is needed to restrict to LINEAR_HASH continuations only.
fn enforce_respan_capacity<AB>(
    builder: &mut AB,
    hasher_flag: AB::Expr,
    next: &MainTraceRow<AB::Var>,
    cols: &HasherColumns<AB::Expr>,
    cols_next: &HasherColumns<AB::Expr>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // hasher_flag_next: next row is also a hasher row
    let hasher_flag_next: AB::Expr =
        AB::Expr::ONE - Into::<AB::Expr>::into(next.chiplets[0].clone());

    // f_sponge_next: next row is a sponge-mode input (s0=1, s1=0, s2=0)
    let f_sponge_next =
        flags::f_sponge(cols_next.s0.clone(), cols_next.s1.clone(), cols_next.s2.clone());

    // Gate degree: hasher_flag(1) * hasher_flag_next(1) * f_sponge_next(3) * (1-is_start)(1) = 6.
    // Constraint degree: gate(6) * state_diff(1) = 7.
    let gate = hasher_flag
        * hasher_flag_next
        * f_sponge_next
        * (AB::Expr::ONE - cols_next.is_start.clone());

    state::enforce_respan_capacity_preservation(
        builder,
        gate,
        &cols.capacity(),
        &cols_next.capacity(),
    );
}
