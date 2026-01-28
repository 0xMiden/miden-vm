//! Hasher chiplet constraints (Poseidon2, 32-row cycle).
//!
//! This module implements constraints for the hasher chiplet, organized into sub-modules:
//!
//! - [`flags`]: Operation flag computation functions
//! - [`periodic`]: Periodic column definitions (cycle markers, round constants)
//! - [`selectors`]: Selector logic constraints
//! - [`state`]: Permutation state constraints
//! - [`merkle`]: Merkle tree operation constraints
//!
//! ## Hasher Operations
//!
//! The hasher supports:
//! 1. Single permutation of Poseidon2
//! 2. 2-to-1 hash (merge)
//! 3. Linear hash of n field elements
//! 4. Merkle path verification
//! 5. Merkle root update
//!
//! ## Column Layout
//!
//! | Columns | Purpose |
//! |---------|---------|
//! | s[0..2] | Selector flags |
//! | h[0..12) | Hasher state (RATE0, RATE1, CAP) |
//! | i       | Node index (for Merkle operations) |
//!
//! ## References
//!
//! - [Hasher chiplet design](https://0xmiden.github.io/miden-vm/design/chiplets/hasher.html)

pub mod flags;
pub mod merkle;
pub mod periodic;
pub mod selectors;
pub mod state;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;
// Re-export commonly used items
pub use periodic::{STATE_WIDTH, periodic_columns};

use crate::{
    Felt, MainTraceRow,
    trace::{
        CHIPLETS_OFFSET,
        chiplets::{HASHER_NODE_INDEX_COL_IDX, HASHER_SELECTOR_COL_RANGE, HASHER_STATE_COL_RANGE},
    },
};

// ENTRY POINTS
// ================================================================================================

/// Enforce all hasher chiplet constraints.
///
/// This is the main entry point for hasher constraints, enforcing:
/// 1. Permutation step constraints
/// 2. Selector constraints
/// 3. Boundary constraints
/// 4. Merkle operation constraints
///
/// ## Chiplet Activation
///
/// The hasher chiplet is active when `chiplets[0] = 0` (i.e., `!s0` at the chiplet level).
pub fn enforce_hasher_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    let periodic: [AB::PeriodicVal; periodic::NUM_PERIODIC_COLUMNS] = {
        let periodic = builder.periodic_evals();
        debug_assert!(
            periodic.len() >= periodic::NUM_PERIODIC_COLUMNS,
            "not enough periodic values for hasher constraints"
        );
        core::array::from_fn(|i| periodic[i])
    };

    // Pre-compute common flags once for efficiency
    let hasher_flag: AB::Expr = AB::Expr::ONE - local.chiplets[0].clone().into();
    let transition_flag = hasher_flag.clone() * builder.is_transition();

    enforce_permutation(builder, local, next, &hasher_flag, &periodic);
    enforce_selector_consistency(builder, local, next, &hasher_flag, &periodic);
    enforce_boundary_constraints(builder, local, next, &hasher_flag, &transition_flag, &periodic);
    enforce_merkle_constraints(builder, local, next, &transition_flag, &periodic);
}

// INTERNAL HELPERS
// ================================================================================================

/// Typed access to hasher chiplet columns.
///
/// This struct provides named access to hasher columns, eliminating error-prone
/// index arithmetic. Created from a `MainTraceRow` reference.
///
/// ## Layout
/// - `s0, s1, s2`: Selector columns determining operation type
/// - `state[0..12]`: Poseidon2 state (RATE0[0..4], RATE1[4..8], CAP[8..12])
/// - `node_index`: Merkle tree node index
pub struct HasherColumns<E> {
    /// Selector 0
    pub s0: E,
    /// Selector 1
    pub s1: E,
    /// Selector 2
    pub s2: E,
    /// Full Poseidon2 state (12 elements)
    pub state: [E; STATE_WIDTH],
    /// Node index for Merkle operations
    pub node_index: E,
}

impl<E: Clone> HasherColumns<E> {
    /// Extract hasher columns from a main trace row.
    pub fn from_row<AB>(row: &MainTraceRow<AB::Var>) -> Self
    where
        AB: MidenAirBuilder<F = Felt>,
        AB::Var: Into<E> + Clone,
    {
        let s_start = HASHER_SELECTOR_COL_RANGE.start - CHIPLETS_OFFSET;
        let h_start = HASHER_STATE_COL_RANGE.start - CHIPLETS_OFFSET;
        let idx_col = HASHER_NODE_INDEX_COL_IDX - CHIPLETS_OFFSET;

        HasherColumns {
            s0: row.chiplets[s_start].clone().into(),
            s1: row.chiplets[s_start + 1].clone().into(),
            s2: row.chiplets[s_start + 2].clone().into(),
            state: core::array::from_fn(|i| row.chiplets[h_start + i].clone().into()),
            node_index: row.chiplets[idx_col].clone().into(),
        }
    }

    /// Get the digest (first 4 elements of state, same as rate0).
    #[inline]
    pub fn digest(&self) -> [E; 4] {
        core::array::from_fn(|i| self.state[i].clone())
    }

    /// Get rate0 (state[0..4]).
    #[inline]
    pub fn rate0(&self) -> [E; 4] {
        core::array::from_fn(|i| self.state[i].clone())
    }

    /// Get rate1 (state[4..8]).
    #[inline]
    pub fn rate1(&self) -> [E; 4] {
        core::array::from_fn(|i| self.state[4 + i].clone())
    }

    /// Get capacity (state[8..12]).
    #[inline]
    pub fn capacity(&self) -> [E; 4] {
        core::array::from_fn(|i| self.state[8 + i].clone())
    }
}

/// Enforce Poseidon2 permutation step constraints.
///
/// Delegates to [`state::enforce_permutation_steps`] with proper column extraction.
fn enforce_permutation<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    hasher_flag: &AB::Expr,
    periodic: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Only enforce on transition rows
    let step_gate = hasher_flag.clone() * builder.is_transition();

    // Load hasher columns using typed struct
    let cols: HasherColumns<AB::Expr> = HasherColumns::from_row::<AB>(local);
    let cols_next: HasherColumns<AB::Expr> = HasherColumns::from_row::<AB>(next);

    // Enforce permutation steps
    state::enforce_permutation_steps(
        builder,
        step_gate.clone(),
        &cols.state,
        &cols_next.state,
        periodic,
    );

    // Enforce selector booleanity.
    // Uses raw chiplet columns because `assert_bools` requires vars (not exprs).
    let s_start = HASHER_SELECTOR_COL_RANGE.start - CHIPLETS_OFFSET;
    selectors::enforce_selector_booleanity(
        builder,
        step_gate,
        local.chiplets[s_start].clone(),
        local.chiplets[s_start + 1].clone(),
        local.chiplets[s_start + 2].clone(),
    );
}

/// Enforce selector consistency constraints.
///
/// Delegates to [`selectors::enforce_selector_consistency`] with proper column extraction.
fn enforce_selector_consistency<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    hasher_flag: &AB::Expr,
    periodic: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Load hasher columns using typed struct
    let cols: HasherColumns<AB::Expr> = HasherColumns::from_row::<AB>(local);
    let cols_next: HasherColumns<AB::Expr> = HasherColumns::from_row::<AB>(next);

    selectors::enforce_selector_consistency(
        builder,
        hasher_flag.clone(),
        cols.s0,
        cols.s1,
        cols.s2,
        cols_next.s0,
        cols_next.s1,
        cols_next.s2,
        periodic,
    );
}

/// Enforce boundary constraints on row 31 of the hasher cycle.
///
/// - **ABP**: Capacity lanes preserved across transition
/// - **Output**: Node index must be zero
fn enforce_boundary_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    hasher_flag: &AB::Expr,
    transition_flag: &AB::Expr,
    periodic: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Periodic values (base field)
    let cycle_row_31: AB::Expr = periodic[periodic::P_CYCLE_ROW_31].into();

    // Load hasher columns using typed struct
    let cols: HasherColumns<AB::Expr> = HasherColumns::from_row::<AB>(local);
    let cols_next: HasherColumns<AB::Expr> = HasherColumns::from_row::<AB>(next);

    // f_abp: ABP = row31 & s0 & !s1 & !s2
    let f_abp =
        flags::f_abp(cycle_row_31.clone(), cols.s0.clone(), cols.s1.clone(), cols.s2.clone());

    // f_out: output row (HOUT or SOUT) = row31 & !s0 & !s1
    let f_out = flags::f_out(cycle_row_31, cols.s0.clone(), cols.s1.clone());

    // ABP preserves capacity lanes
    state::enforce_abp_capacity_preservation(
        builder,
        transition_flag.clone(),
        f_abp,
        &cols.capacity(),
        &cols_next.capacity(),
    );

    // Output requires index = 0
    builder.assert_zero(hasher_flag.clone() * f_out * cols.node_index.clone());
}

/// Enforce Merkle path constraints.
///
/// Delegates to [`merkle`] module functions for index and state constraints.
fn enforce_merkle_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    transition_flag: &AB::Expr,
    periodic: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Load hasher columns using typed struct
    let cols: HasherColumns<AB::Expr> = HasherColumns::from_row::<AB>(local);
    let cols_next: HasherColumns<AB::Expr> = HasherColumns::from_row::<AB>(next);

    // Node index constraints
    merkle::enforce_node_index_constraints(
        builder,
        transition_flag.clone(),
        cols.s0.clone(),
        cols.s1.clone(),
        cols.s2.clone(),
        cols.node_index.clone(),
        cols_next.node_index.clone(),
        periodic,
    );

    // Merkle absorb state constraints
    merkle::enforce_merkle_absorb_state(
        builder,
        transition_flag.clone(),
        cols.s0.clone(),
        cols.s1.clone(),
        cols.s2.clone(),
        cols.node_index.clone(),
        cols_next.node_index.clone(),
        &cols.digest(),
        &cols_next.rate0(),
        &cols_next.rate1(),
        &cols_next.capacity(),
        periodic,
    );
}
