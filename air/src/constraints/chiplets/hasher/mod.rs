//! Hasher chiplet constraints.
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
//! ## Column Layout (within chiplet, offset by selectors)
//!
//! | Column   | Purpose |
//! |----------|---------|
//! | s[0..2]  | Selector flags |
//! | h[0..12) | Hasher state (RATE0, RATE1, CAP) |
//! | i        | Node index (for Merkle operations) |
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
    constraints::tagging::{TaggingAirBuilderExt, ids::TAG_CHIPLETS_BASE},
    trace::{
        CHIPLETS_OFFSET,
        chiplets::{HASHER_NODE_INDEX_COL_IDX, HASHER_SELECTOR_COL_RANGE, HASHER_STATE_COL_RANGE},
    },
};

// TAGGING IDS
// ================================================================================================

/// Base ID for hasher chiplet constraints (next after chiplet selectors).
pub(super) const HASHER_BASE_ID: usize = TAG_CHIPLETS_BASE + 10;
pub(super) const HASHER_PERM_INIT_BASE_ID: usize = HASHER_BASE_ID;
pub(super) const HASHER_PERM_EXT_BASE_ID: usize = HASHER_PERM_INIT_BASE_ID + STATE_WIDTH;
pub(super) const HASHER_PERM_INT_BASE_ID: usize = HASHER_PERM_EXT_BASE_ID + STATE_WIDTH;
pub(super) const HASHER_SELECTOR_BOOL_BASE_ID: usize = HASHER_PERM_INT_BASE_ID + STATE_WIDTH;
pub(super) const HASHER_SELECTOR_CONSIST_BASE_ID: usize = HASHER_SELECTOR_BOOL_BASE_ID + 3;
pub(super) const HASHER_ABP_BASE_ID: usize = HASHER_SELECTOR_CONSIST_BASE_ID + 4;
pub(super) const HASHER_OUTPUT_IDX_ID: usize = HASHER_ABP_BASE_ID + 4;
pub(super) const HASHER_MERKLE_INDEX_BASE_ID: usize = HASHER_OUTPUT_IDX_ID + 1;
pub(super) const HASHER_MERKLE_ABSORB_BASE_ID: usize = HASHER_MERKLE_INDEX_BASE_ID + 2;

const OUTPUT_INDEX_NAMESPACE: &str = "chiplets.hasher.output.index";

/// Precomputed hasher flags derived from selectors and cycle markers.
struct HasherFlags<E> {
    pub cycle_row_31: E,
    pub f_abp: E,
    pub f_mpa: E,
    pub f_mva: E,
    pub f_mua: E,
    pub f_out: E,
    pub f_out_next: E,
    pub f_mp: E,
    pub f_mv: E,
    pub f_mu: E,
}

impl<E: PrimeCharacteristicRing + Clone> HasherFlags<E> {
    #[inline]
    fn f_merkle_active(&self) -> E {
        flags::f_merkle_active(
            self.f_mp.clone(),
            self.f_mv.clone(),
            self.f_mu.clone(),
            self.f_mpa.clone(),
            self.f_mva.clone(),
            self.f_mua.clone(),
        )
    }

    #[inline]
    fn f_merkle_absorb(&self) -> E {
        flags::f_merkle_absorb(self.f_mpa.clone(), self.f_mva.clone(), self.f_mua.clone())
    }

    #[inline]
    fn f_continuation(&self) -> E {
        flags::f_continuation(
            self.f_abp.clone(),
            self.f_mpa.clone(),
            self.f_mva.clone(),
            self.f_mua.clone(),
        )
    }
}

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
    pub fn from_row<V>(row: &MainTraceRow<V>) -> Self
    where
        V: Into<E> + Clone,
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

struct HasherContext<AB: TaggingAirBuilderExt<F = Felt>> {
    pub cols: HasherColumns<AB::Expr>,
    pub cols_next: HasherColumns<AB::Expr>,
    pub flags: HasherFlags<AB::Expr>,
    pub hasher_flag: AB::Expr,
    pub periodic: [AB::PeriodicVal; periodic::NUM_PERIODIC_COLUMNS],
}

impl<AB> HasherContext<AB>
where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    pub fn new(
        builder: &mut AB,
        local: &MainTraceRow<AB::Var>,
        next: &MainTraceRow<AB::Var>,
    ) -> Self {
        let periodic: [AB::PeriodicVal; periodic::NUM_PERIODIC_COLUMNS] = {
            let periodic = builder.periodic_evals();
            debug_assert!(
                periodic.len() >= periodic::NUM_PERIODIC_COLUMNS,
                "not enough periodic values for hasher constraints"
            );
            core::array::from_fn(|i| periodic[i])
        };

        let hasher_flag: AB::Expr = AB::Expr::ONE - local.chiplets[0].clone().into();
        let cols: HasherColumns<AB::Expr> = HasherColumns::from_row(local);
        let cols_next: HasherColumns<AB::Expr> = HasherColumns::from_row(next);
        let flags = compute_hasher_flags::<AB>(&periodic, &cols, &cols_next);

        HasherContext::<AB> {
            cols,
            cols_next,
            flags,
            hasher_flag,
            periodic,
        }
    }
}

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
    AB: TaggingAirBuilderExt<F = Felt>,
{
    let ctx = HasherContext::<AB>::new(builder, local, next);

    enforce_permutation(builder, &ctx);
    // Enforce selector booleanity using raw vars.
    let cols_var: HasherColumns<AB::Var> = HasherColumns::<AB::Var>::from_row(local);
    selectors::enforce_selector_booleanity(
        builder,
        ctx.hasher_flag.clone(),
        cols_var.s0,
        cols_var.s1,
        cols_var.s2,
    );
    enforce_selector_consistency(builder, &ctx);
    enforce_abp_capacity(builder, &ctx);
    enforce_merkle_constraints(builder, &ctx);
}

// INTERNAL HELPERS
// ================================================================================================

/// Enforce Poseidon2 permutation step constraints.
///
/// Delegates to [`state::enforce_permutation_steps`] with proper column extraction.
fn enforce_permutation<AB>(builder: &mut AB, ctx: &HasherContext<AB>)
where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // Enforce permutation steps
    state::enforce_permutation_steps(
        builder,
        ctx.hasher_flag.clone(),
        &ctx.cols.state,
        &ctx.cols_next.state,
        &ctx.periodic,
    );
}

/// Enforce selector consistency constraints.
///
/// Delegates to [`selectors::enforce_selector_consistency`] with proper column extraction.
fn enforce_selector_consistency<AB>(builder: &mut AB, ctx: &HasherContext<AB>)
where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    selectors::enforce_selector_consistency(
        builder,
        ctx.hasher_flag.clone(),
        &ctx.cols,
        &ctx.cols_next,
        &ctx.flags,
    );
}

/// Enforce ABP capacity preservation on row 31 of the cycle.
fn enforce_abp_capacity<AB>(builder: &mut AB, ctx: &HasherContext<AB>)
where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    state::enforce_abp_capacity_preservation(
        builder,
        ctx.hasher_flag.clone(),
        ctx.flags.f_abp.clone(),
        &ctx.cols.capacity(),
        &ctx.cols_next.capacity(),
    );
}

/// Enforce Merkle path constraints.
///
/// Delegates to [`merkle`] module functions for index and state constraints.
fn enforce_merkle_constraints<AB>(builder: &mut AB, ctx: &HasherContext<AB>)
where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // Node index constraints
    merkle::enforce_node_index_constraints(
        builder,
        ctx.hasher_flag.clone(),
        &ctx.cols,
        &ctx.cols_next,
        &ctx.flags,
    );

    // Merkle absorb state constraints
    merkle::enforce_merkle_absorb_state(
        builder,
        ctx.hasher_flag.clone(),
        &ctx.cols,
        &ctx.cols_next,
        &ctx.flags,
    );
}

fn compute_hasher_flags<AB>(
    periodic: &[AB::PeriodicVal],
    cols: &HasherColumns<AB::Expr>,
    cols_next: &HasherColumns<AB::Expr>,
) -> HasherFlags<AB::Expr>
where
    AB: MidenAirBuilder<F = Felt>,
{
    let cycle_row_31: AB::Expr = periodic[periodic::P_CYCLE_ROW_31].into();

    let cycle_row_0: AB::Expr = periodic[periodic::P_CYCLE_ROW_0].into();
    let cycle_row_30: AB::Expr = periodic[periodic::P_CYCLE_ROW_30].into();

    let s0 = cols.s0.clone();
    let s1 = cols.s1.clone();
    let s2 = cols.s2.clone();
    let s0_next = cols_next.s0.clone();
    let s1_next = cols_next.s1.clone();

    let f_mp = flags::f_mp(cycle_row_0.clone(), s0.clone(), s1.clone(), s2.clone());
    let f_mv = flags::f_mv(cycle_row_0.clone(), s0.clone(), s1.clone(), s2.clone());
    let f_mu = flags::f_mu(cycle_row_0.clone(), s0.clone(), s1.clone(), s2.clone());

    let f_abp = flags::f_abp(cycle_row_31.clone(), s0.clone(), s1.clone(), s2.clone());
    let f_mpa = flags::f_mpa(cycle_row_31.clone(), s0.clone(), s1.clone(), s2.clone());
    let f_mva = flags::f_mva(cycle_row_31.clone(), s0.clone(), s1.clone(), s2.clone());
    let f_mua = flags::f_mua(cycle_row_31.clone(), s0.clone(), s1.clone(), s2.clone());

    let f_out = flags::f_out(cycle_row_31.clone(), s0, s1.clone());
    let f_out_next = flags::f_out_next(cycle_row_30, s0_next, s1_next);

    HasherFlags {
        cycle_row_31,
        f_abp,
        f_mpa,
        f_mva,
        f_mua,
        f_out,
        f_out_next,
        f_mp,
        f_mv,
        f_mu,
    }
}
