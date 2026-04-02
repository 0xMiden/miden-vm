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
use miden_crypto::stark::air::AirBuilder;
// Re-export commonly used items
pub use periodic::{STATE_WIDTH, periodic_columns};

use crate::{
    MainTraceRow, MidenAirBuilder,
    constraints::chiplets::selectors::ChipletFlags,
    trace::{HasherCols, chiplets::borrow_chiplet},
};

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

// ================================================================================================
// COMPOSITE FLAGS
// ================================================================================================

impl<E: PrimeCharacteristicRing> HasherFlags<E> {
    /// Merkle operation active flag.
    ///
    /// True when any Merkle operation (MP, MV, MU, MPA, MVA, MUA) is active.
    /// Used for gating index shift constraints.
    ///
    /// # Degree
    /// - Depends on constituent flags, typically 4
    #[inline]
    fn f_merkle_active(&self) -> E {
        self.f_mp.clone()
            + self.f_mv.clone()
            + self.f_mu.clone()
            + self.f_mpa.clone()
            + self.f_mva.clone()
            + self.f_mua.clone()
    }

    /// Merkle absorb flag (row 31 only).
    ///
    /// True when absorbing the next node during Merkle path computation.
    ///
    /// # Degree
    /// - Depends on constituent flags, typically 4
    #[inline]
    fn f_merkle_absorb(&self) -> E {
        self.f_mpa.clone() + self.f_mva.clone() + self.f_mua.clone()
    }

    /// Continuation flag for hashing operations.
    ///
    /// True when operation continues to next cycle (ABP, MPA, MVA, MUA).
    /// Constrains s0' = 0 to ensure proper sequencing.
    ///
    /// # Degree
    /// - Depends on constituent flags, typically 4
    #[inline]
    fn f_continuation(&self) -> E {
        self.f_abp.clone() + self.f_mpa.clone() + self.f_mva.clone() + self.f_mua.clone()
    }
}

struct HasherContext<'a, AB: MidenAirBuilder> {
    pub cols: &'a HasherCols<AB::Var>,
    pub cols_next: &'a HasherCols<AB::Var>,
    pub flags: HasherFlags<AB::Expr>,
    pub hasher_flag: AB::Expr,
    pub periodic: [AB::PeriodicVar; periodic::NUM_PERIODIC_COLUMNS],
}

impl<'a, AB> HasherContext<'a, AB>
where
    AB: MidenAirBuilder,
{
    pub fn new(
        builder: &mut AB,
        local: &'a MainTraceRow<AB::Var>,
        next: &'a MainTraceRow<AB::Var>,
        flags: &ChipletFlags<AB::Expr>,
    ) -> Self {
        let periodic: [AB::PeriodicVar; periodic::NUM_PERIODIC_COLUMNS] = {
            let periodic = builder.periodic_values();
            debug_assert!(
                periodic.len() >= periodic::NUM_PERIODIC_COLUMNS,
                "not enough periodic values for hasher constraints"
            );
            core::array::from_fn(|i| periodic[i])
        };

        let hasher_flag = flags.is_active.clone();
        let cols: &HasherCols<AB::Var> = borrow_chiplet(&local.chiplets[1..17]);
        let cols_next: &HasherCols<AB::Var> = borrow_chiplet(&next.chiplets[1..17]);
        let hasher_flags = compute_hasher_flags::<AB>(&periodic, cols, cols_next);

        HasherContext::<AB> {
            cols,
            cols_next,
            flags: hasher_flags,
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
    flags: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let ctx = HasherContext::<AB>::new(builder, local, next, flags);

    // Permutation step constraints
    {
        let state: [AB::Expr; STATE_WIDTH] = ctx.cols.state.map(Into::into);
        let state_next: [AB::Expr; STATE_WIDTH] = ctx.cols_next.state.map(Into::into);
        state::enforce_permutation_steps(
            builder,
            ctx.hasher_flag.clone(),
            &state,
            &state_next,
            &ctx.periodic,
        );
    }

    // Selector booleanity
    builder.when(ctx.hasher_flag.clone()).assert_bools(ctx.cols.selectors);

    // Selector consistency
    selectors::enforce_selector_consistency(
        builder,
        ctx.hasher_flag.clone(),
        ctx.cols,
        ctx.cols_next,
        &ctx.flags,
    );

    // ABP capacity preservation on row 31 of the cycle
    {
        let cap: [AB::Expr; 4] = ctx.cols.capacity().map(Into::into);
        let cap_next: [AB::Expr; 4] = ctx.cols_next.capacity().map(Into::into);
        state::enforce_abp_capacity_preservation(
            builder,
            ctx.hasher_flag.clone(),
            ctx.flags.f_abp.clone(),
            &cap,
            &cap_next,
        );
    }

    // Merkle node index constraints
    merkle::enforce_node_index_constraints(
        builder,
        ctx.hasher_flag.clone(),
        ctx.cols,
        ctx.cols_next,
        &ctx.flags,
    );

    // Merkle absorb state constraints
    merkle::enforce_merkle_absorb_state(
        builder,
        ctx.hasher_flag.clone(),
        ctx.cols,
        ctx.cols_next,
        &ctx.flags,
    );
}

fn compute_hasher_flags<AB>(
    periodic: &[AB::PeriodicVar],
    cols: &HasherCols<AB::Var>,
    cols_next: &HasherCols<AB::Var>,
) -> HasherFlags<AB::Expr>
where
    AB: MidenAirBuilder,
{
    let cycle_row_31: AB::Expr = periodic[periodic::P_CYCLE_ROW_31].into();

    let cycle_row_0: AB::Expr = periodic[periodic::P_CYCLE_ROW_0].into();
    let cycle_row_30: AB::Expr = periodic[periodic::P_CYCLE_ROW_30].into();

    let s0: AB::Expr = cols.selectors[0].into();
    let s1: AB::Expr = cols.selectors[1].into();
    let s2: AB::Expr = cols.selectors[2].into();
    let s0_next: AB::Expr = cols_next.selectors[0].into();
    let s1_next: AB::Expr = cols_next.selectors[1].into();

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
