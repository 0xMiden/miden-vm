//! PVM LogUp integration using normalized cyclic running sums.
//!
//! Reuses the Miden VM's closure-based lookup framework (`LookupAir`, `LookupBuilder`,
//! `LookupColumn`, `LookupGroup`, `LookupBatch`, `LookupMessage`, `Challenges`,
//! `LookupFractions`, `accumulate`) and follows the same centered accumulator convention as the
//! Miden AIRs. The local constraint builder adds support for combined preprocessed/main windows
//! and excludes trailing non-LogUp auxiliary registers from the running sum.
//!
//! ## Closing the running sum
//!
//! Let `t(r)` be the sum of every LogUp fraction assigned to row `r`,
//! `sigma = sum_r t(r)`, and `sigma_prime = sigma / n` for an `n`-row trace. Column 0 is centered
//! by `sigma_prime` and closes cyclically, including the last-to-first edge:
//!
//! ```text
//! when_first:    acc[0] = 0
//! every row:     D₀·(acc_next[0] − Σ_{i<L} acc[i] + sigma_prime) − N₀ = 0
//! every row i>0: D_i·acc[i] − N_i = 0
//! ```
//!
//! where `sigma_prime` lives at `permutation_values()[0]` and `L = num_logup_cols` bounds the sum
//! to the LogUp columns. Trailing Schwartz-Zippel register columns are excluded. Summing the
//! recurrence over the cyclic domain proves `n * sigma_prime = sigma`, including lookup activity
//! on the last row. No padding row or per-AIR `inv_n` public input is required.
//!
//! [`build_logup_aux_trace`] runs the shared `build_lookup_fractions` and `accumulate` routines,
//! returning the centered trace and committed `sigma_prime`. The cross-AIR closure reconstructs
//! each raw sum by weighting every committed value by its trace length.
//!
//! ## Encoding
//!
//! Encoding is delegated to [`Challenges`]:
//!
//! ```text
//! encode(bus, elems) = bus_prefix[bus] + Σ β^i · elems[i]
//! bus_prefix[bus]    = α + (bus + 1) · β^W
//! ```
//!
//! where `W = `[`MAX_MESSAGE_WIDTH`]. Distinct bus ids live on disjoint
//! `β^W`-spaced offsets, so two `(bus, payload)` pairs collide only on
//! a vanishing-probability subset of `(α, β)`.
//!
//! [`lookup_challenges_from_slice`] builds a `Challenges<QuadFelt>` from
//! the flat `[α, β]` slice that `LiftedAir::build_aux_trace` is given —
//! sized to [`MAX_MESSAGE_WIDTH`] / [`NUM_BUS_IDS`] so prover and
//! verifier see identical prefixes.

mod aux_builder;
mod constraint;

/// Emit one **flattened** LogUp column — a single batch of its fractions —
/// inside a chiplet's `LookupAir::eval` (where the builder param is `LB` and
/// the `LookupColumn` / `LookupGroup` / `LookupBatch` traits are in scope).
///
/// Each fraction is `(name, multiplicity, message, deg)`. The column packing determines the
/// resulting constraint degree; column 0 is also the centered cyclic accumulator. `$cd` is the
/// (ignored, on the constraint path) column-degree hint.
macro_rules! frac_col {
    ($builder:expr, $group:expr, $cd:expr, $( ($name:expr, $mult:expr, $msg:expr, $deg:expr) ),+ $(,)?) => {
        $builder.next_column(
            |col| {
                col.group($group, |g| {
                    g.batch("f", LB::Expr::ONE, |b| {
                        $( b.insert($name, $mult, $msg, $deg); )+
                    }, $cd);
                }, $cd);
            },
            $cd,
        );
    };
}
pub use aux_builder::build_logup_aux_trace;
pub use constraint::{
    CombinedWindow, CyclicConstraintBatch, CyclicConstraintColumn, CyclicConstraintGroup,
    CyclicConstraintLookupBuilder, LookupMainWindow,
};
pub(crate) use frac_col;
// Re-export miden-vm's framework so chiplets only need one `use`.
pub use miden_air::lookup::{
    BoundaryBuilder, Challenges, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
    LookupFractions, LookupGroup, LookupMessage, ProverLookupBuilder, accumulate,
    build_lookup_fractions,
};
use miden_core::field::QuadFelt;

use crate::relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS};

// CHALLENGES
// ================================================================================================

/// Number of extension-field challenges drawn by the verifier — one
/// global `(α, β)` pair, shared across every relation.
pub const NUM_RANDOMNESS: usize = 2;

/// Build a `Challenges<QuadFelt>` from the flat `[α, β]` slice handed to
/// `LiftedAir::build_aux_trace`.
///
/// Sizes the precomputed tables to [`MAX_MESSAGE_WIDTH`] /
/// [`NUM_BUS_IDS`] so prover and verifier see identical prefixes.
pub fn lookup_challenges_from_slice(s: &[QuadFelt]) -> Challenges<QuadFelt> {
    debug_assert!(
        s.len() >= NUM_RANDOMNESS,
        "expected at least {NUM_RANDOMNESS} challenges, got {}",
        s.len(),
    );
    Challenges::new(s[0], s[1], MAX_MESSAGE_WIDTH, NUM_BUS_IDS)
}

// PUBLIC-INPUT LAYOUT
// ================================================================================================

/// Number of base-field public inputs the VM exposes: the 4-felt
/// transcript root (an Eidos digest).
///
/// Every chiplet declares the same public-input count. Only the transcript-eval chip reads the
/// root, pinning its row-0 hash to `public_values()[0..4]`. Trace lengths are supplied to the
/// external multi-AIR closure and are not duplicated in the AIR public inputs.
pub const NUM_PUBLIC_VALUES: usize = 4;

// COMMITTED LOGUP-VALUE CONTRACT
// ================================================================================================

/// Number of normalized LogUp values exposed by each non-composite chiplet: exactly one
/// `sigma_prime = sigma / n`. Auxiliary column counts vary per chiplet; composite AIRs expose one
/// normalized value per component.
pub const NUM_LOGUP_VALUES: usize = 1;
