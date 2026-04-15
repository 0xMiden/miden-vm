//! Stateless [`AuxBuilder`] for the LogUp lookup argument.
//!
//! [`MidenLookupAuxBuilder`] is the prover-side glue between the closure-based
//! [`MidenLookupAir`] and the upstream `p3-miden-lifted-air` STARK harness. It
//! is a zero-sized type with no per-trace state: `build_aux_trace` walks the
//! main trace through [`build_lookup_fractions`] and feeds the result through
//! [`accumulate`] to produce the LogUp aux trace.
//!
//! ## Aux trace shape (Milestone B, decision D1)
//!
//! [`accumulate`] returns a [`RowMajorMatrix`] with `num_rows + 1` rows:
//!
//! - row 0 is the all-`ZERO` initial accumulator
//! - row `r` (for `1..=num_rows`) holds the running sum **after** row `r − 1`'s fraction
//!   contributions have been folded in
//! - row `num_rows` is therefore the global running sum across the entire trace
//!
//! The [`AuxBuilder`] return splits that matrix in two:
//!
//! - `aux_trace` is the first `num_rows` rows of the accumulator — it starts at `ZERO` and ends at
//!   the running sum **before** the last row's contribution. The last row's fraction contribution
//!   does **not** appear in the aux trace.
//! - `committed_finals` is the `num_rows`-th row of the accumulator (one `EF` per column = "width
//!   of the trace") — the full running sum across the entire trace, observed by the Fiat-Shamir
//!   challenger.
//!
//! ## Public values (Milestone B, decision D5)
//!
//! The [`AuxBuilder`] trait does not thread `public_values` through to
//! `build_aux_trace`, so `build_lookup_fractions` is invoked with `&[]`. This
//! is sound for the current LogUp setup because the prover-path bus emitters
//! at `air/src/constraints/lookup/buses/*.rs` do not read
//! `builder.public_values()` — verified by grep in the milestone B exploration
//! pass. Restoring per-row public-input access (e.g. for boundary correction
//! terms on open buses) is a follow-up milestone.
//!
//! ## LogUp boundaries
//!
//! Milestone B intentionally **disables** the LogUp boundary / transition
//! constraints (see the commented-out block in
//! [`super::constraint::ConstraintColumn::column`]). The aux trace is still
//! committed and observed by the challenger so the integration plumbing can be
//! exercised end-to-end, but the symbolic LogUp algebra is not yet enforced.
//! A follow-up milestone will restore real boundary checks once the column
//! closure + public-input correction terms for open buses are designed.

use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::ExtensionField,
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::stark::air::AuxBuilder;

use super::{LookupAir, LookupChallenges, MidenLookupAir, accumulate, build_lookup_fractions};
use crate::constraints::chiplets::columns::PeriodicCols;

// MIDEN LOOKUP AUX BUILDER
// ================================================================================================

/// Stateless prover-side [`AuxBuilder`] for the Miden VM LogUp lookup argument.
///
/// Zero-sized — every call to [`MidenLookupAuxBuilder::build_aux_trace`] runs
/// the collection phase from scratch using only the inputs the trait provides.
#[derive(Copy, Clone, Debug, Default)]
pub struct MidenLookupAuxBuilder;

impl<EF> AuxBuilder<Felt, EF> for MidenLookupAuxBuilder
where
    EF: ExtensionField<Felt>,
{
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        let _span = tracing::info_span!("build_aux_trace_logup").entered();

        // The constraint-path adapter reads α/β out of `permutation_randomness()[0..2]`
        // (see `ConstraintLookupBuilder::new`) — match that ordering exactly so the
        // prover- and constraint-path challenges line up.
        let alpha = challenges[0];
        let beta = challenges[1];
        let lookup_challenges = LookupChallenges::<EF>::new(alpha, beta);

        // Periodic columns are part of the AIR's static layout — recomputing them per
        // call is cheap (a fixed set of `Vec<Felt>` constructors) and keeps the builder
        // stateless, matching `ProcessorAir::periodic_columns`.
        let periodic = PeriodicCols::periodic_columns();

        // D5: the `AuxBuilder` trait does not thread public values through. Empty slice
        // is safe today because no prover-path bus emitter reads `public_values()` —
        // see the module doc for details.
        let fractions =
            build_lookup_fractions(&MidenLookupAir, main, &periodic, &[], &lookup_challenges);

        // `accumulate` returns an `(num_rows + 1) × num_cols` matrix; row 0 is the zero
        // initial state and row `num_rows` is the full running sum across the trace.
        let full = accumulate(&fractions);
        let num_cols = full.width;
        let num_rows = main.height();
        debug_assert_eq!(
            full.values.len(),
            (num_rows + 1) * num_cols,
            "accumulate output buffer is sized for num_rows + 1 rows",
        );

        // D1: split the `(num_rows + 1) × num_cols` buffer into the aux trace
        // (rows `0..num_rows`) and the committed finals (row `num_rows`). The split is a
        // single `Vec::split_off` — no extra allocation, no element copies.
        let mut data = full.values;
        let committed: Vec<EF> = data.split_off(num_rows * num_cols);
        debug_assert_eq!(committed.len(), num_cols);
        let aux_trace = RowMajorMatrix::new(data, num_cols);
        debug_assert_eq!(aux_trace.values.len(), num_rows * num_cols);

        (aux_trace, committed)
    }
}
