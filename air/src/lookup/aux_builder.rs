//! Generic LogUp aux-trace helper.
//!
//! Composes the field-polymorphic [`build_lookup_fractions`] collection phase with
//! [`accumulate`] and splits the result into `(aux_trace, committed_finals)`. The
//! Miden-side [`MidenLookupAuxBuilder`](crate::constraints::lookup::MidenLookupAuxBuilder)
//! wraps this helper by sourcing the periodic columns + challenges shape from Miden's
//! static layout.
//!
//! ## Aux trace shape
//!
//! [`accumulate`] returns a [`RowMajorMatrix`] with `num_rows + 1` rows:
//!
//! - row 0 is the all-`ZERO` initial accumulator
//! - row `r` (for `1..=num_rows`) holds the running sum **after** row `r − 1`'s fraction
//!   contributions have been folded in
//! - row `num_rows` is therefore the global running sum across the entire trace
//!
//! The return value splits that matrix in two:
//!
//! - `aux_trace` is the first `num_rows` rows of the accumulator — it starts at `ZERO` and ends at
//!   the running sum **before** the last row's contribution. The last row's fraction contribution
//!   does **not** appear in the aux trace.
//! - `committed_finals` is the `num_rows`-th row of the accumulator (one `EF` per column) — the
//!   full running sum across the entire trace, observed by the Fiat-Shamir challenger.

use alloc::vec::Vec;

use miden_core::{
    field::{ExtensionField, Field},
    utils::{Matrix, RowMajorMatrix},
};

use super::{
    Challenges, LookupAir, ProverLookupBuilder, accumulate, prover::build_lookup_fractions,
};

/// Run the collection + accumulation phases for `air` over `main` and return the LogUp
/// aux trace plus the committed final values.
///
/// Generic over the base field `F` and extension field `EF`. The caller supplies the
/// precomputed [`Challenges<EF>`] and the periodic-column vectors; this function does
/// not read a static constant layout.
pub fn build_logup_aux<A, F, EF>(
    air: &A,
    main: &RowMajorMatrix<F>,
    periodic_columns: &[Vec<F>],
    public_values: &[F],
    challenges: &Challenges<EF>,
) -> (RowMajorMatrix<EF>, Vec<EF>)
where
    F: Field,
    EF: ExtensionField<F>,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, F, EF>>,
{
    let fractions = build_lookup_fractions(air, main, periodic_columns, public_values, challenges);

    let full = accumulate(&fractions);
    let num_cols = full.width;
    let num_rows = main.height();
    debug_assert_eq!(
        full.values.len(),
        (num_rows + 1) * num_cols,
        "accumulate output buffer is sized for num_rows + 1 rows",
    );

    let mut data = full.values;
    let committed: Vec<EF> = data.split_off(num_rows * num_cols);
    debug_assert_eq!(committed.len(), num_cols);

    let aux_trace = RowMajorMatrix::new(data, num_cols);
    (aux_trace, committed)
}
