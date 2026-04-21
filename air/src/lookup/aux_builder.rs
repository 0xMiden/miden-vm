//! Generic LogUp aux-trace helper.
//!
//! Composes the field-polymorphic [`build_lookup_fractions`] collection phase with
//! [`accumulate`] and splits the result into `(aux_trace, committed_finals)`. Miden-side
//! callers wrap this helper by sourcing the periodic columns + challenges shape from their
//! own static layout.
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
//! - `committed_finals` is `[acc_final, ZERO]`: the accumulator's terminal value from the
//!   `num_rows`-th row, padded with a zero element for the MASM recursive verifier which absorbs
//!   exactly 2 boundary values. TODO(#3032): remove the zero padding once trace splitting lands and
//!   each sub-trace has its own accumulator.

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
    challenges: &Challenges<EF>,
) -> (RowMajorMatrix<EF>, Vec<EF>)
where
    F: Field,
    EF: ExtensionField<F>,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, F, EF>>,
{
    let fractions = build_lookup_fractions(air, main, periodic_columns, challenges);

    let full = accumulate(&fractions);
    let num_cols = full.width;
    let num_rows = main.height();
    debug_assert_eq!(
        full.values.len(),
        (num_rows + 1) * num_cols,
        "accumulate output buffer is sized for num_rows + 1 rows",
    );

    let mut data = full.values;
    let last_row: Vec<EF> = data.split_off(num_rows * num_cols);
    debug_assert_eq!(last_row.len(), num_cols);

    // TODO(#3032): Only col 0 is a real committed final. Pad with ZERO for the MASM
    // recursive verifier which absorbs 2 boundary values. Remove padding once trace
    // splitting lands and each trace has its own accumulator.
    let committed: Vec<EF> = vec![last_row[0], EF::ZERO];

    let aux_trace = RowMajorMatrix::new(data, num_cols);
    (aux_trace, committed)
}
