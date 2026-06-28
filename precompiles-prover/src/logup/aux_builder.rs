//! Prover-side LogUp aux-trace driver (natural last-row σ-closing).
//!
//! Adapted from miden-vm `air/src/lookup/aux_builder.rs::build_logup_aux_trace`
//! at commit `3176d1f`. The fraction-collection ([`build_lookup_fractions`])
//! and accumulation ([`accumulate`]) phases are reused unchanged; only the
//! column-0 handling differs:
//!
//! - Stock miden: take the running sum's terminal as `committed_final`, truncate the (n+1)-row
//!   matrix to n rows, and return `(aux_trace, vec![committed_final])`.
//! - Here: take that same terminal as `σ = Σ_r delta_r` and return it verbatim — column 0 is the
//!   plain running sum (`aux[0] = 0`, `aux[r] = Σ_{i<r} delta_i`). The constraint side closes it on
//!   the last row (`when_last: D₀·(σ − Σ acc) − N₀ = 0`, see `constraint.rs`), so no `σ/n` drift
//!   correction and no reserved dead row are needed.

use miden_core::{
    field::{ExtensionField, Field},
    utils::{Matrix, RowMajorMatrix},
};
use miden_lifted_air::LiftedAir;

use super::{Challenges, LookupAir, ProverLookupBuilder, accumulate, build_lookup_fractions};

/// Prover-side LogUp aux-trace body for `LiftedAir + LookupAir`
/// chiplets (natural last-row σ-closing).
///
/// Sources `α`, `β`, `max_message_width`, `num_bus_ids`, and the
/// periodic columns from the AIR's trait methods, runs miden-vm's stock
/// fraction-collection + fused-accumulator phases, and returns column 0
/// as the plain running sum (no σ/n correction).
///
/// Returns `(aux_trace, vec![sigma])`. The single committed permutation
/// value is σ — the AIR's full LogUp residue, summed across AIRs and
/// asserted zero by `MultiAir::eval_external`.
pub fn build_logup_aux_trace<A, F, EF>(
    air: &A,
    main: &RowMajorMatrix<F>,
    challenges: &[EF],
) -> (RowMajorMatrix<EF>, Vec<EF>)
where
    F: Field,
    EF: ExtensionField<F>,
    A: LiftedAir<F, EF>,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, F, EF>>,
{
    let alpha = challenges[0];
    let beta = challenges[1];
    let lookup_challenges =
        Challenges::<EF>::new(alpha, beta, air.max_message_width(), air.num_bus_ids());
    let periodic = air.periodic_columns();

    let fractions = build_lookup_fractions(air, main, &periodic, &lookup_challenges);

    let full = accumulate(&fractions);
    let num_cols = full.width;
    let num_rows = main.height();
    debug_assert_eq!(
        full.values.len(),
        (num_rows + 1) * num_cols,
        "accumulate output buffer is sized for num_rows + 1 rows",
    );

    // Take σ from col 0 of the trailing row (= Σ_r delta_r), then
    // truncate to num_rows. No σ/n correction: column 0 is the plain
    // running sum (row r = Σ_{i<r} delta_i, with aux[0] = 0). The natural
    // last-row closing constraint folds the final row's interactions into
    // the committed σ — `when_last: D₀·(σ − Σ acc) − N₀ = 0` (see
    // `constraint.rs`); the per-AIR quotient degree of 0.26 absorbs its
    // degree, so no dead row and no σ/n drift are needed.
    let mut data = full.values;
    let sigma = data[num_rows * num_cols];
    data.truncate(num_rows * num_cols);

    let aux_trace = RowMajorMatrix::new(data, num_cols);
    (aux_trace, vec![sigma])
}
