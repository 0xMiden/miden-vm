//! Prover-side LogUp aux-trace driver (natural last-row σ-closing).
//!
//! Fraction collection and accumulation reuse miden-vm's [`build_lookup_fractions`] and
//! [`accumulate`]. The shared accumulator returns a centered cyclic trace and
//! `sigma_prime = sigma / n`; this adapter adds the per-row drift `r * sigma_prime` back into
//! column 0 to recover the plain running sum, then commits `sigma = n * sigma_prime`.
//!
//! The constraint side closes the plain running sum on the last row
//! (`when_last: D₀·(σ − Σ acc) − N₀ = 0`, see `constraint.rs`), so no normalized drift term appears
//! in the precompile AIR constraints and no reserved dead row is needed.

use alloc::{vec, vec::Vec};

use miden_core::{
    field::{ExtensionField, Field},
    utils::{Matrix, RowMajorMatrix},
};
use miden_lifted_air::LiftedAir;

use super::{Challenges, LookupAir, ProverLookupBuilder, accumulate, build_lookup_fractions};

/// Prover-side LogUp aux-trace body for `LiftedAir + LookupAir`
/// chiplets (natural last-row σ-closing).
///
/// Sources `α`, `β`, `max_message_width`, `num_bus_ids`, and the periodic columns from the AIR's
/// trait methods, runs miden-vm's fraction-collection and normalized fused-accumulator phases,
/// then removes the centering from column 0.
///
/// Returns `(aux_trace, vec![sigma])`. The single committed permutation value is `sigma` — the
/// AIR's full LogUp residue, summed across AIRs and asserted zero by `MultiAir::eval_external`.
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

    let (mut aux_trace, sigma_prime) = accumulate(&fractions);
    let num_cols = aux_trace.width;
    let num_rows = main.height();
    debug_assert_eq!(aux_trace.height(), num_rows);

    // The shared accumulator stores `centered[r] = plain[r] - r * sigma_prime`. Restore the plain
    // running sum expected by the natural last-row constraint with an add-only drift scan. After
    // the final row, `drift = n * sigma_prime = sigma`.
    let mut drift = EF::ZERO;
    for row in 0..num_rows {
        aux_trace.values[row * num_cols] += drift;
        drift += sigma_prime;
    }

    (aux_trace, vec![drift])
}
