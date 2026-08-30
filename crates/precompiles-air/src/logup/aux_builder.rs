//! Prover-side normalized LogUp aux-trace driver.
//!
//! Fraction collection and accumulation reuse the Miden VM's [`build_lookup_fractions`] and
//! [`accumulate`]. The shared accumulator returns the centered cyclic trace and
//! `sigma_prime = sigma / n`; this module preserves both unchanged so PVM and Miden AIRs use the
//! same committed-value convention.

use alloc::{vec, vec::Vec};

use miden_core::{
    field::{ExtensionField, Field},
    utils::{Matrix, RowMajorMatrix},
};
use miden_lifted_air::LiftedAir;

use super::{Challenges, LookupAir, ProverLookupBuilder, accumulate, build_lookup_fractions};

/// Prover-side LogUp aux-trace body for `LiftedAir + LookupAir` chiplets.
///
/// Sources `α`, `β`, `max_message_width`, `num_bus_ids`, and the periodic columns from the AIR's
/// trait methods, then runs the shared fraction-collection and normalized accumulation phases.
///
/// Returns `(aux_trace, vec![sigma_prime])`, where `sigma_prime = sigma / main.height()`. The
/// external multi-AIR closure weights this value by the trace length to reconstruct the AIR's full
/// LogUp sum.
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

    // Preprocessed columns are already prepended to `main` by the only AIR which uses them
    // (BytePairLut); passing them a second time would shift its lookup column indices.
    let fractions = build_lookup_fractions(air, main, None, &periodic, &lookup_challenges);

    let (aux_trace, sigma_prime) = accumulate(&fractions);
    debug_assert_eq!(aux_trace.height(), main.height());

    (aux_trace, vec![sigma_prime])
}
