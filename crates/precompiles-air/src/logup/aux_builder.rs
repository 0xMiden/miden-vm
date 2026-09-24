//! Prover-side LogUp aux-trace driver (natural last-row σ-closing).
//!
//! The shared [`miden_air::lookup::build_logup_aux_trace`] returns a centered cyclic trace and
//! `sigma_prime = sigma / n`; this adapter adds the per-row drift `r * sigma_prime` back into
//! column 0 to recover the plain running sum, then commits `sigma = n * sigma_prime`.
//!
//! The constraint side closes the plain running sum on the last row
//! (`when_last: D₀·(σ − Σ acc) − N₀ = 0`, see `constraint.rs`), so no normalized drift term appears
//! in the precompile AIR constraints and no reserved dead row is needed.

use alloc::vec::Vec;

use miden_core::{
    field::{ExtensionField, Field},
    utils::{Matrix, RowMajorMatrix},
};
use miden_lifted_air::LiftedAir;

use super::{LookupAir, ProverLookupBuilder};

/// Return the plain running-sum trace and its full LogUp residue in `aux_values[0]`.
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
    let (mut aux_trace, mut aux_values) =
        miden_air::lookup::build_logup_aux_trace(air, main, challenges);
    let sigma_prime = aux_values[0];
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

    aux_values[0] = drift;
    (aux_trace, aux_values)
}

#[cfg(test)]
mod tests {
    use miden_air::lookup::accumulate_slow;
    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
    };
    use miden_lifted_air::BaseAir;

    use super::*;
    use crate::{
        logup::{build_lookup_fractions, lookup_challenges_from_slice},
        primitives::byte_pair_lut::BytePairLutAir,
    };

    #[test]
    fn shared_builder_preserves_plain_running_sum() {
        let air = BytePairLutAir;
        let num_rows = 1025;
        let width = air.preprocessed_width() + air.width();
        let mut main = RowMajorMatrix::new(
            (0..num_rows * width).map(|i| Felt::from_usize(i % 17 + 1)).collect(),
            width,
        );
        // Keep a zero-contribution middle block and a live final row.
        main.values[512 * width..1024 * width].fill(Felt::ZERO);
        let challenges = [QuadFelt::new([Felt::from_u32(7), Felt::ONE]), QuadFelt::from_u32(13)];
        let lookup_challenges = lookup_challenges_from_slice(&challenges);
        let fractions = build_lookup_fractions(&air, &main, &[], &lookup_challenges);
        let (expected, mean) = accumulate_slow(&fractions);
        let (actual, aux_values) = build_logup_aux_trace(&air, &main, &challenges);

        assert_eq!(aux_values, [mean * QuadFelt::from_usize(num_rows)]);
        assert_eq!(actual.height(), num_rows);
        assert_eq!(actual.width(), expected.len());
        for (row_idx, row) in actual.values.chunks_exact(actual.width()).enumerate() {
            assert_eq!(row[0], expected[0][row_idx] + QuadFelt::from_usize(row_idx) * mean);
            for (column, &value) in row.iter().enumerate().skip(1) {
                assert_eq!(value, expected[column][row_idx]);
            }
        }
    }
}
