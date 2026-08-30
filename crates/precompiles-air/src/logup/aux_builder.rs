//! Prover-side normalized LogUp aux-trace driver.
//!
//! The shared [`miden_air::lookup::build_logup_aux_trace`] returns the centered cyclic trace and
//! `sigma_prime = sigma / n`; this module passes both through unchanged so PVM and Miden AIRs use
//! the same committed-value convention.

use alloc::vec::Vec;

use miden_core::{
    field::{ExtensionField, Field},
    utils::RowMajorMatrix,
};
use miden_lifted_air::LiftedAir;

use super::{LookupAir, ProverLookupBuilder};

/// Prover-side LogUp aux-trace body for `LiftedAir + LookupAir` chiplets.
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
    // PVM lookups read preprocessed columns from `main` itself (BytePairLut prepends its fixed
    // table), so no separate preprocessed window is supplied.
    miden_air::lookup::build_logup_aux_trace_with_preprocessed(air, main, None, challenges)
}

#[cfg(test)]
mod tests {
    use miden_air::lookup::accumulate_slow;
    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
        utils::Matrix,
    };
    use miden_lifted_air::BaseAir;

    use super::*;
    use crate::{
        logup::{build_lookup_fractions, lookup_challenges_from_slice},
        primitives::byte_pair_lut::BytePairLutAir,
    };

    #[test]
    fn shared_builder_trace_matches_slow_accumulation() {
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
        let fractions = build_lookup_fractions(&air, &main, None, &[], &lookup_challenges);
        let (expected, mean) = accumulate_slow(&fractions);
        let (actual, aux_values) = build_logup_aux_trace(&air, &main, &challenges);

        assert_eq!(aux_values, [mean]);
        assert_eq!(actual.height(), num_rows);
        assert_eq!(actual.width(), expected.len());
        for (row_idx, row) in actual.values.chunks_exact(actual.width()).enumerate() {
            for (column, &value) in row.iter().enumerate() {
                assert_eq!(value, expected[column][row_idx]);
            }
        }
    }
}
