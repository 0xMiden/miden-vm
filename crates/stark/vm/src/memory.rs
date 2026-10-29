//! Memory budgets for the production VM relation.

use miden_air::vm::{MIDEN_AIR_COUNT, MidenMultiAir};
use miden_core::{Felt, field::QuadFelt};
pub use miden_stark::memory::{ProverMemoryModel, ProvingBudget};
use miden_stark::pcs::PcsParams;

/// Derives the shared STARK model from generated production AIR metadata.
pub fn memory_model(params: &PcsParams) -> Option<ProverMemoryModel<MIDEN_AIR_COUNT>> {
    ProverMemoryModel::from_multi_air::<Felt, QuadFelt, _>(&MidenMultiAir::new(), params)
}

/// Estimates peak proving memory from padded heights in VM AIR order.
pub fn prover_peak_bytes(heights: &[usize; MIDEN_AIR_COUNT], params: &PcsParams) -> Option<u64> {
    memory_model(params)?.prover_peak_bytes(heights)
}

/// Default maximum estimated proving memory: 64 GiB.
pub const DEFAULT_MAX_PROVER_MEMORY_BYTES: u64 = 64 << 30;

/// Supplies the canonical VM model with the caller's byte limit.
pub fn canonical_budget(limit_bytes: u64) -> ProvingBudget<MIDEN_AIR_COUNT> {
    ProvingBudget::new(
        memory_model(&miden_air::vm::config::pcs_params()).expect("canonical VM memory model fits"),
        limit_bytes,
    )
}

/// Supplies the canonical VM model with its default byte limit.
pub fn default_budget() -> ProvingBudget<MIDEN_AIR_COUNT> {
    canonical_budget(DEFAULT_MAX_PROVER_MEMORY_BYTES)
}

#[cfg(test)]
mod tests {
    use miden_air::vm::{AIRS, BaseAir, LiftedAir, MidenAir, config::pcs_params};
    use miden_air_definitions::vm::trace::and8_lookup::AND8_LOOKUP_TRACE_HEIGHT;
    use miden_stark::log_quotient_degree;

    use super::*;

    /// Pinned bytes/row figures for the current AIR shape: Core, Chiplets, EidosCompression, and
    /// And8 have 48/24/108/7 main columns, 4/4/20/4 extension-field auxiliary columns, and
    /// quotient degrees 8/8/2/2 respectively, with blowup 8. A width, auxiliary-width, or
    /// quotient-degree change must break this test loudly rather than silently drift the model.
    #[test]
    fn pinned_bytes_for_current_air_shape() {
        let params = pcs_params();

        assert_eq!(
            AIRS,
            [
                MidenAir::CORE,
                MidenAir::CHIPLETS,
                MidenAir::EIDOS_COMPRESSION,
                MidenAir::AND8_LOOKUP,
            ]
        );
        assert_eq!(AIRS.map(|air| air.width()), [48, 24, 108, 7]);
        assert_eq!(
            AIRS.map(|air| <MidenAir as LiftedAir<Felt, QuadFelt>>::aux_width(&air)),
            [4, 4, 20, 4]
        );
        assert_eq!(AIRS.map(|air| log_quotient_degree::<Felt, QuadFelt, _>(&air)), [3, 3, 1, 1]);
        assert_eq!(AIRS.map(|air| BaseAir::<Felt>::preprocessed_width(&air)), [0, 0, 0, 5]);
        assert_eq!(params.log_blowup(), 3);
        assert_eq!(AND8_LOOKUP_TRACE_HEIGHT, 1 << 16);

        assert_eq!(prover_peak_bytes(&[1, 0, 0, 0], &params), Some(9920), "Core alone");
        assert_eq!(prover_peak_bytes(&[0, 1, 0, 0], &params), Some(7760), "Chiplets alone");
        assert_eq!(
            prover_peak_bytes(&[0, 0, 1, 0], &params),
            Some(18200),
            "EidosCompression alone"
        );
        assert_eq!(prover_peak_bytes(&[0, 0, 0, 1], &params), Some(9000), "And8Lookup alone");
        assert_eq!(prover_peak_bytes(&[1, 1, 1, 1], &params), Some(30240), "all four at height 1");
    }

    #[test]
    fn zero_heights_cost_nothing() {
        let params = pcs_params();
        assert_eq!(prover_peak_bytes(&[0, 0, 0, 0], &params), Some(0));
    }

    #[test]
    fn increasing_any_height_never_decreases_the_result() {
        let params = pcs_params();
        let base = [1_000usize, 2_000, 500, 65_536];
        let base_bytes = prover_peak_bytes(&base, &params).expect("fits in u64");
        for i in 0..MIDEN_AIR_COUNT {
            let mut bumped = base;
            bumped[i] += 1;
            let bumped_bytes = prover_peak_bytes(&bumped, &params).expect("fits in u64");
            assert!(bumped_bytes >= base_bytes, "bumping height {i} decreased the modelled peak");
        }
    }

    #[test]
    fn max_any_height_round_trips_through_the_cheapest_air() {
        let params = pcs_params();
        // The cheapest AIR is whichever produces the smallest `prover_peak_bytes` at height 1;
        // placing all budget on it is exactly what `max_any_height_for_budget` searches for.
        let cheapest = (0..MIDEN_AIR_COUNT)
            .min_by_key(|&i| {
                let mut heights = [0usize; MIDEN_AIR_COUNT];
                heights[i] = 1;
                prover_peak_bytes(&heights, &params).expect("fits in u64")
            })
            .expect("MIDEN_AIR_COUNT is non-zero");
        for n in [0usize, 1, 7, 100, 1 << 10, 1 << 20] {
            let mut heights = [0usize; MIDEN_AIR_COUNT];
            heights[cheapest] = n;
            let budget = prover_peak_bytes(&heights, &params).expect("fits in u64");
            assert_eq!(
                memory_model(&params).unwrap().max_any_height_for_budget(budget),
                n,
                "round trip failed for n = {n}"
            );
        }
    }

    #[test]
    fn max_any_height_for_budget_never_rejects_a_uniform_shape_that_fits() {
        let params = pcs_params();
        for n in [0usize, 1, 7, 100, 1 << 10, 1 << 20] {
            let budget = prover_peak_bytes(&[n; MIDEN_AIR_COUNT], &params).expect("fits in u64");
            let any = memory_model(&params).unwrap().max_any_height_for_budget(budget);
            assert!(
                any >= n,
                "max_any_height_for_budget({budget}) = {any} rejects uniform height {n}"
            );
        }
    }

    #[test]
    fn maximum_heights_use_checked_arithmetic() {
        let params = pcs_params();
        let expected = u64::try_from(30_240u128 * usize::MAX as u128).ok();
        assert_eq!(prover_peak_bytes(&[usize::MAX; MIDEN_AIR_COUNT], &params), expected);
    }
}
