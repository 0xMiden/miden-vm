//! Peak prover memory model for the lifted-STARK Miden VM proof.
//!
//! Derives AIR-specific quantities (widths, quotient degree) from the [`BaseAir`] /
//! [`LiftedAir`] impls over [`AIRS`], and protocol quantities from [`PcsParams`].
//! The runtime AIR facade supplies build-generated constraint degrees, so budget queries never
//! perform symbolic AIR evaluation.
//!
//! [`prover_peak_bytes`] models the allocations that dominate peak usage: each main and aux
//! trace held at its 1x buffer plus its blowup-factor LDE, the quotient accumulator, and every
//! layer of the three LMCS digest trees (main, aux, quotient) alive at `open` time. Smaller or
//! transient allocations — FRI folding layers, the DEEP composition polynomial, per-AIR scratch
//! buffers, allocator slack, rayon scratch, the live witness — are covered instead by
//! [`SAFETY_NUMERATOR`] / [`SAFETY_DENOMINATOR`], a documented guess rather than a measurement.
//!
//! This model does not charge the fixed And8 preprocessed table or its committed LDE tree. In
//! `std` builds that setup is cached process-wide per STARK configuration and blowup, rather than
//! allocated from an individual trace shape; `no_std` proving may rebuild it. The model likewise
//! does not charge transient rematerializations of the fixed table while building the And8
//! auxiliary trace. Consequently, the configured budget bounds the dominant VM-proof allocations
//! modelled here, not total process RSS. It also does not cover the precompile prover's memory
//! footprint.

use miden_air::vm::{AIRS, BaseAir, Felt, LiftedAir, MIDEN_AIR_COUNT, MidenAir};
use miden_core::field::{BasedVectorSpace, QuadFelt};
use miden_stark::{
    log_quotient_degree,
    memory::{ProverMemoryModel, ProvingBudget},
    pcs::PcsParams,
};

// CONSTANTS
// ================================================================================================

/// Size, in bytes, of one base-field element.
const FELT_BYTES: u64 = size_of::<Felt>() as u64;

/// Extension-field dimension in base-field elements.
const EXT_DIMENSION: u64 = <QuadFelt as BasedVectorSpace<Felt>>::DIMENSION as u64;

/// Digest size, in bytes, common to every STARK-configuration hash function Miden VM supports:
/// 4 [`Felt`] elements for the algebraic configs, 32 raw bytes for Blake3 and Keccak.
const DIGEST_BYTES: u64 = 32;

/// LMCS trees held simultaneously at proof-opening time: main, auxiliary, and quotient.
const LMCS_TREES_AT_PEAK: u64 = 3;

/// Numerator of the safety multiplier applied to the modelled figure (see module docs).
pub const SAFETY_NUMERATOR: u64 = 5;

/// Denominator of the safety multiplier applied to the modelled figure (see module docs).
pub const SAFETY_DENOMINATOR: u64 = 4;

// PEAK MEMORY MODEL
// ================================================================================================

/// Peak prover memory, in bytes, for a proof over the given per-AIR padded trace heights.
///
/// `heights` is in [`AIRS`] order. Returns `None` on arithmetic overflow.
pub fn prover_peak_bytes(heights: &[usize; MIDEN_AIR_COUNT], params: &PcsParams) -> Option<u64> {
    memory_model(params)?.prover_peak_bytes(heights)
}

/// Constructs a model from generated production AIR metadata, without symbolic evaluation.
pub fn memory_model(params: &PcsParams) -> Option<ProverMemoryModel<MIDEN_AIR_COUNT>> {
    let blowup = 1u64.checked_shl(u32::from(params.log_blowup()))?;
    let one_plus_blowup = blowup.checked_add(1)?;
    let mut row_costs = [0; MIDEN_AIR_COUNT];
    let mut max_quotient_degree = 0;
    for (air, cost) in AIRS.iter().zip(&mut row_costs) {
        let width = u64::try_from(air.width()).ok()?;
        let aux_width =
            u64::try_from(<MidenAir as LiftedAir<Felt, QuadFelt>>::aux_width(air)).ok()?;
        let quotient_degree =
            1u64.checked_shl(u32::from(log_quotient_degree::<Felt, QuadFelt, _>(air)))?;
        let columns = width.checked_add(aux_width.checked_mul(EXT_DIMENSION)?)?;
        *cost = FELT_BYTES.checked_mul(one_plus_blowup)?.checked_mul(columns)?;
        max_quotient_degree = max_quotient_degree.max(quotient_degree);
    }
    let quotient_bytes = EXT_DIMENSION
        .checked_mul(FELT_BYTES)?
        .checked_mul(max_quotient_degree)?
        .checked_mul(blowup)?;
    let tree_bytes = LMCS_TREES_AT_PEAK
        .checked_mul(2)?
        .checked_mul(blowup)?
        .checked_mul(DIGEST_BYTES)?;
    Some(ProverMemoryModel::new(
        row_costs,
        quotient_bytes.checked_add(tree_bytes)?,
        SAFETY_NUMERATOR,
        SAFETY_DENOMINATOR,
    ))
}

/// Permissive single-AIR height cap for this model and byte limit.
pub fn max_any_height_for_budget(budget_bytes: u64, params: &PcsParams) -> usize {
    memory_model(params).map_or(0, |model| model.max_any_height_for_budget(budget_bytes))
}

/// Default maximum modelled peak memory, preserving the existing 64 GiB policy.
pub const DEFAULT_MAX_PROVER_MEMORY_BYTES: u64 = 64 << 30;

/// Supplies the canonical VM model with the caller's byte limit.
pub fn canonical_budget(limit_bytes: u64) -> ProvingBudget<MIDEN_AIR_COUNT> {
    ProvingBudget::new(
        memory_model(&crate::setup::config::pcs_params()).expect("canonical VM memory model fits"),
        limit_bytes,
    )
}

/// Supplies the canonical VM model with its default byte limit.
pub fn default_budget() -> ProvingBudget<MIDEN_AIR_COUNT> {
    canonical_budget(DEFAULT_MAX_PROVER_MEMORY_BYTES)
}

#[cfg(test)]
mod tests {
    use miden_air_source::vm::trace::and8_lookup::AND8_LOOKUP_TRACE_HEIGHT;

    use super::*;
    use crate::setup::config::pcs_params;

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

        assert_eq!(prover_peak_bytes(&[1, 0, 0, 0], &params), Some(8240), "Core alone");
        assert_eq!(prover_peak_bytes(&[0, 1, 0, 0], &params), Some(6080), "Chiplets alone");
        assert_eq!(
            prover_peak_bytes(&[0, 0, 1, 0], &params),
            Some(16520),
            "EidosCompression alone"
        );
        assert_eq!(prover_peak_bytes(&[0, 0, 0, 1], &params), Some(4550), "And8Lookup alone");
        assert_eq!(prover_peak_bytes(&[1, 1, 1, 1], &params), Some(25790), "all four at height 1");
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
                max_any_height_for_budget(budget, &params),
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
            let any = max_any_height_for_budget(budget, &params);
            assert!(
                any >= n,
                "max_any_height_for_budget({budget}) = {any} rejects uniform height {n}"
            );
        }
    }

    #[test]
    fn overflow_returns_none_instead_of_panicking() {
        let params = pcs_params();
        assert_eq!(prover_peak_bytes(&[usize::MAX; MIDEN_AIR_COUNT], &params), None);
    }
}
