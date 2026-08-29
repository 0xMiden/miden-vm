//! Peak prover memory model for the lifted-STARK Miden VM proof.
//!
//! Derives AIR-specific quantities (widths, quotient degree) from the [`BaseAir`] /
//! [`LiftedAir`] impls over [`AIRS`], and protocol quantities from [`PcsParams`].
//!
//! [`prover_peak_bytes`] models the allocations that dominate peak usage: each main and aux
//! trace held at its 1x buffer plus its blowup-factor LDE, the quotient accumulator, and every
//! layer of the three LMCS digest trees (main, aux, quotient) alive at `open` time. Smaller or
//! transient allocations — FRI folding layers, the DEEP composition polynomial, per-AIR scratch
//! buffers, allocator slack, rayon scratch, the live witness — are covered instead by
//! [`SAFETY_NUMERATOR`] / [`SAFETY_DENOMINATOR`], a documented guess rather than a measurement.
//!
//! Does not cover the precompile prover's memory footprint.

use miden_core::field::{BasedVectorSpace, QuadFelt};
use miden_crypto::stark::{log_quotient_degree, pcs::PcsParams};

use crate::{AIRS, BaseAir, Felt, LiftedAir, MIDEN_AIR_COUNT, MidenAir};

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
    let blowup = 1u64.checked_shl(u32::from(params.log_blowup()))?;
    let one_plus_blowup = blowup.checked_add(1)?;

    let mut per_air_total: u64 = 0;
    let mut max_height: u64 = 0;
    let mut max_quotient_degree: u64 = 0;

    for (air, &height) in AIRS.iter().zip(heights.iter()) {
        let height = u64::try_from(height).ok()?;
        let width = u64::try_from(air.width()).ok()?;
        let aux_width =
            u64::try_from(<MidenAir as LiftedAir<Felt, QuadFelt>>::aux_width(air)).ok()?;
        let log_d = log_quotient_degree::<Felt, QuadFelt, _>(air);
        let quotient_degree = 1u64.checked_shl(u32::from(log_d))?;

        let aux_base_columns = aux_width.checked_mul(EXT_DIMENSION)?;
        let columns = width.checked_add(aux_base_columns)?;
        let bytes_per_row = FELT_BYTES.checked_mul(one_plus_blowup)?.checked_mul(columns)?;
        let per_air = height.checked_mul(bytes_per_row)?;

        per_air_total = per_air_total.checked_add(per_air)?;
        max_height = max_height.max(height);
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
    let shared_total = max_height.checked_mul(quotient_bytes.checked_add(tree_bytes)?)?;

    let modelled = per_air_total.checked_add(shared_total)?;
    modelled
        .checked_mul(SAFETY_NUMERATOR)
        .map(|scaled| scaled.div_ceil(SAFETY_DENOMINATOR))
}

/// The largest single-AIR height that can fit in `budget_bytes`, derived from the cheapest AIR
/// (every other height held at zero). Permissive: never rejects a shape [`prover_peak_bytes`]
/// would accept.
pub fn max_any_height_for_budget(budget_bytes: u64, params: &PcsParams) -> usize {
    let mut best = 0usize;
    for i in 0..MIDEN_AIR_COUNT {
        let height = max_height_for_budget(budget_bytes, params, |n| {
            let mut heights = [0usize; MIDEN_AIR_COUNT];
            heights[i] = n;
            heights
        });
        best = best.max(height);
    }
    best
}

/// The largest `n` for which `heights_for(n)` fits `budget_bytes`, found by binary search
/// ([`prover_peak_bytes`] is non-decreasing in every height).
fn max_height_for_budget(
    budget_bytes: u64,
    params: &PcsParams,
    heights_for: impl Fn(usize) -> [usize; MIDEN_AIR_COUNT],
) -> usize {
    let fits =
        |n: usize| prover_peak_bytes(&heights_for(n), params).is_some_and(|b| b <= budget_bytes);

    let mut lo = 0usize;
    let mut hi = usize::MAX;
    if fits(hi) {
        return hi;
    }
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if fits(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    lo
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::pcs_params;

    /// Pinned bytes/row figures for the current AIR shape (51/22/16 main columns, 4/3/1 aux
    /// columns, quotient degree 8 for all three, blowup 8): a width, aux-width, or quotient
    /// degree change must break this test loudly rather than silently drift the model.
    #[test]
    fn pinned_bytes_for_current_air_shape() {
        let params = pcs_params();
        assert_eq!(prover_peak_bytes(&[1, 0, 0], &params), Some(8510), "Core alone");
        assert_eq!(prover_peak_bytes(&[0, 1, 0], &params), Some(5720), "Chiplets alone");
        assert_eq!(
            prover_peak_bytes(&[0, 0, 1], &params),
            Some(4820),
            "Poseidon2Permutation alone"
        );
        assert_eq!(prover_peak_bytes(&[1, 1, 1], &params), Some(12650), "all three at height 1");
    }

    #[test]
    fn zero_heights_cost_nothing() {
        let params = pcs_params();
        assert_eq!(prover_peak_bytes(&[0, 0, 0], &params), Some(0));
    }

    #[test]
    fn increasing_any_height_never_decreases_the_result() {
        let params = pcs_params();
        let base = [1_000usize, 2_000, 500];
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
