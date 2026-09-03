//! Peak prover memory model for the precompile chiplet-stack proof.
//!
//! Mirrors `miden_air::memory`'s peak-memory model for the Miden VM proof, generalized over the
//! [`NUM_CHIPLETS`] heterogeneous chiplet AIRs. [`prover_peak_bytes`] models the allocations that
//! dominate peak usage: each main and aux trace held at its 1x buffer plus its blowup-factor LDE,
//! the quotient accumulator, every layer of the three per-proof LMCS digest trees (main, aux,
//! quotient) alive at `open` time, and the process-cached BytePairLut preprocessed bundle. That
//! bundle retains its raw `2^16 × 4` trace, its blowup-factor LDE, and its LMCS digest tree.
//! The estimate covers one proof and the preprocessed bundle for its selected hash configuration.
//! It excludes bundles cached for other hash configurations and concurrent proofs.
//! Smaller or transient allocations — FRI folding layers, the DEEP composition polynomial,
//! per-chiplet scratch buffers, allocator slack, rayon scratch, the live session — are covered
//! instead by [`SAFETY_NUMERATOR`] / [`SAFETY_DENOMINATOR`], a documented guess rather than a
//! measurement.

use miden_core::{
    Felt,
    field::{BasedVectorSpace, QuadFelt},
};
use miden_crypto::stark::{log_quotient_degree, pcs::PcsParams};
use miden_lifted_air::{BaseAir, LiftedAir};

use crate::{
    air::{ChipletAir, NUM_CHIPLETS},
    primitives::byte_pair_lut::{NUM_PREPROCESSED_COLS, TRACE_HEIGHT},
};

// CONSTANTS
// ================================================================================================

/// Size, in bytes, of one base-field element.
const FELT_BYTES: u64 = size_of::<Felt>() as u64;

/// Extension-field dimension in base-field elements.
const EXT_DIMENSION: u64 = <QuadFelt as BasedVectorSpace<Felt>>::DIMENSION as u64;

/// Digest size, in bytes, common to every STARK-configuration hash function the precompile
/// prover supports: 4 [`Felt`] elements for the algebraic configs, 32 raw bytes for Blake3 and
/// Keccak.
const DIGEST_BYTES: u64 = 32;

/// Per-proof LMCS trees held simultaneously at proof-opening time: main, auxiliary, and quotient.
const PROOF_LMCS_TREES_AT_PEAK: u64 = 3;

/// Numerator of the safety multiplier applied to the modelled figure (see module docs).
pub const SAFETY_NUMERATOR: u64 = 5;

/// Denominator of the safety multiplier applied to the modelled figure (see module docs).
pub const SAFETY_DENOMINATOR: u64 = 4;

// PEAK MEMORY MODEL
// ================================================================================================

/// Peak prover memory, in bytes, for a proof over the given per-chiplet padded trace heights.
///
/// `heights` is in [`ChipletAir::all`] order. Returns `None` on arithmetic overflow.
pub fn prover_peak_bytes(heights: &[usize; NUM_CHIPLETS], params: &PcsParams) -> Option<u64> {
    let blowup = 1u64.checked_shl(u32::from(params.log_blowup()))?;
    let one_plus_blowup = blowup.checked_add(1)?;

    // `Preprocessed` is cached for the process lifetime and retains the raw BytePairLut table,
    // its LDE, and every layer of its LMCS tree. A full binary tree has fewer than twice as many
    // digests as leaves, so `2 * LDE height * DIGEST_BYTES` is a conservative upper bound.
    let preprocessed_height = u64::try_from(TRACE_HEIGHT).ok()?;
    let preprocessed_width = u64::try_from(NUM_PREPROCESSED_COLS).ok()?;
    let preprocessed_trace_bytes = preprocessed_height
        .checked_mul(one_plus_blowup)?
        .checked_mul(preprocessed_width)?
        .checked_mul(FELT_BYTES)?;
    let preprocessed_tree_bytes = preprocessed_height
        .checked_mul(blowup)?
        .checked_mul(2)?
        .checked_mul(DIGEST_BYTES)?;
    let preprocessed_total = preprocessed_trace_bytes.checked_add(preprocessed_tree_bytes)?;

    let mut per_air_total: u64 = 0;
    let mut max_height: u64 = 0;
    let mut max_quotient_degree: u64 = 0;

    for (air, &height) in ChipletAir::all().iter().zip(heights.iter()) {
        let height = u64::try_from(height).ok()?;
        let width = u64::try_from(air.width()).ok()?;
        let aux_width =
            u64::try_from(<ChipletAir as LiftedAir<Felt, QuadFelt>>::aux_width(air)).ok()?;
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
    let tree_bytes = PROOF_LMCS_TREES_AT_PEAK
        .checked_mul(2)?
        .checked_mul(blowup)?
        .checked_mul(DIGEST_BYTES)?;
    let shared_total = max_height.checked_mul(quotient_bytes.checked_add(tree_bytes)?)?;

    let modelled = per_air_total.checked_add(shared_total)?.checked_add(preprocessed_total)?;
    modelled
        .checked_mul(SAFETY_NUMERATOR)
        .map(|scaled| scaled.div_ceil(SAFETY_DENOMINATOR))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stark_config::precompile_pcs_params;

    #[test]
    fn preprocessed_bundle_cost_scales_with_blowup() {
        let low_blowup = PcsParams::new(1, 1, 3, 0, 0, 1, 0).expect("valid PCS params");
        let production_blowup = precompile_pcs_params();

        assert_eq!(prover_peak_bytes(&[0; NUM_CHIPLETS], &low_blowup), Some(18_350_080));
        assert_eq!(prover_peak_bytes(&[0; NUM_CHIPLETS], &production_blowup), Some(65_536_000));
    }

    #[test]
    fn pinned_bytes_for_current_air_shape() {
        let params = precompile_pcs_params();
        // Current per-row trace costs before the safety multiplier, in `ChipletAir::all()` order,
        // are:
        // 13_320, 2_736, 7_776, 504, 5_112, 7_344, 2_592, 2_592, 3_384, and 5_472
        // bytes. The shared term uses the maximum quotient degree (4) across the full AIR set.
        // Each expectation also includes that quotient/tree peak, the preprocessed bundle, and the
        // 5/4 safety factor. Any AIR shape change must break this test rather than silently drift
        // the model.
        let expected = [
            65_555_210, 65_541_980, 65_548_280, 65_539_190, 65_544_950, 65_547_740, 65_541_800,
            65_541_800, 65_542_790, 65_545_400,
        ];
        for (i, expected) in expected.into_iter().enumerate() {
            let mut heights = [0; NUM_CHIPLETS];
            heights[i] = 1;
            assert_eq!(
                prover_peak_bytes(&heights, &params),
                Some(expected),
                "{:?} alone",
                ChipletAir::all()[i]
            );
        }
        assert_eq!(
            prover_peak_bytes(&[1; NUM_CHIPLETS], &params),
            Some(65_602_100),
            "all chiplet AIRs at height 1"
        );
    }

    #[test]
    fn increasing_any_height_never_decreases_the_result() {
        let params = precompile_pcs_params();
        let base = [1_000usize; NUM_CHIPLETS];
        let base_bytes = prover_peak_bytes(&base, &params).expect("fits in u64");
        for i in 0..NUM_CHIPLETS {
            let mut bumped = base;
            bumped[i] += 1;
            let bumped_bytes = prover_peak_bytes(&bumped, &params).expect("fits in u64");
            assert!(bumped_bytes >= base_bytes, "bumping height {i} decreased the modelled peak");
        }
    }

    #[test]
    fn overflow_returns_none_instead_of_panicking() {
        let params = precompile_pcs_params();
        assert_eq!(prover_peak_bytes(&[usize::MAX; NUM_CHIPLETS], &params), None);
    }
}
