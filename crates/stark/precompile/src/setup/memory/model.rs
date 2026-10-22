//! Peak prover memory model for the precompile chiplet-stack proof.
//!
//! Mirrors the production VM peak-memory model in `miden-vm-stark` for the Miden VM proof,
//! generalized over the [`NUM_CHIPLETS`] heterogeneous chiplet AIRs. [`prover_peak_bytes`] models
//! the allocations that dominate peak usage: each main and aux trace held at its 1x buffer plus its
//! blowup-factor LDE, the quotient accumulator, every layer of the three per-proof LMCS digest
//! trees (main, aux, quotient) alive at `open` time, the transient per-leaf hashing buffer held
//! while whichever of those trees is under construction squeezes its leaf digests, and the
//! process-cached BytePairLut preprocessed bundle. That bundle retains its raw `2^16`-row trace,
//! its blowup-factor LDE, its LMCS digest tree, and the same transient per-leaf hashing buffer for
//! its own one-time construction. The estimate covers one proof and the preprocessed bundle for
//! its selected hash configuration. It excludes bundles cached for other hash configurations and
//! concurrent proofs.
//! Smaller or transient allocations — FRI folding layers, the DEEP composition polynomial,
//! per-chiplet scratch buffers, allocator slack, rayon scratch, the live session — are covered
//! instead by [`SAFETY_NUMERATOR`] / [`SAFETY_DENOMINATOR`], a documented guess rather than a
//! measurement.

use miden_air_source::precompile::{
    air::{ChipletAir, NUM_CHIPLETS},
    primitives::byte_pair_lut::TRACE_HEIGHT,
};
use miden_core::{
    Felt,
    field::{BasedVectorSpace, QuadFelt},
    proof::HashFunction,
};
#[cfg(test)]
use miden_stark::log_quotient_degree;
use miden_stark::{
    air::{BaseAir, LiftedAir},
    pcs::PcsParams,
};

// CONSTANTS
// ================================================================================================

/// Size, in bytes, of one base-field element.
const FELT_BYTES: u64 = size_of::<Felt>() as u64;

/// Extension-field dimension in base-field elements.
const EXT_DIMENSION: u64 = <QuadFelt as BasedVectorSpace<Felt>>::DIMENSION as u64;

/// Digest size, in bytes, common to every STARK-configuration hash function the precompile
/// prover supports: 4 [`Felt`] elements for Eidos, 32 raw bytes for Blake3 and
/// Keccak.
const DIGEST_BYTES: u64 = 32;

/// Per-proof LMCS trees held simultaneously at proof-opening time: main, auxiliary, and quotient.
const PROOF_LMCS_TREES_AT_PEAK: u64 = 3;

/// Sponge-state width, in bytes, of the transient per-leaf buffer Keccak holds while hashing an
/// LMCS tree's leaves: the full 25-`u64` (1600-bit) Keccak-f permutation state.
const KECCAK_LEAF_STATE_BYTES: u64 = 25 * 8;

/// Numerator of the safety multiplier applied to the modelled figure (see module docs).
pub const SAFETY_NUMERATOR: u64 = 5;

/// Denominator of the safety multiplier applied to the modelled figure (see module docs).
pub const SAFETY_DENOMINATOR: u64 = 4;

/// Per-leaf LMCS hashing-scratch width, in bytes, for `hash_fn`.
///
/// Building an LMCS tree's leaf layer holds a buffer of these per-leaf states (see
/// `LiftedTree::build_with_alignment` in `miden-stark`) until every leaf's digest has been
/// squeezed out of it; the buffer coexists with the squeezed digests until it is dropped. Blake3's
/// `ChainingHasher` and the Eidos LMCS hasher use the digest itself as their state, so they cost
/// nothing beyond [`DIGEST_BYTES`]; Keccak holds a wider sponge state.
const fn leaf_state_bytes(hash_fn: HashFunction) -> u64 {
    match hash_fn {
        HashFunction::Blake3_256 | HashFunction::Eidos => DIGEST_BYTES,
        HashFunction::Keccak => KECCAK_LEAF_STATE_BYTES,
    }
}

// PEAK MEMORY MODEL
// ================================================================================================

/// Peak prover memory, deriving quotient geometry symbolically for tooling.
/// Production callers use the backend's compiled-degree estimator.
#[cfg(test)]
pub fn prover_peak_bytes(
    heights: &[usize; NUM_CHIPLETS],
    params: &PcsParams,
    hash_fn: HashFunction,
) -> Option<u64> {
    let max_log_quotient_degree = ChipletAir::all()
        .iter()
        .map(log_quotient_degree::<Felt, QuadFelt, ChipletAir>)
        .max()?;
    let num_quotient_chunks = 1usize.checked_shl(u32::from(max_log_quotient_degree))?;
    prover_peak_bytes_with_quotient_chunks(heights, params, hash_fn, num_quotient_chunks)
}

/// Peak prover memory using a quotient chunk count already derived by the relation compiler.
///
/// This path reads trace widths only and never evaluates AIR constraints. The caller supplies
/// the compiled relation's quotient chunk count, a positive power of two.
pub fn prover_peak_bytes_with_quotient_chunks(
    heights: &[usize; NUM_CHIPLETS],
    params: &PcsParams,
    hash_fn: HashFunction,
    num_quotient_chunks: usize,
) -> Option<u64> {
    let raw_widths = ChipletAir::all().map(|air| {
        (
            air.preprocessed_width(),
            air.width(),
            <ChipletAir as LiftedAir<Felt, QuadFelt>>::aux_width(&air) * EXT_DIMENSION as usize,
        )
    });
    prover_peak_bytes_for_shape(
        heights,
        &raw_widths,
        (TRACE_HEIGHT, ChipletAir::BytePairLut.preprocessed_width()),
        num_quotient_chunks,
        params,
        hash_fn,
    )
}

/// Numeric peak-memory model for raw committed widths and one fixed preprocessed table.
///
/// Each width tuple is `(preprocessed, main, auxiliary)` in base-field coordinates, before
/// commitment padding. `preprocessed_shape` is the fixed table's `(height, width)`.
pub fn prover_peak_bytes_for_shape(
    heights: &[usize],
    raw_widths: &[(usize, usize, usize)],
    preprocessed_shape: (usize, usize),
    num_quotient_chunks: usize,
    params: &PcsParams,
    hash_fn: HashFunction,
) -> Option<u64> {
    if heights.len() != raw_widths.len() {
        return None;
    }
    if !num_quotient_chunks.is_power_of_two() {
        return None;
    }
    let max_quotient_degree = u64::try_from(num_quotient_chunks).ok()?;
    let blowup = 1u64.checked_shl(u32::from(params.log_blowup()))?;
    let one_plus_blowup = blowup.checked_add(1)?;
    // `tree_bytes`/`preprocessed_tree_bytes` already bound the persisted digest tree, leaf layer
    // included, at `DIGEST_BYTES` per leaf; only the excess width of the transient per-leaf
    // hashing state over that digest is unmodelled extra scratch.
    let extra_leaf_scratch_bytes = leaf_state_bytes(hash_fn).saturating_sub(DIGEST_BYTES);

    // `Preprocessed` is cached for the process lifetime and retains the raw byte-pair table,
    // its LDE, every layer of its LMCS tree, and the leaf-hashing scratch buffer held while that
    // tree's leaves are squeezed. A full binary tree has fewer than twice as many digests as
    // leaves, so `2 * LDE height * DIGEST_BYTES` is a conservative upper bound.
    let preprocessed_height = u64::try_from(preprocessed_shape.0).ok()?;
    let preprocessed_width = u64::try_from(preprocessed_shape.1).ok()?;
    let preprocessed_trace_bytes = preprocessed_height
        .checked_mul(one_plus_blowup)?
        .checked_mul(preprocessed_width)?
        .checked_mul(FELT_BYTES)?;
    let preprocessed_tree_bytes = preprocessed_height
        .checked_mul(blowup)?
        .checked_mul(2)?
        .checked_mul(DIGEST_BYTES)?;
    let preprocessed_leaf_scratch_bytes =
        preprocessed_height.checked_mul(blowup)?.checked_mul(extra_leaf_scratch_bytes)?;
    let preprocessed_total = preprocessed_trace_bytes
        .checked_add(preprocessed_tree_bytes)?
        .checked_add(preprocessed_leaf_scratch_bytes)?;

    let mut per_air_total: u64 = 0;
    let mut max_height: u64 = 0;

    for (&(_, width, aux_base_columns), &height) in raw_widths.iter().zip(heights) {
        let height = u64::try_from(height).ok()?;
        let width = u64::try_from(width).ok()?;
        let aux_base_columns = u64::try_from(aux_base_columns).ok()?;
        let columns = width.checked_add(aux_base_columns)?;
        let bytes_per_row = FELT_BYTES.checked_mul(one_plus_blowup)?.checked_mul(columns)?;
        let per_air = height.checked_mul(bytes_per_row)?;

        per_air_total = per_air_total.checked_add(per_air)?;
        max_height = max_height.max(height);
    }

    let quotient_bytes = EXT_DIMENSION
        .checked_mul(FELT_BYTES)?
        .checked_mul(max_quotient_degree)?
        .checked_mul(blowup)?;
    let tree_bytes = PROOF_LMCS_TREES_AT_PEAK
        .checked_mul(2)?
        .checked_mul(blowup)?
        .checked_mul(DIGEST_BYTES)?;
    // Main, aux, and quotient trees are committed one at a time, so only one leaf-hashing scratch
    // buffer is alive at once; `max_height` bounds the LDE height of whichever tree that is.
    let leaf_scratch_bytes =
        max_height.checked_mul(blowup)?.checked_mul(extra_leaf_scratch_bytes)?;
    let shared_total = max_height
        .checked_mul(quotient_bytes.checked_add(tree_bytes)?)?
        .checked_add(leaf_scratch_bytes)?;

    let modelled = per_air_total.checked_add(shared_total)?.checked_add(preprocessed_total)?;
    modelled
        .checked_mul(SAFETY_NUMERATOR)
        .map(|scaled| scaled.div_ceil(SAFETY_DENOMINATOR))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Fixed inputs for the model's numeric fixtures; production policy is owned by miden-air.
    fn memory_test_params() -> PcsParams {
        PcsParams::new(3, 2, 7, 4, 12, 27, 17).expect("valid memory fixture parameters")
    }

    #[test]
    fn supplied_quotient_chunks_preserve_the_symbolic_estimate() {
        let params = memory_test_params();
        let heights = [16; NUM_CHIPLETS];
        assert_eq!(
            prover_peak_bytes_with_quotient_chunks(&heights, &params, HashFunction::Eidos, 4),
            prover_peak_bytes(&heights, &params, HashFunction::Eidos),
        );
        // The supplied compiled dimension must drive the estimate; recomputing the symbolic
        // full-relation degree here would silently discard a caller's relation geometry.
        assert!(
            prover_peak_bytes_with_quotient_chunks(&heights, &params, HashFunction::Eidos, 2)
                .unwrap()
                < prover_peak_bytes_with_quotient_chunks(&heights, &params, HashFunction::Eidos, 4)
                    .unwrap(),
        );
    }

    #[test]
    fn preprocessed_bundle_cost_scales_with_blowup() {
        let low_blowup = PcsParams::new(1, 1, 3, 0, 0, 1, 0).expect("valid PCS params");
        let production_blowup = memory_test_params();

        assert_eq!(
            prover_peak_bytes(&[0; NUM_CHIPLETS], &low_blowup, HashFunction::Blake3_256),
            Some(20_316_160)
        );
        assert_eq!(
            prover_peak_bytes(&[0; NUM_CHIPLETS], &production_blowup, HashFunction::Blake3_256),
            Some(71_434_240)
        );
    }

    /// Synthetic rows isolate memory accounting from routine production AIR-width changes.
    /// Auxiliary widths below are already base-field coordinates, exactly like committed rows.
    #[test]
    fn synthetic_shape_accounts_for_traces_quotient_trees_and_hashing_scratch() {
        let params = PcsParams::new(1, 1, 3, 0, 0, 1, 0).unwrap();
        let widths = [(0, 3, 2), (0, 1, 4)];
        // At blowup 2, the main/aux buffers cost 720 bytes; the quotient and three proof
        // trees cost 1792; the fixed table and its tree cost 1216. Their total 3728 is
        // multiplied by 5/4. Wide hash states add scratch for 8 setup and 4 proof rows.
        for (hash_fn, expected) in [
            (HashFunction::Blake3_256, 4660),
            (HashFunction::Eidos, 4660),
            (HashFunction::Keccak, 9700),
        ] {
            assert_eq!(
                prover_peak_bytes_for_shape(&[2, 4], &widths, (8, 1), 2, &params, hash_fn),
                Some(expected)
            );
        }
        // An AIR's own buffer cost is separate from the shared peak at the maximum height.
        assert_eq!(
            prover_peak_bytes_for_shape(&[2, 0], &widths, (8, 1), 2, &params, HashFunction::Eidos),
            Some(2940)
        );
        assert_eq!(
            prover_peak_bytes_for_shape(&[0, 4], &widths, (8, 1), 2, &params, HashFunction::Eidos),
            Some(4360)
        );
    }

    #[test]
    fn increasing_any_height_never_decreases_the_result() {
        let params = memory_test_params();
        let base = [1_000usize; NUM_CHIPLETS];
        for hash_fn in [HashFunction::Blake3_256, HashFunction::Eidos, HashFunction::Keccak] {
            let base_bytes = prover_peak_bytes(&base, &params, hash_fn).expect("fits in u64");
            for i in 0..NUM_CHIPLETS {
                let mut bumped = base;
                bumped[i] += 1;
                let bumped_bytes =
                    prover_peak_bytes(&bumped, &params, hash_fn).expect("fits in u64");
                assert!(
                    bumped_bytes >= base_bytes,
                    "bumping height {i} decreased the modelled peak for {hash_fn:?}"
                );
            }
        }
    }

    #[test]
    fn overflow_returns_none_instead_of_panicking() {
        let params = memory_test_params();
        assert_eq!(
            prover_peak_bytes(&[usize::MAX; NUM_CHIPLETS], &params, HashFunction::Keccak),
            None
        );
    }

    /// Regression test for the leaf-hashing scratch buffer flagged in PR #3799 review
    /// (pullrequestreview-5188317972): with Keccak, hashing a `2^19`-leaf LMCS tree holds a
    /// `[u64; 25]` state per leaf (100 MiB) alongside the squeezed `[u64; 4]` digests (16 MiB),
    /// not just the persisted digest tree the model previously counted alone.
    #[test]
    fn keccak_leaf_hashing_scratch_exceeds_blake3() {
        let params = memory_test_params();
        // `TRACE_HEIGHT` (the preprocessed bundle's fixed height) is also `2^16`, so this height
        // makes both the per-AIR shared term and the preprocessed term contribute the same-sized
        // leaf-hashing scratch below.
        let mut heights = [0; NUM_CHIPLETS];
        heights[0] = 1 << 16;
        assert_eq!(u64::try_from(TRACE_HEIGHT).unwrap(), 1u64 << 16);

        let blake3_bytes =
            prover_peak_bytes(&heights, &params, HashFunction::Blake3_256).expect("fits in u64");
        let keccak_bytes =
            prover_peak_bytes(&heights, &params, HashFunction::Keccak).expect("fits in u64");

        // Unmodelled, the gap between the two hash functions' peaks would be 0: DIGEST_BYTES is
        // the same 32 bytes for both. Modelled, Keccak's wider leaf state must show up as a
        // strictly larger peak: once for the per-AIR shared term (main/aux/quotient, bounded by
        // `max_height`) and once for the preprocessed bundle's own tree (bounded by
        // `TRACE_HEIGHT`), both at this height, scaled by the safety multiplier.
        let blowup: u64 = 1 << params.log_blowup();
        let per_term_gap = (1u64 << 16) * blowup * (KECCAK_LEAF_STATE_BYTES - DIGEST_BYTES);
        let expected_gap = (2 * per_term_gap) * SAFETY_NUMERATOR / SAFETY_DENOMINATOR;
        assert_eq!(keccak_bytes - blake3_bytes, expected_gap);
    }
}
