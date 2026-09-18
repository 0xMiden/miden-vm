//! Peak prover memory model for the precompile chiplet-stack proof.
//!
//! Mirrors `miden_air::memory`'s peak-memory model for the Miden VM proof, generalized over the
//! [`NUM_CHIPLETS`] heterogeneous chiplet AIRs. [`prover_peak_bytes`] models the allocations that
//! dominate peak usage: each main and aux trace held at its 1x buffer plus its blowup-factor LDE,
//! the quotient accumulator, every layer of the three per-proof LMCS digest trees (main, aux,
//! quotient) alive at `open` time, the transient per-leaf hashing buffer held while whichever of
//! those trees is under construction squeezes its leaf digests, and the process-cached
//! BytePairLut preprocessed bundle. That bundle retains its raw `2^16 × 4` trace, its
//! blowup-factor LDE, its LMCS digest tree, and the same transient per-leaf hashing buffer for
//! its own one-time construction. The estimate covers one proof and the preprocessed bundle for
//! its selected hash configuration. It excludes bundles cached for other hash configurations and
//! concurrent proofs.
//! Smaller or transient allocations — FRI folding layers, the DEEP composition polynomial,
//! per-chiplet scratch buffers, allocator slack, rayon scratch, the live session — are covered
//! instead by [`SAFETY_NUMERATOR`] / [`SAFETY_DENOMINATOR`], a documented guess rather than a
//! measurement.

use miden_core::{
    Felt,
    field::{BasedVectorSpace, QuadFelt},
    proof::HashFunction,
};
use miden_crypto::stark::{log_quotient_degree, pcs::PcsParams};
use miden_lifted_air::{BaseAir, LiftedAir};

use crate::{
    air::{ChipletAir, NUM_CHIPLETS},
    primitives::byte_pair_lut::TRACE_HEIGHT,
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

/// Sponge-state width, in bytes, of the transient per-leaf buffer RPO, RPX, and Poseidon2 hold
/// while hashing an LMCS tree's leaves: 12 [`Felt`] elements per `StatefulSponge` state.
const ALGEBRAIC_LEAF_STATE_BYTES: u64 = 12 * FELT_BYTES;

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
/// `LiftedTree::build_with_alignment` in `miden-lifted-stark`) until every leaf's digest has been
/// squeezed out of it; the buffer coexists with the squeezed digests until it is dropped. Blake3's
/// `ChainingHasher` and the Eidos LMCS hasher use the digest itself as their state, so they cost
/// nothing beyond [`DIGEST_BYTES`]; RPO, RPX, Poseidon2, and Keccak all hold a wider sponge state.
const fn leaf_state_bytes(hash_fn: HashFunction) -> u64 {
    match hash_fn {
        HashFunction::Blake3_256 | HashFunction::Eidos => DIGEST_BYTES,
        HashFunction::Rpo256 | HashFunction::Rpx256 | HashFunction::Poseidon2 => {
            ALGEBRAIC_LEAF_STATE_BYTES
        },
        HashFunction::Keccak => KECCAK_LEAF_STATE_BYTES,
    }
}

// PEAK MEMORY MODEL
// ================================================================================================

/// Peak prover memory, in bytes, for a proof over the given per-chiplet padded trace heights.
pub fn prover_peak_bytes(
    heights: &[usize; NUM_CHIPLETS],
    params: &PcsParams,
    hash_fn: HashFunction,
) -> Option<u64> {
    let blowup = 1u64.checked_shl(u32::from(params.log_blowup()))?;
    let one_plus_blowup = blowup.checked_add(1)?;
    // `tree_bytes`/`preprocessed_tree_bytes` already bound the persisted digest tree, leaf layer
    // included, at `DIGEST_BYTES` per leaf; only the excess width of the transient per-leaf
    // hashing state over that digest is unmodelled extra scratch.
    let extra_leaf_scratch_bytes = leaf_state_bytes(hash_fn).saturating_sub(DIGEST_BYTES);

    // `Preprocessed` is cached for the process lifetime and retains the raw byte-pair/And8 table,
    // its LDE, every layer of its LMCS tree, and the leaf-hashing scratch buffer held while that
    // tree's leaves are squeezed. A full binary tree has fewer than twice as many digests as
    // leaves, so `2 * LDE height * DIGEST_BYTES` is a conservative upper bound.
    let preprocessed_height = u64::try_from(TRACE_HEIGHT).ok()?;
    // The byte-pair and And8 tables are committed as one preprocessed matrix.
    let preprocessed_width = u64::try_from(ChipletAir::BytePairAnd8.preprocessed_width()).ok()?;
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
    use crate::stark_config::precompile_pcs_params;

    #[test]
    fn preprocessed_bundle_cost_scales_with_blowup() {
        let low_blowup = PcsParams::new(1, 1, 3, 0, 0, 1, 0).expect("valid PCS params");
        let production_blowup = precompile_pcs_params();

        assert_eq!(
            prover_peak_bytes(&[0; NUM_CHIPLETS], &low_blowup, HashFunction::Blake3_256),
            Some(39_976_960)
        );
        assert_eq!(
            prover_peak_bytes(&[0; NUM_CHIPLETS], &production_blowup, HashFunction::Blake3_256),
            Some(130_416_640)
        );
    }

    #[test]
    fn pinned_bytes_for_current_air_shape() {
        let params = precompile_pcs_params();
        // Current per-row trace costs before the safety multiplier, in `ChipletAir::all()` order,
        // are:
        // 13_176, 11_088, 7_776, 2_664, 4_968, 7_344, 2_592, 2_592, 3_384, and 5_472
        // bytes. The shared term uses the maximum quotient degree (4) across the full AIR set.
        // Each expectation also includes that quotient/tree peak, the preprocessed bundle, and the
        // 5/4 safety factor. Blake3 and Eidos add no leaf-hashing scratch beyond the digest itself.
        // Any AIR shape change must break this test rather than silently drift the model.
        let expected = [
            130_435_670,
            130_433_060,
            130_428_920,
            130_422_530,
            130_425_410,
            130_428_380,
            130_422_440,
            130_422_440,
            130_423_430,
            130_426_040,
        ];
        for hash_fn in [HashFunction::Blake3_256, HashFunction::Eidos] {
            for (i, expected) in expected.into_iter().enumerate() {
                let mut heights = [0; NUM_CHIPLETS];
                heights[i] = 1;
                assert_eq!(
                    prover_peak_bytes(&heights, &params, hash_fn),
                    Some(expected),
                    "{:?} alone with {hash_fn:?}",
                    ChipletAir::all()[i]
                );
            }
            assert_eq!(
                prover_peak_bytes(&[1; NUM_CHIPLETS], &params, hash_fn),
                Some(130_495_520),
                "all chiplet AIRs at height 1 with {hash_fn:?}"
            );
        }
    }

    #[test]
    fn increasing_any_height_never_decreases_the_result() {
        let params = precompile_pcs_params();
        let base = [1_000usize; NUM_CHIPLETS];
        for hash_fn in [
            HashFunction::Blake3_256,
            HashFunction::Rpo256,
            HashFunction::Rpx256,
            HashFunction::Poseidon2,
            HashFunction::Keccak,
        ] {
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
        let params = precompile_pcs_params();
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
        let params = precompile_pcs_params();
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
