//! Unified testing infrastructure for the lifted STARK crate.
//!
//! Provides three complete configuration variants, each containing everything
//! needed to test at any level (LMCS, PCS, or full STARK):
//!
//! - `configs::goldilocks_poseidon2`
//! - `configs::goldilocks_keccak`
//! - `configs::goldilocks_blake3_192`
//!
//! Also provides shared fixtures, matrix generation utilities, and test helpers.

pub mod airs;
pub mod configs;
pub mod params;

#[cfg(test)]
mod test_aux_shape;
#[cfg(test)]
mod test_bus;
#[cfg(test)]
mod test_multi_aux_alignment;
#[cfg(test)]
mod test_tiny_air;

// Re-export commonly used params at the module level for convenience.
use alloc::vec::Vec;

use p3_field::Field;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
pub use params::{
    BENCH_PCS_PARAMS, FRI_FOLD_ARITY_2, FRI_FOLD_ARITY_4, FRI_FOLD_ARITY_8, LOG_HEIGHTS,
    PARALLEL_STR, QC_CONSTRAINT_DEGREE, QC_PCS_PARAMS, RELATIVE_SPECS, TEST_SEED,
};
use rand::{
    SeedableRng,
    distr::{Distribution, StandardUniform},
    rngs::SmallRng,
};

// =============================================================================
// Matrix generation
// =============================================================================

/// Generate benchmark matrices from relative specs.
///
/// Creates matrices with heights relative to `max_height = 1 << log_max_height`.
/// Each spec `(offset, width)` creates a matrix with:
/// - height = `max_height >> offset`
/// - width = `width`
///
/// Matrices in each group are sorted by ascending height.
pub fn generate_matrices_from_specs<F: Field>(
    specs: &[&[(usize, usize)]],
    log_max_height: u8,
) -> Vec<Vec<RowMajorMatrix<F>>>
where
    StandardUniform: Distribution<F>,
{
    let rng = &mut SmallRng::seed_from_u64(TEST_SEED);
    let max_height = 1 << log_max_height as usize;

    specs
        .iter()
        .map(|group_specs| {
            let mut matrices: Vec<RowMajorMatrix<F>> = group_specs
                .iter()
                .map(|&(offset, width)| {
                    let height = max_height >> offset;
                    RowMajorMatrix::rand(rng, height, width)
                })
                .collect();
            // Sort by ascending height (required by LMCS)
            matrices.sort_by_key(Matrix::height);
            matrices
        })
        .collect()
}

/// Calculate total elements across all matrices.
pub fn total_elements<F: Field>(matrix_groups: &[Vec<RowMajorMatrix<F>>]) -> u64 {
    matrix_groups
        .iter()
        .flat_map(|g| g.iter())
        .map(|m| {
            let dims = m.dimensions();
            (dims.height * dims.width) as u64
        })
        .sum()
}

// =============================================================================
// define_test_config! macro
// =============================================================================

/// Generates LMCS type aliases and channel helper functions for a test config.
///
/// Requires these items in scope from the base config module:
/// `Felt`, `Sponge`, `Compress`, `Challenger`, `test_challenger`
///
/// Also requires `Lmcs` to be defined as a type alias in the invoking module.
macro_rules! define_lmcs_test_helpers {
    () => {
        use $crate::lmcs::Lmcs as LmcsTrait;

        pub type TestTree = <Lmcs as LmcsTrait>::Tree<p3_matrix::dense::RowMajorMatrix<Felt>>;
        pub type TestCommitment = <Lmcs as LmcsTrait>::Commitment;
        pub type TestTranscriptData = miden_stark_transcript::TranscriptData<Felt, TestCommitment>;
        pub type TestDigest = <Challenger as p3_challenger::CanFinalizeDigest>::Digest;
        pub type TestProverChannel =
            miden_stark_transcript::ProverTranscript<Felt, TestCommitment, Challenger>;
        pub type TestVerifierChannel<'a> =
            miden_stark_transcript::VerifierTranscript<'a, Felt, TestCommitment, Challenger>;

        pub fn prover_channel() -> TestProverChannel {
            miden_stark_transcript::ProverTranscript::new(test_challenger())
        }

        pub fn prover_channel_with_commitment(commitment: &TestCommitment) -> TestProverChannel {
            let mut challenger = test_challenger();
            p3_challenger::CanObserve::observe(&mut challenger, commitment.clone());
            miden_stark_transcript::ProverTranscript::new(challenger)
        }

        pub fn verifier_channel(data: &TestTranscriptData) -> TestVerifierChannel<'_> {
            miden_stark_transcript::VerifierTranscript::from_data(test_challenger(), data)
        }

        pub fn verifier_channel_with_commitment<'a>(
            data: &'a TestTranscriptData,
            commitment: &TestCommitment,
        ) -> TestVerifierChannel<'a> {
            let mut challenger = test_challenger();
            p3_challenger::CanObserve::observe(&mut challenger, commitment.clone());
            miden_stark_transcript::VerifierTranscript::from_data(challenger, data)
        }
    };
}

pub(crate) use define_lmcs_test_helpers;

// =============================================================================
// Internal re-exports for benchmarks
// =============================================================================
pub use crate::pcs::{
    deep::interpolate::PointQuotients, fri::fold::FriFold, prover::open_with_channel,
    utils::bit_reversed_coset_points,
};
pub use crate::prover::quotient::commit_quotient;
