//! Goldilocks + Poseidon2 test configuration.
//!
//! Provides a complete set of type aliases, constructors, and helpers for testing
//! LMCS, PCS, and full STARK with Goldilocks field and Poseidon2 hashing.

use alloc::vec::Vec;

use p3_challenger::DuplexChallenger;
use p3_dft::Radix2DitParallel;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_goldilocks::Poseidon2Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::{Hash, TruncatedPermutation};
use rand::{SeedableRng, rngs::SmallRng};

pub use super::{Felt, PackedFelt, QuadFelt};
use crate::{
    air::{MultiAir, ProverStatement, Statement},
    testing::TEST_SEED,
};

// =============================================================================
// Base field/hash configuration
// =============================================================================

/// Poseidon2 permutation width.
pub const WIDTH: usize = 12;

/// Sponge rate (elements absorbed per permutation).
pub const RATE: usize = 8;

/// Digest size in field elements.
pub const DIGEST: usize = 4;

/// Poseidon2 permutation.
pub type Perm = Poseidon2Goldilocks<WIDTH>;

/// Stateful sponge for hashing (can be used for LMCS).
pub type Sponge = miden_stateful_hasher::StatefulSponge<Perm, WIDTH, RATE, DIGEST>;

/// Truncated permutation for 2-to-1 compression.
pub type Compress = TruncatedPermutation<Perm, 2, DIGEST, WIDTH>;

/// Commitment type (truncated permutation output).
pub type Commitment = Hash<Felt, Felt, DIGEST>;

/// Duplex challenger for Fiat-Shamir.
pub type Challenger = DuplexChallenger<Felt, Perm, WIDTH, RATE>;

/// Create the permutation with standard seed.
pub fn create_perm() -> Perm {
    let mut rng = SmallRng::seed_from_u64(TEST_SEED);
    Perm::new_from_rng_128(&mut rng)
}

/// Create standard test components with a consistent seed.
///
/// Returns the permutation, sponge, and compressor for Merkle tree construction.
pub fn test_components() -> (Perm, Sponge, Compress) {
    let perm = create_perm();
    let sponge = Sponge::new(perm.clone());
    let compress = Compress::new(perm.clone());
    (perm, sponge, compress)
}

/// Create a standard challenger for Fiat-Shamir.
pub fn test_challenger() -> Challenger {
    Challenger::new(create_perm())
}

// =============================================================================
// LMCS layer
// =============================================================================

/// LMCS configured with Goldilocks + Poseidon2.
pub type Lmcs =
    crate::lmcs::config::LmcsConfig<PackedFelt, PackedFelt, Sponge, Compress, WIDTH, DIGEST>;

crate::testing::define_lmcs_test_helpers!();

/// Create a test LMCS instance.
pub fn test_lmcs() -> Lmcs {
    let (_, sponge, compress) = test_components();
    crate::lmcs::config::LmcsConfig::new(sponge, compress)
}

// =============================================================================
// PCS layer
// =============================================================================

/// Generate a matrix of LDE evaluations for random low-degree polynomials.
pub fn random_lde_matrix<V>(
    rng: &mut SmallRng,
    log_poly_degree: u8,
    log_blowup: u8,
    num_columns: usize,
    shift: Felt,
) -> RowMajorMatrix<V>
where
    V: BasedVectorSpace<Felt> + Clone + Send + Sync + Default,
    rand::distr::StandardUniform: rand::distr::Distribution<V>,
{
    use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
    use p3_matrix::{Matrix as _, bitrev::BitReversibleMatrix};

    let poly_degree = 1 << log_poly_degree as usize;
    let dft = Radix2DFTSmallBatch::<Felt>::default();

    let evals = RowMajorMatrix::rand(rng, poly_degree, num_columns);
    let lde = dft.coset_lde_algebra_batch(evals, log_blowup as usize, shift);
    lde.bit_reverse_rows().to_row_major_matrix()
}

// =============================================================================
// STARK layer
// =============================================================================

pub type Dft = Radix2DitParallel<Felt>;

pub type TestConfig = crate::config::GenericStarkConfig<Felt, QuadFelt, Lmcs, Dft, Challenger>;

pub fn test_config() -> TestConfig {
    crate::config::GenericStarkConfig::new(
        crate::testing::params::TEST_PCS_PARAMS,
        test_lmcs(),
        Dft::default(),
        test_challenger(),
    )
}

/// Generate a power-of-4 chain trace: `[start, start⁴, start¹⁶, start⁶⁴, ...]`
pub fn generate_pow4_trace(start: Felt, height: usize) -> RowMajorMatrix<Felt> {
    let mut values = Vec::with_capacity(height);
    let mut current = start;
    for _ in 0..height {
        values.push(current);
        current = current.exp_power_of_2(2);
    }
    RowMajorMatrix::new(values, 1)
}

/// Run the full prove → verify → transcript-reparse cycle.
pub fn prove_and_verify_statement<MA>(prover_statement: &ProverStatement<Felt, QuadFelt, MA>)
where
    MA: MultiAir<Felt, QuadFelt>,
{
    let config = test_config();

    let output = crate::prover::prove(&config, prover_statement, test_challenger())
        .expect("proving should succeed");

    let verifier_digest = crate::verifier::verify(
        &config,
        prover_statement.statement(),
        &output.proof,
        test_challenger(),
    )
    .expect("verification should succeed");
    assert_eq!(output.digest, verifier_digest);

    // Re-parse transcript from a fresh challenger and verify digest agreement.
    let (_, reparse_digest) = crate::proof::StarkProof::from_data(
        &config,
        prover_statement.statement(),
        &output.proof,
        test_challenger(),
    )
    .expect("transcript re-parse should succeed");
    assert_eq!(output.digest, reparse_digest);
}

/// Minimal [`MultiAir`] wrapper for tests: a list of AIRs, each building its own
/// aux trace via [`LiftedAir::build_aux_trace`](crate::air::LiftedAir::build_aux_trace).
pub struct TestMultiAir<A> {
    pub airs: Vec<A>,
}

impl<A> TestMultiAir<A> {
    pub fn new(airs: Vec<A>) -> Self {
        Self { airs }
    }
}

impl<A> MultiAir<Felt, QuadFelt> for TestMultiAir<A>
where
    A: crate::air::LiftedAir<Felt, QuadFelt>,
{
    type Air = A;

    fn airs(&self) -> &[Self::Air] {
        &self.airs
    }
}

/// Prove and verify multiple traces sharing one AIR.
pub fn prove_and_verify<A>(air: &A, air_inputs: &[Felt], traces: &[RowMajorMatrix<Felt>])
where
    A: crate::air::LiftedAir<Felt, QuadFelt> + Clone,
{
    let airs: Vec<A> = core::iter::repeat_n(air.clone(), traces.len()).collect();
    let traces_owned: Vec<RowMajorMatrix<Felt>> = traces.to_vec();
    let statement = Statement::new(TestMultiAir::new(airs), air_inputs.to_vec(), Vec::new())
        .expect("statement inputs valid");
    let prover_statement =
        ProverStatement::new(statement, traces_owned).expect("trace shape valid");
    prove_and_verify_statement(&prover_statement);
}
