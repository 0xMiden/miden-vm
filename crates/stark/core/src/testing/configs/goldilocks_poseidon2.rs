//! Goldilocks + Poseidon2 test configuration.
//!
//! Provides a complete set of type aliases, constructors, and helpers for testing
//! LMCS, PCS, and full STARK with Goldilocks field and Poseidon2 hashing.

use alloc::vec::Vec;

use p3_challenger::DuplexChallenger;
#[cfg(test)]
use p3_dft::Radix2DitParallel;
#[cfg(test)]
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_goldilocks::Poseidon2Goldilocks;
#[cfg(test)]
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::{Hash, TruncatedPermutation};
use rand::{SeedableRng, rngs::SmallRng};

pub use super::{Felt, PackedFelt, PackedQuadFelt, QuadFelt};
#[cfg(test)]
use crate::air::{ProverStatement, Statement};
use crate::{
    air::{LiftedAir, MultiAir},
    testing::TEST_SEED,
};

// =============================================================================
// Base field/hash configuration
// =============================================================================

/// Poseidon2 permutation width.
pub(crate) const WIDTH: usize = 12;

/// Sponge rate (elements absorbed per permutation).
pub(crate) const RATE: usize = 8;

/// Digest size in field elements.
pub(crate) const DIGEST: usize = 4;

/// Poseidon2 permutation.
pub(crate) type Perm = Poseidon2Goldilocks<WIDTH>;

/// Stateful sponge for hashing (can be used for LMCS).
pub(crate) type Sponge = miden_crypto::hash::stateful::StatefulSponge<Perm, WIDTH, RATE, DIGEST>;

/// Truncated permutation for 2-to-1 compression.
pub(crate) type Compress = TruncatedPermutation<Perm, 2, DIGEST, WIDTH>;

/// Commitment type (truncated permutation output).
pub type Commitment = Hash<Felt, Felt, DIGEST>;

/// Duplex challenger for Fiat-Shamir.
pub(crate) type Challenger = DuplexChallenger<Felt, Perm, WIDTH, RATE>;

/// Create the permutation with standard seed.
pub(crate) fn create_perm() -> Perm {
    let mut rng = SmallRng::seed_from_u64(TEST_SEED);
    Perm::new_from_rng_128(&mut rng)
}

/// Create standard test components with a consistent seed.
///
/// Returns the permutation, sponge, and compressor for Merkle tree construction.
#[cfg(test)]
pub(crate) fn test_components() -> (Perm, Sponge, Compress) {
    let perm = create_perm();
    let sponge = Sponge::new(perm.clone());
    let compress = Compress::new(perm.clone());
    (perm, sponge, compress)
}

/// Create a standard challenger for Fiat-Shamir.
pub(crate) fn test_challenger() -> Challenger {
    Challenger::new(create_perm())
}

// =============================================================================
// LMCS layer
// =============================================================================

/// LMCS configured with Goldilocks + Poseidon2.
pub(crate) type Lmcs =
    crate::lmcs::config::LmcsConfig<PackedFelt, PackedFelt, Sponge, Compress, WIDTH, DIGEST>;

crate::testing::define_lmcs_test_helpers!();

/// Create a test LMCS instance.
#[cfg(test)]
pub(crate) fn test_lmcs() -> Lmcs {
    let (_, sponge, compress) = test_components();
    crate::lmcs::config::LmcsConfig::new(sponge, compress)
}

// =============================================================================
// PCS layer
// =============================================================================

/// Generate a matrix of LDE evaluations for random low-degree polynomials.
#[cfg(test)]
pub(crate) fn random_lde_matrix<V>(
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

#[cfg(test)]
pub(crate) type Dft = Radix2DitParallel<Felt>;

#[cfg(test)]
pub(crate) type TestConfig =
    crate::config::GenericStarkConfig<Felt, QuadFelt, Lmcs, Dft, Challenger>;

#[cfg(test)]
pub(crate) fn test_config() -> TestConfig {
    crate::config::GenericStarkConfig::new(
        crate::testing::params::TEST_PCS_PARAMS,
        test_lmcs(),
        Dft::default(),
        test_challenger(),
    )
}

/// Generate a power-of-4 chain trace: `[start, start⁴, start¹⁶, start⁶⁴, ...]`
#[cfg(test)]
pub(crate) fn generate_pow4_trace(start: Felt, height: usize) -> RowMajorMatrix<Felt> {
    let mut values = Vec::with_capacity(height);
    let mut current = start;
    for _ in 0..height {
        values.push(current);
        current = current.exp_power_of_2(2);
    }
    RowMajorMatrix::new(values, 1)
}

/// Run the full prove → verify → transcript-reparse cycle.
#[cfg(test)]
pub(crate) fn prove_and_verify_statement<MA>(prover_statement: ProverStatement<Felt, QuadFelt, MA>)
where
    MA: MultiAir<Felt, QuadFelt>,
    <MA::Air as LiftedAir<Felt, QuadFelt>>::EvalData<PackedFelt, PackedQuadFelt>: Sync,
{
    let config = test_config();

    let prover_instance = crate::ProverInstance::new(&config, prover_statement, None)
        .expect("no preprocessed columns");
    let (output, statement) =
        prover_instance.prove(test_challenger()).expect("proving should succeed");

    let verifier_instance =
        crate::VerifierInstance::new(&config, &statement, None).expect("no preprocessed columns");
    let verifier_digest = verifier_instance
        .verify(&output.proof, test_challenger())
        .expect("verification should succeed");
    assert_eq!(output.digest, verifier_digest);

    // Re-parse transcript from a fresh challenger and verify digest agreement.
    let (_, reparse_digest) =
        crate::proof::StarkProof::from_data(&verifier_instance, &output.proof, test_challenger())
            .expect("transcript re-parse should succeed");
    assert_eq!(output.digest, reparse_digest);
}

/// Minimal [`MultiAir`] wrapper for tests: a list of AIRs, each building its own
/// aux trace via [`LiftedAir::build_aux_trace`].
pub struct TestMultiAir<A> {
    pub(crate) airs: Vec<A>,
}

impl<A> TestMultiAir<A> {
    #[cfg(test)]
    pub(crate) fn new(airs: Vec<A>) -> Self {
        Self { airs }
    }
}

impl<A> MultiAir<Felt, QuadFelt> for TestMultiAir<A>
where
    A: LiftedAir<Felt, QuadFelt>,
{
    type Air = A;

    fn airs(&self) -> &[Self::Air] {
        &self.airs
    }
}

/// Prove and verify multiple traces sharing one AIR.
#[cfg(test)]
pub(crate) fn prove_and_verify<A>(air: &A, air_inputs: &[Felt], traces: &[RowMajorMatrix<Felt>])
where
    A: LiftedAir<Felt, QuadFelt> + Clone,
    A::EvalData<PackedFelt, PackedQuadFelt>: Sync,
{
    let airs: Vec<A> = core::iter::repeat_n(air.clone(), traces.len()).collect();
    let traces_owned: Vec<RowMajorMatrix<Felt>> = traces.to_vec();
    let air_inputs = (0..airs.len()).map(|i| (i, air_inputs.to_vec())).collect();
    let statement = Statement::new(TestMultiAir::new(airs), air_inputs, Vec::new())
        .expect("statement inputs valid");
    let prover_statement =
        ProverStatement::new(statement, traces_owned).expect("trace shape valid");
    prove_and_verify_statement(prover_statement);
}
