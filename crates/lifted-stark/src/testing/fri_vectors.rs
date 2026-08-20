//! Standalone FRI test-vector generation.
//!
//! Produces a fold-4 quadratic-extension FRI proof over a random polynomial together with the
//! per-round openings, in a plain-data form that cross-crate tests (e.g. the Miden VM's MASM
//! FRI verifier tests) can repackage without access to this crate's internals.
//!
//! The caller supplies the LMCS and challenger so the vectors can be generated with production
//! hashing components (the Miden VM tests need the miden-crypto Poseidon2 permutation, not the
//! plain Plonky3 one used by this crate's own test configs).

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use miden_stark_transcript::{ProverTranscript, TranscriptChallenger, VerifierTranscript};
use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
use p3_field::{ExtensionField, PrimeField64, TwoAdicField};
use p3_matrix::{Matrix as _, bitrev::BitReversibleMatrix, dense::RowMajorMatrix};
use p3_util::reverse_bits_len;
use rand::{
    RngExt, SeedableRng,
    distr::{Distribution, StandardUniform},
    rngs::SmallRng,
};

use super::canonical_domain;
use crate::{
    domain::Coset,
    lmcs::{Lmcs, proof::BatchProofView, tree_indices::TreeIndices},
    pcs::fri::{FriParams, proof::FriProof, prover::FriPolys, verifier::FriOracle},
    testing::params::FRI_FOLD_ARITY_4,
};

/// Number of evaluations folded in each FRI round.
pub const FOLD_ARITY: usize = FRI_FOLD_ARITY_4.arity();
/// Base-two logarithm of [`FOLD_ARITY`].
pub const LOG_FOLD_ARITY: u8 = FRI_FOLD_ARITY_4.log_arity();
/// Base-field elements in one quadratic-extension value.
pub const EXTENSION_DEGREE: usize = 2;
/// Base-field elements in an LMCS digest.
pub const DIGEST_WIDTH: usize = 4;
/// Base-field elements in one fold-4 quadratic-extension opening.
pub const OPENING_ROW_WIDTH: usize = FOLD_ARITY * EXTENSION_DEGREE;

const MIN_NUM_QUERIES: usize = 2; // both domain boundaries

/// One query against the initial FRI codeword.
#[derive(Clone, Copy, Debug)]
pub struct FriQuery {
    /// Codeword evaluation at the queried position, in extension-field basis order.
    pub evaluation: [u64; EXTENSION_DEGREE],
    /// Queried position in the initial domain.
    pub position: u64,
    /// `g^position`, where `g` is the initial domain generator.
    pub domain_generator_power: u64,
}

/// One authenticated row opening in a FRI round.
#[derive(Clone, Debug)]
pub struct FriRoundOpening {
    /// Tree index of the opened row in the round's (folded) domain.
    pub index: usize,
    /// The opened row: 4 extension elements flattened to 8 base-field elements.
    pub row: [u64; OPENING_ROW_WIDTH],
    /// The LMCS digest of the row (the Merkle leaf).
    pub leaf_digest: [u64; DIGEST_WIDTH],
    /// Sibling digests along the authentication path, leaf to root.
    pub path: Vec<[u64; DIGEST_WIDTH]>,
}

/// A fold-4 quadratic-extension FRI proof unpacked into plain data.
///
/// All values are canonical `u64` representations so consumers need no field-type coupling.
#[derive(Clone, Debug)]
pub struct Fold4Ext2TestVectors {
    /// Per-round LMCS commitments.
    pub commitments: Vec<[u64; DIGEST_WIDTH]>,
    /// Per-round folding challenges as extension-field basis coefficients.
    pub betas: Vec<[u64; EXTENSION_DEGREE]>,
    /// Final (remainder) polynomial coefficients in descending degree order, as consecutive
    /// basis-coefficient pairs.
    pub final_poly: Vec<u64>,
    /// Per-round authenticated row openings.
    pub round_openings: Vec<Vec<FriRoundOpening>>,
    /// Queries against the initial FRI codeword.
    pub queries: Vec<FriQuery>,
    /// Generator of the initial evaluation domain.
    pub domain_generator: u64,
}

/// Proves a FRI claim over a random polynomial of degree less than `2^log_poly_degree` using
/// fold-4 layer folding over the quadratic extension field, verifies it, then unpacks the proof.
///
/// Folding proceeds until the final polynomial has exactly `2^log_final_degree` coefficients, so
/// `log_poly_degree - log_final_degree` must be even. Folding PoW is disabled and query positions
/// are selected by the fixture rather than sampled from the transcript. These vectors exercise
/// transcript-derived folding challenges, fold consistency, Merkle authentication, and the
/// remainder check.
///
/// The LMCS must be non-hiding: leaf digests are recomputed from the opened rows without salt.
///
/// # Panics
///
/// Panics if the extension degree is not 2, the final degree exceeds the source degree, fold-4
/// cannot land exactly on the requested final degree, the domain parameters are invalid, or
/// `num_queries` is outside `2..=lde_size`.
pub fn fold4_ext2_test_vectors<F, EF, L, Chal>(
    lmcs: &L,
    challenger: &Chal,
    log_poly_degree: u8,
    log_blowup: u8,
    log_final_degree: u8,
    num_queries: usize,
    seed: u64,
) -> Fold4Ext2TestVectors
where
    F: TwoAdicField + PrimeField64,
    EF: ExtensionField<F>,
    StandardUniform: Distribution<EF>,
    L: Lmcs<F = F>,
    L::Commitment: Into<[F; DIGEST_WIDTH]>,
    Chal: Clone + TranscriptChallenger<F, L::Commitment>,
{
    assert_eq!(
        EF::DIMENSION,
        EXTENSION_DEGREE,
        "fold4_ext2 vectors require a quadratic extension field"
    );
    assert!(
        log_final_degree <= log_poly_degree,
        "final degree must not exceed the polynomial degree"
    );
    assert_eq!(
        (log_poly_degree - log_final_degree) % LOG_FOLD_ARITY,
        0,
        "fold-4 folding must land exactly on the final degree"
    );

    let domain = canonical_domain::<F>(log_poly_degree, log_blowup);
    let poly_degree = domain.trace_height();
    let lde_size = domain.lde_height();
    let log_domain = domain.log_lde_height();
    assert!(
        (MIN_NUM_QUERIES..=lde_size).contains(&num_queries),
        "num_queries must be between 2 and the LDE domain size"
    );

    let params = FriParams {
        fold: FRI_FOLD_ARITY_4,
        log_final_degree,
        folding_pow_bits: 0,
    };
    let mut rng = SmallRng::seed_from_u64(seed);

    // Evaluations of a random polynomial on the LDE domain, in bit-reversed order.
    let dft = Radix2DFTSmallBatch::<F>::default();
    let evals = RowMajorMatrix::<EF>::rand(&mut rng, poly_degree, 1);
    let evals = dft
        .coset_lde_algebra_batch(evals, log_blowup as usize, F::ONE)
        .bit_reverse_rows()
        .to_row_major_matrix()
        .values;
    assert_eq!(evals.len(), lde_size, "LDE output must match the declared domain");

    // Sample distinct query positions in domain order, always including both domain
    // boundaries so the first and last Merkle leaves are exercised.
    let mut positions = BTreeSet::from([0, lde_size - 1]);
    while positions.len() < num_queries {
        positions.insert(rng.random_range(0..lde_size));
    }
    let query_positions: Vec<usize> = positions.into_iter().collect();
    let tree_indices = TreeIndices::new(query_positions.iter().copied(), log_domain)
        .expect("query positions are in range");

    // Run the FRI commit and query phases, writing the proof to the transcript.
    let mut channel = ProverTranscript::new(challenger.clone());
    let fri_polys = FriPolys::<F, EF, _>::new(&params, lmcs, &domain, evals.clone(), &mut channel);
    fri_polys.prove_queries(&params, tree_indices.clone(), &mut channel);
    let (_digest, transcript) = channel.finalize();

    // Verify the proof before exporting it as test vectors. The verifier consumes a fresh view of
    // the transcript because the next pass re-parses the same data into its plain-data form.
    let initial_evals: BTreeMap<usize, EF> = query_positions
        .iter()
        .map(|&position| {
            let bit_reversed = reverse_bits_len(position, log_domain as usize);
            (position, evals[bit_reversed])
        })
        .collect();
    let mut verify_channel = VerifierTranscript::from_data(challenger.clone(), &transcript);
    let oracle = FriOracle::<F, EF, L>::new(&params, &domain, &mut verify_channel)
        .expect("FRI verifier should read the commit phase");
    oracle
        .test_low_degree(lmcs, &params, initial_evals, tree_indices.clone(), &mut verify_channel)
        .expect("generated FRI proof should verify");
    verify_channel
        .finalize()
        .expect("verified FRI transcript should be fully consumed");

    // Re-parse the transcript: commit-phase data first, then the per-round batch openings.
    let mut channel = VerifierTranscript::from_data(challenger.clone(), &transcript);
    let proof = FriProof::<F, EF, _>::read_from_channel(&params, &domain, &mut channel)
        .expect("commit phase should re-parse");

    let mut round_openings = Vec::new();
    let mut round_indices = tree_indices;
    for _ in &proof.rounds {
        round_indices.shrink_depth(LOG_FOLD_ARITY);
        let batch = lmcs
            .read_batch_proof(&[OPENING_ROW_WIDTH], &round_indices, &mut channel)
            .expect("round openings should re-parse");

        let mut openings = Vec::new();
        for index in batch.indices() {
            let rows = batch.opening(index).expect("opening must exist for query index");
            let siblings = batch.path(index).expect("path must exist for query index");
            let leaf_digest: [F; DIGEST_WIDTH] = lmcs.hash(rows.iter_rows()).into();
            let row: [F; OPENING_ROW_WIDTH] =
                rows.as_slice().try_into().expect("fold-4/ext2 opening has the expected width");
            openings.push(FriRoundOpening {
                index,
                row: row.map(|v| v.as_canonical_u64()),
                leaf_digest: leaf_digest.map(|d| d.as_canonical_u64()),
                path: siblings
                    .into_iter()
                    .map(|sibling| {
                        let digest: [F; DIGEST_WIDTH] = sibling.into();
                        digest.map(|d| d.as_canonical_u64())
                    })
                    .collect(),
            });
        }
        round_openings.push(openings);
    }
    channel.finalize().expect("FRI transcript should be fully consumed");

    // `evals` is in bit-reversed order while positions are in domain order.
    let generator = domain.lde_coset().subgroup().generator();
    let queries = query_positions
        .iter()
        .map(|&p| {
            let eval = &evals[reverse_bits_len(p, log_domain as usize)];
            FriQuery {
                evaluation: canonical_extension_coefficients::<F, EF>(eval),
                position: p as u64,
                domain_generator_power: generator.exp_u64(p as u64).as_canonical_u64(),
            }
        })
        .collect();

    Fold4Ext2TestVectors {
        commitments: proof
            .rounds
            .iter()
            .map(|r| {
                let com: [F; DIGEST_WIDTH] = r.commitment.clone().into();
                com.map(|c| c.as_canonical_u64())
            })
            .collect(),
        betas: proof
            .rounds
            .iter()
            .map(|r| canonical_extension_coefficients::<F, EF>(&r.beta))
            .collect(),
        final_poly: proof
            .final_poly
            .iter()
            .flat_map(canonical_extension_coefficients::<F, EF>)
            .collect(),
        round_openings,
        queries,
        domain_generator: generator.as_canonical_u64(),
    }
}

fn canonical_extension_coefficients<F, EF>(value: &EF) -> [u64; EXTENSION_DEGREE]
where
    F: PrimeField64,
    EF: ExtensionField<F>,
{
    let coefficients: &[F; EXTENSION_DEGREE] = value
        .as_basis_coefficients_slice()
        .try_into()
        .expect("extension degree was validated");
    coefficients.map(|coefficient| coefficient.as_canonical_u64())
}
