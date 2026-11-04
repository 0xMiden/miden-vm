use miden_air::vm::config;
use miden_core::{
    Felt, WORD_SIZE, Word,
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
};
use miden_stark::{
    StarkConfig,
    testing::{
        FriFold,
        fri_vectors::{
            DIGEST_WIDTH, EXTENSION_DEGREE, Fold4Ext2TestVectors, FriQuery, LOG_FOLD_ARITY,
            fold4_ext2_test_vectors,
        },
    },
};
use miden_utils_testing::crypto::{MerklePath, PartialMerkleTree};
use miden_vm_stark::setup::config::eidos_config;

const NUM_DISTINCT_QUERIES: usize = 32;
const TEST_SEED: u64 = 42;

const _: () = assert!(DIGEST_WIDTH == WORD_SIZE);

type AdvMap = Vec<(Word, Vec<Felt>)>;

pub(super) struct FriResult {
    /// Merkle authentication paths for the opened rows, one partial tree per FRI round.
    pub partial_trees: Vec<PartialMerkleTree>,

    /// Entries used to unhash Merkle nodes to field-element rows representing the query values.
    pub advice_maps: AdvMap,

    /// Queries against the initial FRI codeword.
    pub queries: Vec<FriQuery>,

    /// Folding challenges as extension-field basis coefficients `(a0, a1)`.
    pub alphas: Vec<[u64; EXTENSION_DEGREE]>,

    /// Merkle-tree layer commitments `(c0, c1, c2, c3)`.
    pub commitments: Vec<[u64; DIGEST_WIDTH]>,

    /// The remainder polynomial coefficients in descending degree order, as consecutive (r0, r1).
    pub remainder: Vec<u64>,

    /// The generator of the initial evaluation domain.
    pub domain_generator: u64,

    /// Folded-domain point, index, and extension value for each input query, in query order.
    pub final_queries: Vec<[Felt; WORD_SIZE]>,
}

/// Proves a FRI claim with fold-4 layer folding over the quadratic extension field and repackages
/// the proof into the non-deterministic inputs needed to verify it inside the Miden VM.
///
/// The proof is generated over a random polynomial of degree less than `2^log_poly_degree` and
/// uses the native maximum remainder bound to choose the number of folding rounds.
pub(super) fn fri_prove_verify_fold4_ext2(log_poly_degree: u8, log_blowup: u8) -> FriResult {
    let Fold4Ext2TestVectors {
        commitments,
        betas,
        final_poly,
        round_openings,
        mut queries,
        domain_generator,
    } = {
        // Use the production Eidos components so Merkle nodes match the VM's native hash.
        let stark_config = eidos_config(config::pcs_params(), config::RELATION_DIGEST);
        fold4_ext2_test_vectors::<Felt, QuadFelt, _, _, _>(
            stark_config.lmcs(),
            &stark_config.challenger(),
            log_poly_degree,
            log_blowup,
            config::pcs_params().log_final_degree(),
            NUM_DISTINCT_QUERIES,
            TEST_SEED,
            |commitment| {
                let limbs: [u64; DIGEST_WIDTH] = commitment.into();
                limbs.map(|limb| limb % Felt::ORDER)
            },
        )
    };

    assert_eq!(
        round_openings.len(),
        commitments.len(),
        "each FRI round must have openings and a commitment"
    );
    assert_eq!(betas.len(), commitments.len(), "each FRI round must have one folding challenge");

    // FRI sampling permits duplicates. Include a repeated index alongside the distinct queries.
    queries.push(queries[0]);
    let folder = FriFold::new(LOG_FOLD_ARITY).unwrap();
    let generator = Felt::new_unchecked(domain_generator);
    let remainder_coefficients = final_poly.len() / EXTENSION_DEGREE;
    let log_reduction = log_poly_degree - remainder_coefficients.ilog2() as u8;
    let final_generator = generator.exp_power_of_2(log_reduction.into());
    let final_size = (remainder_coefficients as u64) << log_blowup;
    let final_queries = queries
        .iter()
        .map(|query| {
            let index = query.position & (final_size - 1);
            // The vector generator verifies every FRI round. Recompute its last fold to expose
            // the terminal value independently of the remainder polynomial evaluation below.
            let value = match round_openings.last().zip(betas.last()) {
                Some((openings, beta)) => {
                    let opening = openings.iter().find(|o| o.index as u64 == index).unwrap();
                    let row: Vec<_> = opening
                        .row
                        .as_chunks::<EXTENSION_DEGREE>()
                        .0
                        .iter()
                        .map(|pair| QuadFelt::new(pair.map(Felt::new_unchecked)))
                        .collect();
                    let last_generator =
                        generator.exp_power_of_2((log_reduction - LOG_FOLD_ARITY).into());
                    folder.fold_evals(
                        &row,
                        last_generator.exp_u64(index).inverse(),
                        QuadFelt::new(beta.map(Felt::new_unchecked)),
                    )
                },
                None => QuadFelt::new(query.evaluation.map(Felt::new_unchecked)),
            };
            let point = final_generator.exp_u64(index);
            let remainder_value = final_poly
                .as_chunks::<EXTENSION_DEGREE>()
                .0
                .iter()
                .fold(QuadFelt::ZERO, |acc, pair| {
                    acc * point + QuadFelt::new(pair.map(Felt::new_unchecked))
                });
            assert_eq!(value, remainder_value, "native fold must match the remainder polynomial");
            let coefficients = value.as_basis_coefficients_slice();
            [point, Felt::new_unchecked(index), coefficients[0], coefficients[1]]
        })
        .collect();

    // Convert each round's openings into a partial Merkle tree (for the Merkle store) and
    // `leaf_hash -> leaf_data` advice-map entries.
    let mut partial_trees = Vec::with_capacity(round_openings.len());
    let mut advice_maps = Vec::new();
    for (round, (openings, &commitment)) in round_openings.iter().zip(&commitments).enumerate() {
        let mut paths = Vec::with_capacity(openings.len());
        for opening in openings {
            let leaf_word = to_word(opening.leaf_digest);
            let merkle_path =
                MerklePath::new(opening.path.iter().map(|&sibling| to_word(sibling)).collect());
            paths.push((opening.index as u64, leaf_word, merkle_path));
            let row: Vec<Felt> = opening.row.iter().map(|&v| Felt::new_unchecked(v)).collect();
            advice_maps.push((leaf_word, row));
        }
        let tree = PartialMerkleTree::with_paths(paths).expect("openings form a consistent tree");
        assert_eq!(
            tree.root(),
            to_word(commitment),
            "round {round} openings must authenticate to the transcript commitment"
        );
        partial_trees.push(tree);
    }

    // The MASM evaluators stream the configured maximum or half that many coefficients.
    let remainder = final_poly;
    assert!(
        remainder.len().is_multiple_of(EXTENSION_DEGREE),
        "remainder must contain complete extension-field coefficients"
    );
    let remainder_coefficients = remainder.len() / EXTENSION_DEGREE;
    let max_coefficients = 1 << config::pcs_params().log_final_degree();
    assert!(
        [max_coefficients / 2, max_coefficients].contains(&remainder_coefficients),
        "remainder must match one of the two MASM specializations"
    );

    FriResult {
        partial_trees,
        advice_maps,
        queries,
        // The MASM verifier calls the folding challenges alphas.
        alphas: betas,
        commitments,
        remainder,
        domain_generator,
        final_queries,
    }
}

fn to_word(digest: [u64; DIGEST_WIDTH]) -> Word {
    Word::new(digest.map(Felt::new_unchecked))
}
