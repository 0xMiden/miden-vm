use miden_air::config;
use miden_core::{Felt, WORD_SIZE, Word, field::QuadFelt};
use miden_lifted_stark::{
    StarkConfig,
    testing::fri_vectors::{
        DIGEST_WIDTH, EXTENSION_DEGREE, Fold4Ext2TestVectors, FriQuery, fold4_ext2_test_vectors,
    },
};
use miden_utils_testing::crypto::{MerklePath, PartialMerkleTree};

pub(super) const BLOWUP_EXP: u8 = 3;
const NUM_FRI_QUERIES: usize = 32;
const REMAINDER_64_COEFFICIENTS: usize = 64;
const REMAINDER_128_COEFFICIENTS: usize = 128;
const SUPPORTED_REMAINDER_SIZES: &[usize] =
    &[REMAINDER_64_COEFFICIENTS, REMAINDER_128_COEFFICIENTS];
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
}

/// Proves a FRI claim with fold-4 layer folding over the quadratic extension field and repackages
/// the proof into the non-deterministic inputs needed to verify it inside the Miden VM.
///
/// The proof is generated over a random polynomial of degree less than `2^log_poly_degree` and
/// folds down to a remainder polynomial of exactly `2^log_final_degree` extension-field
/// coefficients.
pub(super) fn fri_prove_verify_fold4_ext2(log_poly_degree: u8, log_final_degree: u8) -> FriResult {
    let Fold4Ext2TestVectors {
        commitments,
        betas,
        final_poly,
        round_openings,
        queries,
        domain_generator,
    } = {
        // Use the production Poseidon2 components so Merkle nodes match the VM's native hash.
        let stark_config = config::poseidon2_config(config::pcs_params(), config::RELATION_DIGEST);
        fold4_ext2_test_vectors::<Felt, QuadFelt, _, _>(
            stark_config.lmcs(),
            &stark_config.challenger(),
            log_poly_degree,
            BLOWUP_EXP,
            log_final_degree,
            NUM_FRI_QUERIES,
            TEST_SEED,
        )
    };

    // Convert each round's openings into a partial Merkle tree (for the Merkle store) and
    // `leaf_hash -> leaf_data` advice-map entries.
    assert_eq!(
        round_openings.len(),
        commitments.len(),
        "each FRI round must have openings and a commitment"
    );
    assert_eq!(betas.len(), commitments.len(), "each FRI round must have one folding challenge");

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

    // The MASM evaluators stream a fixed 64 or 128 extension coefficients, so only these two
    // remainder sizes are meaningful.
    let remainder = final_poly;
    assert!(
        remainder.len().is_multiple_of(EXTENSION_DEGREE),
        "remainder must contain complete extension-field coefficients"
    );
    let remainder_coefficients = remainder.len() / EXTENSION_DEGREE;
    assert!(
        SUPPORTED_REMAINDER_SIZES.contains(&remainder_coefficients),
        "remainder must encode 64 or 128 quadratic-extension coefficients"
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
    }
}

fn to_word(digest: [u64; DIGEST_WIDTH]) -> Word {
    Word::new(digest.map(Felt::new_unchecked))
}
