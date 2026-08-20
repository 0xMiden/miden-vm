use alloc::collections::BTreeMap;

use miden_core::{WORD_SIZE, Word};
use miden_lifted_stark::testing::fri_vectors::{EXTENSION_DEGREE, FOLD_ARITY, LOG_FOLD_ARITY};
use miden_utils_testing::{Felt, crypto::MerkleStore};

mod verifier_fri_e2f4;
use verifier_fri_e2f4::{BLOWUP_EXP, FriResult, fri_prove_verify_fold4_ext2};

const ADVICE_LENGTH_PREFIXES: usize = 3; // queries, layers, and remainder

/// Elements per layer record: the commitment word followed by `[d_size, t_depth, a0, a1]`.
const LAYER_RECORD_WIDTH: usize = 2 * WORD_SIZE;

const FRI_PREPROCESS_SOURCE: &str = "
    use miden::core::stark::constants

    const MAX_FRI_QUERIES = 150
    const MAX_FRI_LAYERS = 32
    const MAX_FRI_REMAINDER_WORDS = 64

    #! Copies a non-empty sequence of words from the advice stack into memory.
    #!
    #! Input:  [X, num_words - 1, write_ptr, ...]
    #! Output: [X, x, write_ptr + 4 * num_words, ...]
    proc store_advice_words
        push.1
        while.true
            adv_loadw
            dup.5
            u32wrapping_add.4
            swap.6
            mem_storew_le
            dup.4
            sub.1
            swap.5
            neq.0
        end
    end

    proc preprocess
        dup exec.constants::set_lde_domain_generator
        adv_push
        # => [num_queries, g, ...]
        dup u32gt.0 assert.err=\"number of FRI queries must be nonzero\"
        dup u32lte.MAX_FRI_QUERIES assert.err=\"number of FRI queries exceeds FRI workspace\"

        exec.constants::fri_com_ptr
        # => [layer_ptr, num_queries, g, ...]
        dup.1 mul.4 sub
        # => [query_ptr, num_queries, g, ...]
        dup exec.constants::set_fri_queries_address
        swap
        sub.1
        padw
        # => [X, num_query_words - 1, query_ptr, layer_ptr, g]
        exec.store_advice_words
        #=> [X, x, layer_ptr, g]

        drop
        #=> [X, layer_ptr, g]

        dup.4
        movdn.5
        #=> [X, layer_ptr, layer_ptr, g]

        adv_push
        dup u32lte.MAX_FRI_LAYERS assert.err=\"number of FRI layers exceeds FRI workspace\"

        dup push.0 neq
        if.true
            mul.2
            sub.1
            movdn.4
            #=> [X, num_layer_words - 1, layer_ptr, layer_ptr, g]

            exec.store_advice_words
            #=> [X, x, remainder_poly_ptr, layer_ptr, g]

            drop
        else
            drop
        end
        #=> [X, remainder_poly_ptr, layer_ptr, g]

        dup.4
        movdn.5
        #=> [X, remainder_poly_ptr, remainder_poly_ptr, layer_ptr, g]

        adv_push
        dup u32gt.0 assert.err=\"FRI remainder polynomial must be nonzero\"
        dup u32lte.MAX_FRI_REMAINDER_WORDS assert.err=\"FRI remainder polynomial exceeds FRI workspace\"

        dup mul.2 exec.constants::set_remainder_poly_size

        sub.1
        movdn.4
        #=> [X, num_remainder_words - 1, remainder_poly_ptr, remainder_poly_ptr, layer_ptr, g]

        exec.store_advice_words
        #=> [X, x, x, remainder_poly_ptr, layer_ptr, g]
        dropw drop drop
        #=> [remainder_poly_ptr, layer_ptr, g]

        exec.constants::set_remainder_poly_address
        drop drop
    end
";

#[test]
fn fri_verify_rejects_empty_query_region() {
    let source = "
        use miden::core::pcs::fri::frie2f4
        use miden::core::stark::constants

        begin
            push.1 exec.constants::set_lde_domain_generator
            push.64 exec.constants::set_remainder_poly_size
            exec.constants::fri_com_ptr
            dup exec.constants::set_remainder_poly_address
            exec.constants::set_fri_queries_address
            exec.frie2f4::verify
        end
        ";

    let test = build_test!(source, &[]);
    expect_assert_error_code_from_msg!(test, "fri query region must be non-empty");
}

/// Everything needed to run `frie2f4::verify` on a freshly generated FRI proof.
struct FriTestData {
    source: String,
    domain_generator: u64,
    advice_stack: Vec<u64>,
    store: MerkleStore,
    advice_map: BTreeMap<Word, Vec<Felt>>,
}

/// Generates a fold-4 FRI proof over a random polynomial of degree less than
/// `2^log_poly_degree` and packages it as the preprocess + verify program with its inputs.
fn build_fri_test(log_poly_degree: u8, log_final_degree: u8) -> FriTestData {
    let source = format!(
        "{FRI_PREPROCESS_SOURCE}
        use miden::core::pcs::fri::frie2f4

        begin
            exec.preprocess
            exec.frie2f4::verify
        end
        "
    );

    let fri = fri_prove_verify_fold4_ext2(log_poly_degree, log_final_degree);
    let depth = log_poly_degree
        .checked_add(BLOWUP_EXP)
        .expect("FRI domain depth must fit in u8") as usize;
    let advice_stack = prepare_advice_stack(depth, &fri);

    let mut store = MerkleStore::new();
    for partial_tree in &fri.partial_trees {
        store.extend(partial_tree.inner_nodes());
    }

    FriTestData {
        source,
        domain_generator: fri.domain_generator,
        advice_stack,
        store,
        advice_map: BTreeMap::from_iter(fri.advice_maps),
    }
}

#[test]
fn fri_fold4_ext2_remainder64() {
    let t = build_fri_test(14, 6);
    let test =
        build_test!(&t.source, &[t.domain_generator], &t.advice_stack, t.store, t.advice_map);
    test.expect_stack(&[]);
}

#[test]
fn fri_fold4_ext2_remainder128() {
    let t = build_fri_test(13, 7);
    let test =
        build_test!(&t.source, &[t.domain_generator], &t.advice_stack, t.store, t.advice_map);
    test.expect_stack(&[]);
}

/// A tampered remainder coefficient must make verification fail: the Horner evaluation of the
/// remainder polynomial no longer matches the folded query values.
#[test]
fn fri_fold4_ext2_rejects_tampered_remainder() {
    let mut t = build_fri_test(14, 6);
    *t.advice_stack.last_mut().unwrap() += 1;
    let test =
        build_test!(&t.source, &[t.domain_generator], &t.advice_stack, t.store, t.advice_map);
    assert!(test.execute().is_err());
}

/// A tampered opened row must make verification fail: the row no longer hashes to the
/// authenticated Merkle leaf.
#[test]
fn fri_fold4_ext2_rejects_tampered_leaf() {
    let mut t = build_fri_test(14, 6);
    t.advice_map.first_entry().unwrap().get_mut()[0] += Felt::new_unchecked(1);
    let test =
        build_test!(&t.source, &[t.domain_generator], &t.advice_stack, t.store, t.advice_map);
    assert!(test.execute().is_err());
}

fn prepare_advice_stack(depth: usize, fri: &FriResult) -> Vec<u64> {
    assert!(fri.remainder.len().is_multiple_of(WORD_SIZE), "remainder must be word-aligned");
    assert_eq!(
        fri.alphas.len(),
        fri.commitments.len(),
        "each layer must have one folding challenge"
    );

    let domain_size = 1u64
        .checked_shl(u32::try_from(depth).expect("domain depth must fit in u32"))
        .expect("domain depth must fit in u64");
    let advice_length = ADVICE_LENGTH_PREFIXES
        + fri.queries.len() * WORD_SIZE
        + fri.commitments.len() * LAYER_RECORD_WIDTH
        + fri.remainder.len();
    let mut stack = Vec::with_capacity(advice_length);

    stack.push(fri.queries.len() as u64);

    for query in &fri.queries {
        let [e0, e1] = query.evaluation;
        // The VM represents each query as the word [g^p, p, e0, e1].
        let query_word: [u64; WORD_SIZE] = [query.domain_generator_power, query.position, e0, e1];
        stack.extend_from_slice(&query_word);
    }

    stack.push(fri.commitments.len() as u64);

    let mut current_domain_size = domain_size;
    let mut current_depth = depth as u64;

    for (commitment, alpha) in fri.commitments.iter().zip(&fri.alphas) {
        current_domain_size /= FOLD_ARITY as u64;
        current_depth = current_depth
            .checked_sub(LOG_FOLD_ARITY.into())
            .expect("too many FRI layers for the domain");

        stack.extend_from_slice(commitment);
        // The VM loads this metadata as the word [d_size, t_depth, a0, a1].
        stack.extend_from_slice(&[current_domain_size, current_depth]);
        stack.extend_from_slice(alpha);
    }

    let remainder_coefficients = fri.remainder.len() / EXTENSION_DEGREE;
    assert_eq!(
        current_domain_size,
        (remainder_coefficients as u64) << BLOWUP_EXP,
        "folded domain size must match the remainder degree and blowup"
    );

    stack.push((fri.remainder.len() / WORD_SIZE) as u64);
    for word in fri.remainder.chunks_exact(WORD_SIZE) {
        stack.extend_from_slice(word);
    }

    assert_eq!(stack.len(), advice_length, "advice stack must match the computed layout");

    stack
}
