use miden_core_lib::handlers::smt_peek::SMT_PEEK_EVENT_NAME;
use miden_utils_testing::PrimeField64;

use super::*;

// TEST DATA
// ================================================================================================

const fn word(e0: u64, e1: u64, e2: u64, e3: u64) -> Word {
    Word::new([Felt::new(e0), Felt::new(e1), Felt::new(e2), Felt::new(e3)])
}

/// Note: We never insert at the same key twice. This is so that the `smt::get` test can loop over
/// leaves, get the associated value, and compare. We test inserting at the same key twice in tests
/// that use different data.
const LEAVES: [(Word, Word); 2] = [
    (
        word(101, 102, 103, 104),
        // Most significant Felt differs from previous
        word(1_u64, 2_u64, 3_u64, 4_u64),
    ),
    (word(105, 106, 107, 108), word(5_u64, 6_u64, 7_u64, 8_u64)),
];

/// Unlike the above `LEAVES`, these leaves use the same value for their most-significant felts, to
/// test leaves with multiple pairs.
const LEAVES_MULTI: [(Word, Word); 3] = [
    (word(101, 102, 103, 69420), word(0x1, 0x2, 0x3, 0x4)),
    // Most significant felt does NOT differ from previous.
    (word(201, 202, 203, 69420), word(0xb, 0xc, 0xd, 0xe)),
    // A key in the same leaf, but with no corresponding value.
    (word(301, 302, 303, 69420), EMPTY_WORD),
];

/// Tests `get` on every key present in the SMT, as well as an empty leaf
#[test]
fn test_smt_get() {
    fn expect_value_from_get(key: Word, value: Word, smt: &Smt) {
        let source = "
            use miden::core::collections::smt

            begin
                exec.smt::get
            end
        ";
        let root = smt.root();
        let mut initial_stack = Vec::new();
        push_word(&mut initial_stack, &root);
        push_word(&mut initial_stack, &key);
        let expected_output = build_expected_stack(value, smt.root());

        let (store, advice_map) = build_advice_inputs(smt);
        build_test!(source, &initial_stack, &[], store, advice_map).expect_stack(&expected_output);
    }

    let smt = build_smt_from_pairs(&LEAVES);

    // Get all leaves present in tree
    for (key, value) in LEAVES {
        expect_value_from_get(key, value, &smt);
    }

    // Get an empty leaf
    expect_value_from_get(
        Word::new([Felt::from_u32(42), Felt::from_u32(42), Felt::from_u32(42), Felt::from_u32(42)]),
        EMPTY_WORD,
        &smt,
    );
}

#[test]
fn test_smt_get_multi() {
    const SOURCE: &str = "
        use miden::core::collections::smt
        use miden::core::sys

        begin
            # => [K, R]
            exec.smt::get
            # => [V, R]

            exec.sys::truncate_stack
        end
    ";

    fn expect_value_from_get(key: Word, value: Word, smt: &Smt) {
        let root = smt.root();
        let mut initial_stack: Vec<u64> = Default::default();
        push_word(&mut initial_stack, &root);
        push_word(&mut initial_stack, &key);
        let expected_output = build_expected_stack(value, smt.root());

        let (store, advice_map) = build_advice_inputs(smt);
        build_test!(SOURCE, &initial_stack, &[], store, advice_map).expect_stack(&expected_output);
    }

    let smt = build_smt_from_pairs(&LEAVES_MULTI);

    let (k0, v0) = LEAVES_MULTI[0];
    let (k1, v1) = LEAVES_MULTI[1];
    let (k2, v_empty) = LEAVES_MULTI[2];

    expect_value_from_get(k0, v0, &smt);
    expect_value_from_get(k1, v1, &smt);
    expect_value_from_get(k2, v_empty, &smt);
}

/// Tests inserting and removing key-value pairs to an SMT. We do the insert/removal twice to ensure
/// that the removal properly updates the advice map/stack.
#[test]
fn test_smt_set() {
    fn assert_insert_and_remove(smt: &mut Smt) {
        let empty_tree_root = smt.root();

        let source = "
            use miden::core::collections::smt

            begin
                exec.smt::set
                movupw.2 dropw
            end
        ";

        // insert values one-by-one into the tree
        let mut old_roots = Vec::new();
        for (key, value) in LEAVES {
            let root = smt.root();
            old_roots.push(root);
            let (init_stack, final_stack, store, advice_map) =
                prepare_insert_or_set(key, value, smt);
            build_test!(source, &init_stack, &[], store, advice_map).expect_stack(&final_stack);
        }

        // setting to [ZERO; 4] should return the tree to the prior state
        for (key, old_value) in LEAVES.iter().rev() {
            let value = EMPTY_WORD;
            let (init_stack, final_stack, store, advice_map) =
                prepare_insert_or_set(*key, value, smt);

            let poped_root = old_roots.pop().unwrap();
            let expected_final_stack = build_expected_stack(*old_value, poped_root);
            assert_eq!(expected_final_stack, final_stack);
            build_test!(source, &init_stack, &[], store, advice_map).expect_stack(&final_stack);
        }

        assert_eq!(smt.root(), empty_tree_root);
    }

    let mut smt = Smt::new();

    assert_insert_and_remove(&mut smt);
    assert_insert_and_remove(&mut smt);
}

/// Tests updating an existing key with a different value
#[test]
fn test_smt_set_same_key() {
    let mut smt = build_smt_from_pairs(&LEAVES);

    let source = "
    use miden::core::collections::smt
    begin
      exec.smt::set
    end
    ";

    let key = LEAVES[0].0;
    let value = [Felt::from_u32(42323); 4].into();
    let (init_stack, final_stack, store, advice_map) = prepare_insert_or_set(key, value, &mut smt);
    build_test!(source, &init_stack, &[], store, advice_map).expect_stack(&final_stack);
}

/// Tests inserting an empty value to an empty tree
#[test]
fn test_smt_set_empty_value_to_empty_leaf() {
    let mut smt = Smt::new();
    let empty_tree_root = smt.root();

    let source = "
    use miden::core::collections::smt
    begin
      exec.smt::set
    end
    ";

    let key =
        Word::new([Felt::from_u32(41), Felt::from_u32(42), Felt::from_u32(43), Felt::from_u32(44)]);
    let value = EMPTY_WORD;
    let (init_stack, final_stack, store, advice_map) = prepare_insert_or_set(key, value, &mut smt);
    build_test!(source, &init_stack, &[], store, advice_map).expect_stack(&final_stack);

    assert_eq!(smt.root(), empty_tree_root);
}

/// Tests that the advice map is properly updated after a `set` on an empty key
#[test]
fn test_set_advice_map_empty_key() {
    let mut smt = Smt::new();

    let source = format!(
        "
    use miden::core::collections::smt
    # Stack: [V, K, R]
    begin
        # copy V and K, and save lower on stack
        dupw.1 movdnw.3 dupw movdnw.3
        # => [V, K, R, V, K]

        # Sets the advice map
        exec.smt::set
        # => [V_old, R_new, V, K]

        # Prepare for peek
        dropw movupw.2
        # => [K, R_new, V]

        # Fetch what was stored on advice map and clean stack
        emit.event(\"{SMT_PEEK_EVENT_NAME}\") dropw dropw
        # => [V]

        # Push advice map values on stack
        padw adv_loadw
        # => [V_in_map, V]

        # Check for equality of V's
        assert_eqw
        # => [K]
    end
    "
    );

    let key =
        Word::new([Felt::from_u32(41), Felt::from_u32(42), Felt::from_u32(43), Felt::from_u32(44)]);
    let value: [Felt; 4] = [Felt::from_u32(42323); 4];
    let (init_stack, _, store, advice_map) = prepare_insert_or_set(key, value.into(), &mut smt);

    // assert is checked in MASM
    build_test!(source, &init_stack, &[], store, advice_map).execute().unwrap();
}

/// Tests that the advice map is properly updated after a `set` on a key that has existing value
#[test]
fn test_set_advice_map_single_key() {
    let mut smt = build_smt_from_pairs(&LEAVES);

    let source = format!(
        "
    use miden::core::collections::smt
    # Stack: [V, K, R]
    begin
        # copy V and K, and save lower on stack
        dupw.1 movdnw.3 dupw movdnw.3
        # => [V, K, R, V, K]

        # Sets the advice map
        exec.smt::set
        # => [V_old, R_new, V, K]

        # Prepare for peek
        dropw movupw.2
        # => [K, R_new, V]

        # Fetch what was stored on advice map and clean stack
        emit.event(\"{SMT_PEEK_EVENT_NAME}\") dropw dropw
        # => [V]

        # Push advice map values on stack
        padw adv_loadw
        # => [V_in_map, V]

        # Check for equality of V's
        assert_eqw
        # => [K]
    end"
    );

    let key = LEAVES[0].0;
    let value: [Felt; 4] = [Felt::from_u32(42323); 4];
    let (init_stack, _, store, advice_map) = prepare_insert_or_set(key, value.into(), &mut smt);

    // assert is checked in MASM
    build_test!(source, &init_stack, &[], store, advice_map).execute().unwrap();
}

/// Tests setting an empty value to an empty key, but that maps to a leaf with another key
/// (i.e. removing a value that's already empty)
#[test]
fn test_set_empty_key_in_non_empty_leaf() {
    let leaf_idx = Felt::new(42);

    let leaves: [(Word, Word); 1] = [(
        Word::new([leaf_idx, Felt::new(102), Felt::new(103), Felt::new(104)]),
        Word::new([Felt::new(1_u64), Felt::new(2_u64), Felt::new(3_u64), Felt::new(4_u64)]),
    )];

    let mut smt = build_smt_from_pairs(&leaves);

    // This key has same K[0] (leaf index element) as key in the existing leaf, so will map to
    // the same leaf
    let new_key = Word::new([leaf_idx, Felt::new(12), Felt::new(3), Felt::new(4)]);

    let source = "
    use miden::core::collections::smt

    begin
        exec.smt::set
        movupw.2 dropw
    end
    ";
    let (init_stack, final_stack, store, advice_map) =
        prepare_insert_or_set(new_key, EMPTY_WORD, &mut smt);

    build_test!(source, &init_stack, &[], store, advice_map).expect_stack(&final_stack);
}

#[test]
fn test_smt_set_single_to_multi() {
    const SOURCE: &str = "
        use miden::core::collections::smt
        use miden::core::sys

        begin
            # => [V, K, R]
            exec.smt::set
            # => [V_old, R_new]
            exec.sys::truncate_stack
        end
    ";

    fn expect_second_pair(smt: Smt, key: Word, value: Word) {
        let root = smt.root();

        let mut initial_stack: Vec<u64> = Default::default();
        push_word(&mut initial_stack, &root);
        push_word(&mut initial_stack, &key);
        push_word(&mut initial_stack, &value);

        // Will be an empty word for all cases except the no-op case (where V == V_old).
        let expected_old_value = smt_get_value(&smt, key);

        let mut expected_smt = smt.clone();
        smt_insert(&mut expected_smt, key, value);

        let expected_output = build_expected_stack(expected_old_value, expected_smt.root());

        let (store, advice_map) = build_advice_inputs(&smt);
        build_test!(SOURCE, &initial_stack, &[], store, advice_map).expect_stack(&expected_output);
    }

    for existing_pair in LEAVES_MULTI {
        for (new_key, new_val) in LEAVES_MULTI {
            expect_second_pair(build_smt_from_pairs(&[existing_pair]), new_key, new_val);
        }
    }
}

#[test]
fn test_smt_set_in_multi() {
    const SOURCE: &str = "
        use miden::core::collections::smt
        use miden::core::sys

        begin
            # => [V, K, R]
            exec.smt::set
            # => [V_old, R_new]
            exec.sys::truncate_stack
        end
    ";

    fn expect_insertion(smt: &Smt, key: Word, value: Word) {
        let mut expected_smt = smt.clone();
        smt_insert(&mut expected_smt, key, value);
        let old_value = smt_get_value(smt, key);

        let root = smt.root();

        let mut initial_stack: Vec<u64> = Default::default();
        push_word(&mut initial_stack, &root);
        push_word(&mut initial_stack, &key);
        push_word(&mut initial_stack, &value);

        let expected_output = build_expected_stack(old_value, expected_smt.root());

        let (store, advice_map) = build_advice_inputs(smt);
        build_debug_test!(SOURCE, &initial_stack, &[], store, advice_map)
            .expect_stack(&expected_output);
    }

    // Try every place we can do an insertion.
    for (key, value) in LEAVES_MULTI {
        // Start with LEAVES_MULTI - (key, value) for the existing leaf.
        let existing_pairs = LEAVES_MULTI.into_iter().filter(|&pair| pair != (key, value));
        let smt = build_smt_from_iter(existing_pairs);
        expect_insertion(&smt, key, value);
    }

    const K0: Word = word(420, 102, 103, 104);
    const V0: Word = word(555, 666, 777, 888);

    const K1: Word = word(420, 902, 903, 904);
    const V1: Word = word(122, 133, 144, 155);

    const K: Word = word(420, 506, 507, 508);
    const V: Word = word(555, 566, 577, 588);

    // Try inserting right in the middle.

    let smt = build_smt_from_pairs(&[(K0, V0), (K1, V1)]);
    let expected_smt = build_smt_from_pairs(&[(K0, V0), (K1, V1), (K, V)]);

    let root = smt.root();

    let mut initial_stack: Vec<u64> = Default::default();
    push_word(&mut initial_stack, &root);
    push_word(&mut initial_stack, &K);
    push_word(&mut initial_stack, &V);

    let expected_output = build_expected_stack(EMPTY_WORD, expected_smt.root());

    let (store, advice_map) = build_advice_inputs(&smt);
    let test = build_debug_test!(SOURCE, &initial_stack, &[], store, advice_map);
    test.expect_stack(&expected_output);
}

#[test]
fn test_smt_set_replace_in_multi() {
    const SOURCE: &str = "
        use miden::core::collections::smt
        use miden::core::sys

        begin
            # => [V, K, R]
            exec.smt::set
            # => [V_old, R_new]
            exec.sys::truncate_stack
        end
    ";

    const K0: Word = word(420, 102, 103, 104);
    const V0: Word = word(555, 666, 777, 888);

    const K1: Word = word(420, 902, 903, 904);
    const V1: Word = word(122, 133, 144, 155);

    const K2: Word = word(420, 506, 507, 508);
    const V2: Word = word(555, 566, 577, 588);

    // Try setting K0 to V2.

    let smt = build_smt_from_pairs(&[(K0, V0), (K1, V1), (K2, V2)]);
    let mut expected_smt = smt.clone();
    smt_insert(&mut expected_smt, K0, V2);

    let root = smt.root();

    let mut initial_stack: Vec<u64> = Default::default();
    push_word(&mut initial_stack, &root);
    push_word(&mut initial_stack, &K0);
    push_word(&mut initial_stack, &V2);

    let expected_output = build_expected_stack(V0, expected_smt.root());

    let (store, advice_map) = build_advice_inputs(&smt);
    let test = build_debug_test!(SOURCE, &initial_stack, &[], store, advice_map);
    test.expect_stack(&expected_output);
}

#[test]
fn test_smt_set_multi_to_single() {
    const SOURCE: &str = "
        use miden::core::collections::smt
        use miden::core::sys

        begin
            # => [V, K, R]
            exec.smt::set
            # => [V_old, R_new]
            exec.sys::truncate_stack
        end
    ";

    fn expect_remove_second_pair(smt: &Smt, key: Word) {
        let root = smt.root();
        let mut initial_stack: Vec<u64> = Default::default();
        push_word(&mut initial_stack, &root);
        push_word(&mut initial_stack, &key);
        push_word(&mut initial_stack, &EMPTY_WORD);

        let expected_value = smt_get_value(smt, key);

        let mut expected_smt = smt.clone();
        smt_insert(&mut expected_smt, key, EMPTY_WORD);

        let expected_output = build_expected_stack(expected_value, expected_smt.root());

        let (store, advice_map) = build_advice_inputs(smt);
        build_debug_test!(SOURCE, &initial_stack, &[], store, advice_map)
            .expect_stack(&expected_output);
    }

    const K0: Word = word(420, 102, 103, 104);
    const V0: Word = word(555, 666, 777, 888);

    const K1: Word = word(420, 202, 203, 204);
    const V1: Word = word(122, 133, 144, 155);

    let smt = build_smt_from_pairs(&[(K0, V0), (K1, V1)]);

    expect_remove_second_pair(&smt, K0);
    expect_remove_second_pair(&smt, K1);
}

#[test]
fn test_smt_set_remove_in_multi() {
    const SOURCE: &str = "
        use miden::core::collections::smt
        use miden::core::sys

        begin
            # => [V, K, R]
            exec.smt::set
            # => [V_old, R_new]
            exec.sys::truncate_stack
        end
    ";

    fn expect_remove(smt: &Smt, key: Word) {
        let root = smt.root();
        let mut initial_stack: Vec<u64> = Default::default();
        push_word(&mut initial_stack, &root);
        push_word(&mut initial_stack, &key);
        push_word(&mut initial_stack, &EMPTY_WORD);

        let expected_value = smt_get_value(smt, key);

        let mut expected_smt = smt.clone();
        smt_insert(&mut expected_smt, key, EMPTY_WORD);

        let expected_output = build_expected_stack(expected_value, expected_smt.root());

        let (store, advice_map) = build_advice_inputs(smt);
        build_debug_test!(SOURCE, &initial_stack, &[], store, advice_map)
            .expect_stack(&expected_output);
    }

    const K0: Word = word(420, 102, 103, 104);
    const V0: Word = word(555, 666, 777, 888);

    const K1: Word = word(420, 202, 203, 204);
    const V1: Word = word(122, 133, 144, 155);

    const K2: Word = word(420, 302, 303, 304);
    const V2: Word = word(51, 52, 53, 54);

    let all_pairs = [(K0, V0), (K1, V1), (K2, V2)];

    let smt = build_smt_from_pairs(&all_pairs);

    expect_remove(&smt, K0);
    expect_remove(&smt, K1);
    expect_remove(&smt, K2);
}

/// Tests `peek` on every key present in the SMT, as well as an empty leaf
#[test]
fn test_smt_peek() {
    fn expect_value_from_peek(key: Word, value: Word, smt: &Smt) {
        let source = "
            use miden::core::collections::smt

            begin
                # get the value
                exec.smt::peek padw adv_loadw
                # => [VALUE]

                # truncate the stack
                swapw dropw
                # => [VALUE]
            end
        ";
        let root = smt.root();
        let mut initial_stack = Vec::new();
        push_word(&mut initial_stack, &root);
        push_word(&mut initial_stack, &key);
        let expected_output = build_expected_stack(value, smt.root());

        let (store, advice_map) = build_advice_inputs(smt);
        build_test!(source, &initial_stack, &[], store, advice_map).expect_stack(&expected_output);
    }

    let smt = build_smt_from_pairs(&LEAVES);

    // Peek all leaves present in tree
    for (key, value) in LEAVES {
        expect_value_from_peek(key, value, &smt);
    }

    // Peek an empty leaf
    expect_value_from_peek(
        Word::new([Felt::from_u32(42), Felt::from_u32(42), Felt::from_u32(42), Felt::from_u32(42)]),
        EMPTY_WORD,
        &smt,
    );
}

/// Sanity check: verify that leaf hashes used as keys in the advice map match the Merkle store
#[test]
fn test_smt_leaf_hash_matches_merkle_store() {
    use miden_utils_testing::crypto::NodeIndex;

    const SMT_DEPTH: u8 = 64;

    let smt = build_smt_from_pairs(&LEAVES);
    let root = smt.root();
    let store: MerkleStore = MerkleStore::from(&smt);

    for (leaf_index, leaf) in smt.leaves() {
        let leaf_hash = leaf.hash();
        let node_index = NodeIndex::new(SMT_DEPTH, leaf_index.value()).unwrap();

        let node_hash = store.get_node(root, node_index).unwrap();
        assert_eq!(
            node_hash,
            leaf_hash,
            "leaf hash mismatch at index {}: expected {:?}, got {:?}",
            leaf_index.value(),
            leaf_hash,
            node_hash
        );
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[expect(clippy::type_complexity)]
fn prepare_insert_or_set(
    key: Word,
    value: Word,
    smt: &mut Smt,
) -> (Vec<u64>, Vec<u64>, MerkleStore, Vec<(Word, Vec<Felt>)>) {
    // set initial state of the stack to be [VALUE, KEY, ROOT, ...]
    let root = smt.root();

    let mut initial_stack = Vec::new();
    push_word(&mut initial_stack, &root);
    push_word(&mut initial_stack, &key);
    push_word(&mut initial_stack, &value);

    // build a Merkle store for the test before the tree is updated, and then update the tree
    let (store, advice_map) = build_advice_inputs(smt);
    let old_value = smt_insert(smt, key, value);

    // after insert or set, the stack should be [OLD_VALUE, ROOT, ...]
    let expected_output = build_expected_stack(old_value, smt.root());

    (initial_stack, expected_output, store, advice_map)
}

fn build_advice_inputs(smt: &Smt) -> (MerkleStore, Vec<(Word, Vec<Felt>)>) {
    let store = MerkleStore::from(smt);
    let advice_map = smt
        .leaves()
        .map(|(_, leaf)| {
            let leaf_hash = leaf.hash();
            let elements = build_leaf_advice_value(leaf.entries());
            (leaf_hash, elements)
        })
        .collect::<Vec<_>>();

    (store, advice_map)
}

fn build_expected_stack(word0: Word, word1: Word) -> Vec<u64> {
    let mut result = Vec::with_capacity(8);
    append_word_to_vec(&mut result, word0);
    append_word_to_vec(&mut result, word1);
    result
}

// RANDOMIZED ROUND-TRIP TEST
// =================================================================================================

/// Tests that smt::set followed by smt::get returns the inserted values for random key-value pairs
/// in a non-empty tree.
#[test]
fn test_smt_randomized_round_trip() {
    const TEST_ROUNDS: usize = 5;
    const INITIAL_PAIRS: usize = 3;
    const TEST_PAIRS: usize = 4;
    /// Number of unique buckets for key[3]. With 3 buckets and 7 total pairs (3 initial + 4 test),
    /// we're guaranteed to have at least 3 k-v pairs in one bucket, which exercises multi-leaf
    /// functionality.
    const BUCKETS: usize = 3;

    for test_round in 0..TEST_ROUNDS {
        // Create a random seed for reproducibility
        let mut seed = test_round as u64;

        // Build initial SMT with some random key-value pairs
        let mut initial_pairs = Vec::new();
        for _ in 0..INITIAL_PAIRS {
            let key = random_word(&mut seed, BUCKETS);
            let value = random_word(&mut seed, usize::MAX);
            initial_pairs.push((key, value));
        }
        let mut smt = build_smt_from_iter(initial_pairs);

        // Generate test key-value pairs to insert and retrieve
        for _ in 0..TEST_PAIRS {
            let key = random_word(&mut seed, BUCKETS);
            let value = random_word(&mut seed, usize::MAX);

            // Test set operation using the same pattern as existing tests
            let (set_initial_stack, _set_expected_stack, store, advice_map) =
                prepare_insert_or_set(key, value, &mut smt);

            const SET_SOURCE: &str = "
                use miden::core::collections::smt
                use miden::core::sys

                begin
                    # => [V, K, R]

                    dupw.1 movdnw.3
                    # => [V, K, R, K]

                    exec.smt::set
                    # => [V_old, R_new, K]

                    dropw swapw
                    # => [K, R_new]

                    exec.smt::get
                    # => [V, R_new]

                    exec.sys::truncate_stack
                end
            ";

            let expected_output = build_expected_stack(value, smt.root());

            build_test!(SET_SOURCE, &set_initial_stack, &[], store, advice_map)
                .expect_stack(&expected_output);
        }
    }
}

/// Generates a random key word with word[0] constrained to one of BUCKETS values.
/// This ensures keys are distributed across a limited number of buckets, which exercises
/// multi-leaf functionality in the SMT. We constrain word[0] because it is the most
/// significant element for lexicographic comparison.
fn random_word(seed: &mut u64, buckets: usize) -> Word {
    let mut word = [Felt::new(0); 4];
    for element in word.iter_mut() {
        *element = Felt::new(random_u64(seed));
    }
    // Constrain word[0] to be one of buckets values (most significant in LE comparison)
    let bucket_value = random_u64(seed) % (buckets as u64);
    word[0] = Felt::new(bucket_value);
    Word::new(word)
}

/// Generates a random u64 using a simple linear congruential generator
fn random_u64(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
    *seed
}

// STACK ORDERING UTILS
// ================================================================================================

fn push_word(stack: &mut Vec<u64>, word: &Word) {
    for (i, felt) in word.iter().enumerate() {
        stack.insert(i, felt.as_canonical_u64());
    }
}

fn build_smt_from_pairs(pairs: &[(Word, Word)]) -> Smt {
    Smt::with_entries(pairs.iter().copied()).unwrap()
}

fn build_smt_from_iter<I>(iter: I) -> Smt
where
    I: IntoIterator<Item = (Word, Word)>,
{
    Smt::with_entries(iter).unwrap()
}

fn build_leaf_advice_value(entries: &[(Word, Word)]) -> Vec<Felt> {
    if entries.is_empty() {
        return Vec::new();
    }

    let mut builder = AdviceStackBuilder::new();
    for (key, value) in entries {
        builder.push_for_adv_loadw(*key);
        builder.push_for_adv_loadw(*value);
    }
    builder.into_elements()
}

fn smt_insert(smt: &mut Smt, key: Word, value: Word) -> Word {
    smt.insert(key, value).unwrap()
}

fn smt_get_value(smt: &Smt, key: Word) -> Word {
    smt.get_value(&key)
}
