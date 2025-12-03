use miden_libcore::handlers::smt_peek::SMT_PEEK_EVENT_NAME;
use miden_utils_testing::prepend_word_to_vec as prepend_word;

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
        let mut initial_stack = Vec::new();
        append_word_to_vec(&mut initial_stack, smt.root());
        append_word_to_vec(&mut initial_stack, key);
        let expected_output = build_expected_stack(value, smt.root());

        let (store, advice_map) = build_advice_inputs(smt);
        build_test!(source, &initial_stack, &[], store, advice_map).expect_stack(&expected_output);
    }

    let smt = Smt::with_entries(LEAVES).unwrap();

    // Get all leaves present in tree
    for (key, value) in LEAVES {
        expect_value_from_get(key, value, &smt);
    }

    // Get an empty leaf
    expect_value_from_get(
        Word::new([42_u32.into(), 42_u32.into(), 42_u32.into(), 42_u32.into()]),
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
        let mut initial_stack: Vec<u64> = Default::default();
        prepend_word(&mut initial_stack, key);
        prepend_word(&mut initial_stack, smt.root());
        let expected_output = build_expected_stack(value, smt.root());

        let (store, advice_map) = build_advice_inputs(smt);
        build_test!(SOURCE, &initial_stack, &[], store, advice_map).expect_stack(&expected_output);
    }

    let smt = Smt::with_entries(LEAVES_MULTI).unwrap();

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
            old_roots.push(smt.root());
            let (init_stack, final_stack, store, advice_map) =
                prepare_insert_or_set(key, value, smt);
            build_test!(source, &init_stack, &[], store, advice_map).expect_stack(&final_stack);
        }

        // setting to [ZERO; 4] should return the tree to the prior state
        for (key, old_value) in LEAVES.iter().rev() {
            let value = EMPTY_WORD;
            let (init_stack, final_stack, store, advice_map) =
                prepare_insert_or_set(*key, value, smt);

            let expected_final_stack = build_expected_stack(*old_value, old_roots.pop().unwrap());
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
    let mut smt = Smt::with_entries(LEAVES).unwrap();

    let source = "
    use miden::core::collections::smt
    begin
      exec.smt::set
    end
    ";

    let key = LEAVES[0].0;
    let value = [Felt::from(42323_u32); 4].into();
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

    let key = Word::new([41_u32.into(), 42_u32.into(), 43_u32.into(), 44_u32.into()]);
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
        adv_push.4
        # => [V_in_map, V]

        # Check for equality of V's
        assert_eqw
        # => [K]
    end
    "
    );

    let key = Word::new([41_u32.into(), 42_u32.into(), 43_u32.into(), 44_u32.into()]);
    let value: [Felt; 4] = [42323_u32.into(); 4];
    let (init_stack, _, store, advice_map) = prepare_insert_or_set(key, value.into(), &mut smt);

    // assert is checked in MASM
    build_test!(source, &init_stack, &[], store, advice_map).execute().unwrap();
}

/// Tests that the advice map is properly updated after a `set` on a key that has existing value
#[test]
fn test_set_advice_map_single_key() {
    let mut smt = Smt::with_entries(LEAVES).unwrap();

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
        adv_push.4
        # => [V_in_map, V]

        # Check for equality of V's
        assert_eqw
        # => [K]
    end"
    );

    let key = LEAVES[0].0;
    let value: [Felt; 4] = [Felt::from(42323_u32); 4];
    let (init_stack, _, store, advice_map) = prepare_insert_or_set(key, value.into(), &mut smt);

    // assert is checked in MASM
    build_test!(source, &init_stack, &[], store, advice_map).execute().unwrap();
}

/// Tests setting an empty value to an empty key, but that maps to a leaf with another key
/// (i.e. removing a value that's already empty)
#[test]
fn test_set_empty_key_in_non_empty_leaf() {
    let key_mse = Felt::new(42);

    let leaves: [(Word, Word); 1] = [(
        Word::new([Felt::new(101), Felt::new(102), Felt::new(103), key_mse]),
        Word::new([Felt::new(1_u64), Felt::new(2_u64), Felt::new(3_u64), Felt::new(4_u64)]),
    )];

    let mut smt = Smt::with_entries(leaves).unwrap();

    // This key has same most significant element as key in the existing leaf, so will map to that
    // leaf
    let new_key = Word::new([Felt::new(1), Felt::new(12), Felt::new(3), key_mse]);

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
        let mut initial_stack: Vec<u64> = Default::default();
        prepend_word(&mut initial_stack, value);
        prepend_word(&mut initial_stack, key);
        prepend_word(&mut initial_stack, smt.root());

        // Will be an empty word for all cases except the no-op case (where V == V_old).
        let expected_old_value = smt.get_value(&key);

        let mut expected_smt = smt.clone();
        expected_smt.insert(key, value).unwrap();

        let expected_output = build_expected_stack(expected_old_value, expected_smt.root());

        let (store, advice_map) = build_advice_inputs(&smt);
        build_test!(SOURCE, &initial_stack, &[], store, advice_map).expect_stack(&expected_output);
    }

    for existing_pair in LEAVES_MULTI {
        for (new_key, new_val) in LEAVES_MULTI {
            expect_second_pair(Smt::with_entries([existing_pair]).unwrap(), new_key, new_val);
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
        expected_smt.insert(key, value).unwrap();
        let old_value = smt.get_value(&key);

        let mut initial_stack: Vec<u64> = Default::default();
        prepend_word(&mut initial_stack, value);
        prepend_word(&mut initial_stack, key);
        prepend_word(&mut initial_stack, smt.root());

        let expected_output = build_expected_stack(old_value, expected_smt.root());

        let (store, advice_map) = build_advice_inputs(smt);
        build_debug_test!(SOURCE, &initial_stack, &[], store, advice_map)
            .expect_stack(&expected_output);
    }

    // Try every place we can do an insertion.
    for (key, value) in LEAVES_MULTI {
        // Start with LEAVES_MULTI - (key, value) for the existing leaf.
        let existing_pairs = LEAVES_MULTI.into_iter().filter(|&pair| pair != (key, value));
        let smt = Smt::with_entries(existing_pairs).unwrap();
        expect_insertion(&smt, key, value);
    }

    const K0: Word = word(101, 102, 103, 420);
    const V0: Word = word(555, 666, 777, 888);

    const K1: Word = word(901, 902, 903, 420);
    const V1: Word = word(122, 133, 144, 155);

    const K: Word = word(505, 506, 507, 420);
    const V: Word = word(555, 566, 577, 588);

    // Try inserting right in the middle.

    let smt = Smt::with_entries([(K0, V0), (K1, V1)]).unwrap();
    let expected_smt = Smt::with_entries([(K0, V0), (K1, V1), (K, V)]).unwrap();

    let mut initial_stack: Vec<u64> = Default::default();

    prepend_word(&mut initial_stack, V);
    prepend_word(&mut initial_stack, K);
    prepend_word(&mut initial_stack, smt.root());

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

    const K0: Word = word(101, 102, 103, 420);
    const V0: Word = word(555, 666, 777, 888);

    const K1: Word = word(901, 902, 903, 420);
    const V1: Word = word(122, 133, 144, 155);

    const K2: Word = word(505, 506, 507, 420);
    const V2: Word = word(555, 566, 577, 588);

    // Try setting K0 to V2.

    let smt = Smt::with_entries([(K0, V0), (K1, V1), (K2, V2)]).unwrap();
    let mut expected_smt = smt.clone();
    expected_smt.insert(K0, V2).unwrap();

    let mut initial_stack: Vec<u64> = Default::default();

    prepend_word(&mut initial_stack, V2);
    prepend_word(&mut initial_stack, K0);
    prepend_word(&mut initial_stack, smt.root());

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
        let mut initial_stack: Vec<u64> = Default::default();
        prepend_word(&mut initial_stack, EMPTY_WORD);
        prepend_word(&mut initial_stack, key);
        prepend_word(&mut initial_stack, smt.root());

        let expected_value = smt.get_value(&key);

        let mut expected_smt = smt.clone();
        expected_smt.insert(key, EMPTY_WORD).unwrap();

        let expected_output = build_expected_stack(expected_value, expected_smt.root());

        let (store, advice_map) = build_advice_inputs(smt);
        build_debug_test!(SOURCE, &initial_stack, &[], store, advice_map)
            .expect_stack(&expected_output);
    }

    const K0: Word = word(101, 102, 103, 420);
    const V0: Word = word(555, 666, 777, 888);

    const K1: Word = word(201, 202, 203, 420);
    const V1: Word = word(122, 133, 144, 155);

    let smt = Smt::with_entries([(K0, V0), (K1, V1)]).unwrap();

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
        let mut initial_stack: Vec<u64> = Default::default();
        prepend_word(&mut initial_stack, EMPTY_WORD);
        prepend_word(&mut initial_stack, key);
        prepend_word(&mut initial_stack, smt.root());

        let expected_value = smt.get_value(&key);

        let mut expected_smt = smt.clone();
        expected_smt.insert(key, EMPTY_WORD).unwrap();

        let expected_output = build_expected_stack(expected_value, expected_smt.root());

        let (store, advice_map) = build_advice_inputs(smt);
        build_debug_test!(SOURCE, &initial_stack, &[], store, advice_map)
            .expect_stack(&expected_output);
    }

    const K0: Word = word(101, 102, 103, 420);
    const V0: Word = word(555, 666, 777, 888);

    const K1: Word = word(201, 202, 203, 420);
    const V1: Word = word(122, 133, 144, 155);

    const K2: Word = word(301, 302, 303, 420);
    const V2: Word = word(51, 52, 53, 54);

    let all_pairs = [(K0, V0), (K1, V1), (K2, V2)];

    let smt = Smt::with_entries(all_pairs).unwrap();

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
                exec.smt::peek adv_push.4
                # => [VALUE]

                # truncate the stack
                swapw dropw
                # => [VALUE]
            end
        ";
        let mut initial_stack = Vec::new();
        append_word_to_vec(&mut initial_stack, smt.root());
        append_word_to_vec(&mut initial_stack, key);
        let expected_output = build_expected_stack(value, smt.root());

        let (store, advice_map) = build_advice_inputs(smt);
        build_test!(source, &initial_stack, &[], store, advice_map).expect_stack(&expected_output);
    }

    let smt = Smt::with_entries(LEAVES).unwrap();

    // Peek all leaves present in tree
    for (key, value) in LEAVES {
        expect_value_from_peek(key, value, &smt);
    }

    // Peek an empty leaf
    expect_value_from_peek(
        Word::new([42_u32.into(), 42_u32.into(), 42_u32.into(), 42_u32.into()]),
        EMPTY_WORD,
        &smt,
    );
}

// HELPER FUNCTIONS
// ================================================================================================

#[allow(clippy::type_complexity)]
fn prepare_insert_or_set(
    key: Word,
    value: Word,
    smt: &mut Smt,
) -> (Vec<u64>, Vec<u64>, MerkleStore, Vec<(Word, Vec<Felt>)>) {
    // set initial state of the stack to be [VALUE, KEY, ROOT, ...]
    let mut initial_stack = Vec::new();
    append_word_to_vec(&mut initial_stack, smt.root());
    append_word_to_vec(&mut initial_stack, key);
    append_word_to_vec(&mut initial_stack, value);

    // build a Merkle store for the test before the tree is updated, and then update the tree
    let (store, advice_map) = build_advice_inputs(smt);
    let old_value = smt.insert(key, value).unwrap();
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
            (leaf_hash, leaf.to_elements())
        })
        .collect::<Vec<_>>();

    (store, advice_map)
}

fn build_expected_stack(word0: Word, word1: Word) -> Vec<u64> {
    vec![
        word0[3].as_int(),
        word0[2].as_int(),
        word0[1].as_int(),
        word0[0].as_int(),
        word1[3].as_int(),
        word1[2].as_int(),
        word1[1].as_int(),
        word1[0].as_int(),
    ]
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

        let mut smt = Smt::with_entries(initial_pairs).unwrap();

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

/// Generates a random key word with key[3] constrained to one of BUCKETS values.
/// This ensures keys are distributed across a limited number of buckets, which exercises
/// multi-leaf functionality in the SMT.
fn random_word(seed: &mut u64, buckets: usize) -> Word {
    let mut word = [Felt::new(0); 4];
    for element in word.iter_mut() {
        *element = Felt::new(random_u64(seed));
    }
    // Constrain key[3] to be one of buckets values
    let bucket_value = random_u64(seed) % (buckets as u64);
    word[3] = Felt::new(bucket_value);
    Word::new(word)
}

/// Generates a random u64 using a simple linear congruential generator
fn random_u64(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
    *seed
}
