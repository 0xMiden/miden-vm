use miden_stdlib::handlers::smt_peek::SMT_PEEK_EVENT_NAME;
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
            use.std::collections::smt

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
        use.std::collections::smt
        use.std::sys

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
            use.std::collections::smt

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
    use.std::collections::smt
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
    use.std::collections::smt
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
    use.std::collections::smt
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
    use.std::collections::smt
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
    use.std::collections::smt

    begin
        exec.smt::set
        movupw.2 dropw
    end
    ";
    let (init_stack, final_stack, store, advice_map) =
        prepare_insert_or_set(new_key, EMPTY_WORD, &mut smt);

    build_test!(source, &init_stack, &[], store, advice_map).expect_stack(&final_stack);
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
