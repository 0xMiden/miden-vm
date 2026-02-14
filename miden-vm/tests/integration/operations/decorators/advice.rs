use miden_core::Felt;
use miden_prover::Word;
use miden_utils_testing::{build_test, crypto::MerkleStore};

// ADVICE INJECTION
// ================================================================================================

#[test]
fn advice_insert_mem() {
    let source = "begin
    # stack: [1, 2, 3, 4, 5, 6, 7, 8]

    # write to memory and drop first word from stack to use second word as the key for advice map.
    # mem_storew_be reverses the order of field elements in the word when it's stored in memory.
    mem_storew_be.8 dropw mem_storew_be.12
    # State Transition:
    # stack: [5, 6, 7, 8]
    # mem[8..11]: [4, 3, 2, 1]
    # mem[12..15]: [8, 7, 6, 5]

    # copy from memory to advice map
    # the key used is in the reverse order of the field elements in the word at the top of the
    # stack.
    push.16 movdn.4 push.8 movdn.4
    adv.insert_mem
    # State Transition:
    # stack: [5, 6, 7, 8, 4, 16]
    # advice_map: k: [8, 7, 6, 5], v: [4, 3, 2, 1, 8, 7, 6, 5]

    # copy from advice map to advice stack
    adv.push_mapval dropw
    # State Transition:
    # stack: [4, 16, 0, 0]
    # advice_stack: [4, 3, 2, 1, 8, 7, 6, 5]

    # copy first word from advice stack to stack
    # adv_loadw copies the word to the stack with elements in the reverse order.
    adv_loadw
    # State Transition:
    # stack: [1, 2, 3, 4, 0, 0, 0, 0]
    # advice_stack: [8, 7, 6, 5]

    # swap first 2 words on stack
    swapw
    # State Transition:
    # stack: [0, 0, 0, 0, 1, 2, 3, 4]

    # copy next word from advice stack to stack
    # adv_loadw copies the word to the stack with elements in the reverse order.
    adv_loadw
    # State Transition:
    # stack: [5, 6, 7, 8, 1, 2, 3, 4]
    # advice_stack: []

    end";
    let stack_inputs = [1, 2, 3, 4, 5, 6, 7, 8];
    let test = build_test!(source, &stack_inputs);
    test.expect_stack(&[8, 7, 6, 5, 4, 3, 2, 1]);
}

#[test]
fn advice_push_mapval() {
    // --- test simple adv.push_mapval ---------------------------------------------
    let source: &str = "
    begin
        # stack: [4, 3, 2, 1, ...]

        # load the advice stack with values from the advice map and drop the key
        adv.push_mapval
        dropw

        # move the values from the advice stack to the operand stack
        padw adv_loadw
        swapw dropw
    end";

    let stack_inputs = [1, 2, 3, 4];
    // Stack key is [1, 2, 3, 4] with 1 on top
    let stack_key: [u64; 4] = [1, 2, 3, 4];
    let adv_map = [(
        Word::try_from(stack_key).unwrap(),
        vec![Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)],
    )];

    let test = build_test!(source, &stack_inputs, [], MerkleStore::default(), adv_map);
    test.expect_stack(&[5, 6, 7, 8]);

    // --- test simple adv.push_mapval_count ---------------------------------------------
    let source: &str = "
    begin
        # stack: [1, 2, 3, 4, ...]

        # load the advice stack with values from the advice map and drop the key
        adv.push_mapval_count
        dropw

        # move the number of values from the advice stack to the operand stack
        adv_push.1
        swap drop
    end";

    let stack_inputs = [1, 2, 3, 4];
    let stack_key: [u64; 4] = [1, 2, 3, 4];
    let adv_map = [(
        Word::try_from(stack_key).unwrap(),
        vec![Felt::new(9), Felt::new(8), Felt::new(7), Felt::new(6), Felt::new(5)],
    )];

    let test = build_test!(source, &stack_inputs, [], MerkleStore::default(), adv_map);
    test.expect_stack(&[5]);
}

#[test]
fn adv_push_mapvaln() {
    // --- test simple adv.push_mapvaln --------------------------------------------
    let source: &str = "
    begin
        # stack: [1, 2, 3, 4, ...]

        # load the advice stack with values from the advice map (including the number
        # of elements) and drop the key
        adv.push_mapvaln
        dropw

        # move the values from the advice stack to the operand stack
        adv_push.6
        swapdw dropw dropw
    end";

    let stack_inputs = [1, 2, 3, 4];
    let stack_key: [u64; 4] = [1, 2, 3, 4];
    let adv_map = [(
        Word::try_from(stack_key).unwrap(),
        vec![Felt::new(11), Felt::new(12), Felt::new(13), Felt::new(14), Felt::new(15)],
    )];

    let test = build_test!(source, &stack_inputs, [], MerkleStore::default(), adv_map);
    test.expect_stack(&[15, 14, 13, 12, 11, 5]);
}

#[test]
fn adv_push_mapvaln_padding() {
    // --- test adv.push_mapvaln.0 -------------------------------------------------
    let source: &str = "
    begin
        # stack: [1, 2, 3, 4, ...]

        # load the advice stack with values from the advice map (including the number
        # of elements) and drop the key
        # since 0 was provided as an immediate value, the resulting map values should not be padded
        adv.push_mapvaln.0
        dropw

        # move the values from the advice stack to the operand stack
        adv_push.6
        swapdw dropw dropw
    end";

    let stack_inputs = [1, 2, 3, 4];
    let stack_key: [u64; 4] = [1, 2, 3, 4];
    let adv_map = [(
        Word::try_from(stack_key).unwrap(),
        vec![Felt::new(11), Felt::new(12), Felt::new(13), Felt::new(14), Felt::new(15)],
    )];

    let test = build_test!(source, &stack_inputs, [], MerkleStore::default(), adv_map);
    test.expect_stack(&[15, 14, 13, 12, 11, 5]);

    // --- test adv.push_mapvaln.4 -------------------------------------------------
    let source: &str = "
    begin
        # stack: [1, 2, 3, 4, ...]

        # load the advice stack with values from the advice map (including the number
        # of elements) and drop the key
        # since 4 was provided as an immediate value, the resulting map values should be padded to
        # the next multiple of 4
        adv.push_mapvaln.4
        dropw

        # move the values from the advice stack to the operand stack
        adv_push.5
        swapdw dropw dropw
    end";

    let stack_inputs = [1, 2, 3, 4];
    let stack_key: [u64; 4] = [1, 2, 3, 4];
    let adv_map = [(
        Word::try_from(stack_key).unwrap(),
        vec![Felt::new(11), Felt::new(12), Felt::new(13)],
    )];

    let test = build_test!(source, &stack_inputs, [], MerkleStore::default(), adv_map);
    test.expect_stack(&[0, 13, 12, 11, 3]);

    // --- test adv.push_mapvaln.8 -------------------------------------------------
    let source: &str = "
    begin
        # stack: [1, 2, 3, 4, ...]

        # load the advice stack with values from the advice map (including the number
        # of elements) and drop the key
        # since 8 was provided as an immediate value, the resulting map values should be padded to
        # the next multiple of 8
        adv.push_mapvaln.8
        dropw

        # move the values from the advice stack to the operand stack
        adv_push.8 swapdw dropw dropw
        adv_push.1 movup.9 drop
    end";

    let stack_inputs = [1, 2, 3, 4];
    let stack_key: [u64; 4] = [1, 2, 3, 4];
    let adv_map = [(
        Word::try_from(stack_key).unwrap(),
        vec![
            Felt::new(11),
            Felt::new(12),
            Felt::new(13),
            Felt::new(14),
            Felt::new(15),
            Felt::new(16),
        ],
    )];

    let test = build_test!(source, &stack_inputs, [], MerkleStore::default(), adv_map);
    test.expect_stack(&[0, 0, 16, 15, 14, 13, 12, 11, 6]);
}

#[test]
fn advice_has_mapkey() {
    // --- test adv.has_mapkey: key is present --------------------------------
    let source: &str = r#"
    begin
        # stack: [1, 2, 3, 4]

        # push the flag on the advice stack indicating if key [1, 2, 3, 4] exists in advice map
        adv.has_mapkey

        # move the the flag from the advice stack to the operand stack
        adv_push.1

        # check that the flag equals 1 -- the key is present in the map
        dup assert.err="presence flag should be equal 1"

        # truncate the stack
        movup.5 drop
    end"#;

    let stack_inputs = [1, 2, 3, 4];
    let stack_key: [u64; 4] = [1, 2, 3, 4];
    let adv_map = [(
        Word::try_from(stack_key).unwrap(),
        vec![Felt::new(8), Felt::new(7), Felt::new(6), Felt::new(5)],
    )];

    let test = build_test!(source, &stack_inputs, [], MerkleStore::default(), adv_map);
    test.expect_stack(&[1, 1, 2, 3, 4]);

    // --- test adv.has_mapkey: key is not present ----------------------------
    let source: &str = r#"
    begin
        # stack: [1, 2, 3, 4]

        # push the flag on the advice stack indicating if key [1, 2, 3, 4] exists in advice map
        adv.has_mapkey

        # move the the flag from the advice stack to the operand stack
        adv_push.1

        # check that the flag equals 0 -- the key is not present in the map
        dup assertz.err="presence flag should be equal 0"

        # truncate the stack
        movup.5 drop
    end"#;

    let stack_inputs = [1, 2, 3, 4];
    let map_key = [5u64, 6, 7, 8];
    let adv_map = [(
        Word::try_from(map_key).unwrap(),
        vec![Felt::new(9), Felt::new(10), Felt::new(11), Felt::new(12)],
    )];

    let test = build_test!(source, &stack_inputs, [], MerkleStore::default(), adv_map);
    test.expect_stack(&[0, 1, 2, 3, 4]);
}

#[test]
fn advice_insert_hdword() {
    // --- test hashing without domain ----------------------------------------
    let source: &str = "
    begin
        # stack: [1, 2, 3, 4, 5, 6, 7, 8, ...]
        # W0 = [1,2,3,4], W1 = [5,6,7,8]

        # hash and insert top two words into the advice map
        adv.insert_hdword

        # manually compute the hash of the two words
        # hmerge computes hash(W0 || W1), matching adv.insert_hdword
        hmerge
        # => [KEY, ...]

        # load the advice stack with values from the advice map and drop the key
        adv.push_mapval
        dropw

        # move the values from the advice stack to the operand stack
        # Values stored as [W0, W1], advice stack top is W0
        # adv_loadw gets W0, swapw moves it, adv_loadw gets W1, swapw produces [W0, W1]
        adv_loadw swapw adv_loadw swapw
    end";
    let stack_inputs = [1, 2, 3, 4, 5, 6, 7, 8];
    let test = build_test!(source, &stack_inputs);
    // Values are stored as [W0, W1] in advice map.
    // Retrieval: adv_loadw swapw adv_loadw swapw produces [W0, W1].
    test.expect_stack(&[1, 2, 3, 4, 5, 6, 7, 8]);

    // --- test hashing with domain -------------------------------------------
    let source: &str = "
    begin
        # stack: [1, 2, 3, 4, 5, 6, 7, 8, 9, ...]
        # W0 = [1,2,3,4], W1 = [5,6,7,8], domain = 9

        # hash and insert top two words into the advice map
        adv.insert_hdword_d

        # manually compute the hash of the two words with domain
        # Set up state for hperm: [W0, W1, CAP] where CAP = [0, domain, 0, 0]
        # (domain goes in state[9], not state[8])
        push.0 push.0 movup.10 push.0 movdnw.2
        # => [W0, W1, [0, domain, 0, 0], ...]
        hperm
        # Extract hash from R0 (state[0..4]) after permutation
        swapw.2 dropw dropw
        # => [KEY, ...]

        # load the advice stack with values from the advice map and drop the key
        adv.push_mapval
        dropw

        # move the values from the advice stack to the operand stack
        # Values stored as [W0, W1], advice stack top is W0
        # adv_loadw gets W0, swapw moves it, adv_loadw gets W1, swapw produces [W0, W1]
        adv_loadw swapw adv_loadw swapw
    end";
    let stack_inputs = [1, 2, 3, 4, 5, 6, 7, 8, 9];
    let test = build_test!(source, &stack_inputs);
    // Values stored as [W0, W1], retrieval produces [W0, W1] on operand stack
    test.expect_stack(&[1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn advice_insert_hqword() {
    let source: &str = "
    begin
        # stack: [A, B, C, D] = [11-14, 21-24, 31-34, 41-44]

        # hash and insert top four words into the advice map
        adv.insert_hqword

        # manually compute the hash of the four words
        # hash_elements([A || B || C || D]) absorbs in two rounds:
        # Round 1: absorb A, B with zero capacity
        # Round 2: absorb C, D with capacity from round 1

        # First absorption: [A, B, cap=0]
        # Stack: [A, B, C, D, ...]
        padw movdnw.2

        hperm
        # => [RATE1', RATE2', CAP', C, D, ...]

        # Second absorption: use CAP' as new capacity, absorb C, D
        dropw dropw
        # => [CAP', C, D, ...]
        movdnw.2
        hperm
        # => [RATE1'', RATE2'', CAP'', ...]

        # Extract hash 
        swapw.2 dropw dropw
        # => [KEY]

        # load the advice stack with values from the advice map and drop the key
        adv.push_mapval
        dropw

        # move the values from the advice stack to the operand stack
        repeat.4
            movupw.3
            adv_loadw reversew
        end
    end";
    let stack_inputs = [44, 43, 42, 41, 34, 33, 32, 31, 24, 23, 22, 21, 14, 13, 12, 11];
    let test = build_test!(source, &stack_inputs);
    // Values retrieved from advice map in LIFO order
    test.expect_stack(&[11, 12, 13, 14, 21, 22, 23, 24, 31, 32, 33, 34, 41, 42, 43, 44]);
}
