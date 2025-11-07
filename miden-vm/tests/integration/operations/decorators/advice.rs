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

    # swap first 2 words on stack
    swapw
    # State Transition:
    # stack: [1, 2, 3, 4, 5, 6, 7, 8]

    end";
    let stack_inputs = [8, 7, 6, 5, 4, 3, 2, 1];
    let test = build_test!(source, &stack_inputs);
    test.expect_stack(&[1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn advice_push_mapval() {
    // --- test simple adv.mapval ---------------------------------------------
    let source: &str = "
    begin
        # stack: [4, 3, 2, 1, ...]

        # load the advice stack with values from the advice map and drop the key
        adv.push_mapval
        dropw

        # move the values from the advice stack to the operand stack
        adv_push.4
        swapw dropw
    end";

    let stack_inputs = [1, 2, 3, 4];
    let adv_map = [(
        Word::try_from(stack_inputs).unwrap(),
        vec![Felt::new(8), Felt::new(7), Felt::new(6), Felt::new(5)],
    )];

    let test = build_test!(source, &stack_inputs, [], MerkleStore::default(), adv_map);
    test.expect_stack(&[5, 6, 7, 8]);

    // --- test simple adv.mapvaln --------------------------------------------
    let source: &str = "
    begin
        # stack: [4, 3, 2, 1, ...]

        # load the advice stack with values from the advice map (including the number
        # of elements) and drop the key
        adv.push_mapvaln
        dropw

        # move the values from the advice stack to the operand stack
        adv_push.6
        swapdw dropw dropw
    end";

    let stack_inputs = [1, 2, 3, 4];
    let adv_map = [(
        Word::try_from(stack_inputs).unwrap(),
        vec![Felt::new(11), Felt::new(12), Felt::new(13), Felt::new(14), Felt::new(15)],
    )];

    let test = build_test!(source, &stack_inputs, [], MerkleStore::default(), adv_map);
    test.expect_stack(&[15, 14, 13, 12, 11, 5]);
}

#[test]
fn advice_has_mapkey() {
    // --- test adv.has_mapkey: key is present --------------------------------
    let source: &str = r#"
    begin
        # stack: [4, 3, 2, 1]

        # push the flag on the advice stack whether the [1, 2, 3, 4] key is presented in the advice
        # map
        adv.has_mapkey

        # move the the flag from the advice stack to the operand stack
        adv_push.1

        # check that the flag equals 1 -- the key is present in the map
        dup assert.err="presence flag should be equal 1"

        # truncate the stack
        movup.5 drop
    end"#;

    let stack_inputs = [1, 2, 3, 4];
    let adv_map = [(
        Word::try_from(stack_inputs).unwrap(),
        vec![Felt::new(8), Felt::new(7), Felt::new(6), Felt::new(5)],
    )];

    let test = build_test!(source, &stack_inputs, [], MerkleStore::default(), adv_map);
    test.expect_stack(&[1, 4, 3, 2, 1]);

    // --- test adv.has_mapkey: key is not present ----------------------------
    let source: &str = r#"
    begin
        # stack: [4, 3, 2, 1]

        # push the flag on the advice stack whether the [1, 2, 3, 4] key is presented in the advice
        # map
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
    test.expect_stack(&[0, 4, 3, 2, 1]);
}

#[test]
fn advice_insert_hdword() {
    // --- test hashing without domain ----------------------------------------
    let source: &str = "
    begin
        # stack: [1, 2, 3, 4, 5, 6, 7, 8, ...]

        # hash and insert top two words into the advice map
        adv.insert_hdword

        # manually compute the hash of the two words
        hmerge
        # => [KEY, ...]

        # load the advice stack with values from the advice map and drop the key
        adv.push_mapval
        dropw

        # move the values from the advice stack to the operand stack
        adv_push.8
        swapdw dropw dropw
    end";
    let stack_inputs = [8, 7, 6, 5, 4, 3, 2, 1];
    let test = build_test!(source, &stack_inputs);
    test.expect_stack(&[1, 2, 3, 4, 5, 6, 7, 8]);

    // --- test hashing with domain -------------------------------------------
    let source: &str = "
    begin
        # stack: [1, 2, 3, 4, 5, 6, 7, 8, 9, ...]

        # hash and insert top two words into the advice map
        adv.insert_hdword_d

        # manually compute the hash of the two words
        push.0.9.0.0
        swapw.2 swapw
        hperm
        dropw swapw dropw
        # => [KEY, ...]

        # load the advice stack with values from the advice map and drop the key
        adv.push_mapval
        dropw

        # move the values from the advice stack to the operand stack
        adv_push.8
        swapdw dropw dropw
    end";
    let stack_inputs = [9, 8, 7, 6, 5, 4, 3, 2, 1];
    let test = build_test!(source, &stack_inputs);
    test.expect_stack(&[1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn advice_insert_hqword() {
    let source: &str = "
    use.std::sys

    begin
        # stack: [11, 12, 13, 14, 21, 22, 23, 24, 31, 32, 33, 34, 41, 42, 43, 44]

        # hash and insert top four words into the advice map
        adv.insert_hqword

        # manually compute the hash of the four words

        swapdw
        # => [31, 32, 33, 34, 41, 42, 43, 44, 11, 12, 13, 14, 21, 22, 23, 24]

        # pad capacity element of the hasher
        padw movdnw.2
        # => [31, 32, 33, 34, 41, 42, 43, 44, CAPACITY, 11, 12, 13, 14, 21, 22, 23, 24]

        hperm
        # => [RATE, RATE, PERM, 11, 12, 13, 14, 21, 22, 23, 24]

        # drop rate words
        dropw dropw
        # => [PERM, 11, 12, 13, 14, 21, 22, 23, 24]

        movdnw.2
        # => [11, 12, 13, 14, 21, 22, 23, 24, PERM]

        hperm
        # => [RATE, RATE, PERM]

        # get the resulting hash
        dropw swapw dropw
        # => [KEY]

        # load the advice stack with values from the advice map and drop the key
        adv.push_mapval
        dropw

        # move the values from the advice stack to the operand stack
        repeat.4
            movupw.3
            adv_loadw
        end
    end";
    let stack_inputs = [44, 43, 42, 41, 34, 33, 32, 31, 24, 23, 22, 21, 14, 13, 12, 11];
    let test = build_test!(source, &stack_inputs);
    test.expect_stack(&[11, 12, 13, 14, 21, 22, 23, 24, 31, 32, 33, 34, 41, 42, 43, 44]);
}
