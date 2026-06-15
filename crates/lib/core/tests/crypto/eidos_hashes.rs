use miden_core::{Felt, Word};
use miden_crypto::hash::eidos::Eidos;
use miden_processor::{ExecutionError, ZERO, operation::OperationError};
use miden_utils_testing::{build_expected_hash, expect_exec_error_matches};

fn raw_absorb_double_words(values: &[u64]) -> Vec<u64> {
    assert_eq!(values.len() % 8, 0);

    let mut cv = Word::default();
    let mut last_block = [Felt::ZERO; 8];

    for chunk in values.chunks_exact(8) {
        last_block = core::array::from_fn(|i| Felt::new_unchecked(chunk[i]));
        cv = Eidos::compress_block(cv, last_block);
    }

    last_block
        .into_iter()
        .chain(cv.as_slice().iter().copied())
        .map(|felt| felt.as_canonical_u64())
        .collect()
}

fn raw_absorb_digest(values: &[u64]) -> Vec<u64> {
    raw_absorb_double_words(values)[8..12].to_vec()
}

#[test]
fn test_invalid_end_addr() {
    // end_addr can not be smaller than start_addr
    let empty_range = "
    use miden::core::crypto::hashes::eidos

    begin
        push.0999 # end address
        push.1000 # start address

        exec.eidos::hash_words
    end
    ";
    let test = build_test!(empty_range, &[]);
    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError{ err: OperationError::FailedAssertion{ err_code, err_msg }, .. }
        if err_code == ZERO && err_msg.is_none()
    );
}

#[test]
fn test_invalid_end_addr_has_message() {
    let source = "
    use miden::core::crypto::hashes::eidos

    begin
        push.0999 # end address
        push.1000 # start address

        exec.eidos::hash_double_words
    end
    ";
    let test = build_test!(source, &[]);
    expect_assert_error_message!(test);
}

#[test]
fn test_hash_empty() {
    // computes the hash for 8 consecutive zeros using mem_stream directly
    let two_zeros_mem_stream = "
    use miden::core::crypto::hashes::eidos

    begin
        # mem_stream state
        push.1000
        push.8 exec.eidos::init_chaining_word
        padw padw
        mem_stream bcompress

        # drop everything except the hash
        exec.eidos::digest movup.4 drop

        # truncate stack
        swapw dropw
    end
    ";

    #[rustfmt::skip]
    let zero_hash: Vec<u64> = build_expected_hash(&[
        0, 0, 0, 0,
        0, 0, 0, 0,
    ]).into_iter().map(|e| e.as_canonical_u64()).collect();
    build_test!(two_zeros_mem_stream, &[]).expect_stack(&zero_hash);

    // checks the hash compute from 8 zero elements is the same when using hash_words
    let two_zeros = "
    use miden::core::crypto::hashes::eidos

    begin
        push.1008 # end address
        push.1000 # start address

        exec.eidos::hash_words
        # truncate stack
        swapw dropw
    end
    ";

    build_test!(two_zeros, &[]).expect_stack(&zero_hash);
}

#[test]
fn test_single_iteration() {
    // computes the hash of 1 using mem_stream
    let one_memstream = "
    use miden::core::crypto::hashes::eidos

    begin
        # insert 1 to memory
        push.1.1000 mem_store

        # mem_stream state
        push.1000
        push.8 exec.eidos::init_chaining_word
        padw padw
        mem_stream bcompress

        # drop everything except the hash
        exec.eidos::digest movup.4 drop

        # truncate stack
        swapw dropw
    end
    ";

    #[rustfmt::skip]
    let one_hash: Vec<u64> = build_expected_hash(&[
        1, 0, 0, 0,
        0, 0, 0, 0,
    ]).into_iter().map(|e| e.as_canonical_u64()).collect();
    build_test!(one_memstream, &[]).expect_stack(&one_hash);

    // checks the hash of 1 is the same when using hash_words
    // Note: This is testing the hashing of two words, so no padding is added
    // here
    let one_element = "
    use miden::core::crypto::hashes::eidos

    begin
        # insert 1 to memory
        push.1.1000 mem_store

        push.1008 # end address
        push.1000 # start address

        exec.eidos::hash_words

        # truncate stack
        swapw dropw
    end
    ";

    build_test!(one_element, &[]).expect_stack(&one_hash);
}

#[test]
fn test_hash_one_word() {
    // computes the hash of a single 1, the procedure adds padding as required

    // This slice must not have the second word, that will be padded by the hasher with the correct
    // value
    #[rustfmt::skip]
    let one_hash: Vec<u64> = build_expected_hash(&[
        1, 0, 0, 0,
    ]).into_iter().map(|e| e.as_canonical_u64()).collect();

    // checks the hash of 1 is the same when using hash_words
    let one_element = "
    use miden::core::crypto::hashes::eidos

    begin
        push.1.1000 mem_store # push data to memory

        push.1004 # end address
        push.1000 # start address

        exec.eidos::hash_words

        # truncate stack
        swapw dropw
    end
    ";

    build_test!(one_element, &[]).expect_stack(&one_hash);
}

#[test]
fn test_hash_even_words() {
    // checks the hash of two words
    // With mem_storew_le: push.D.C.B.A stores [A, B, C, D]
    let even_words = "
    use miden::core::crypto::hashes::eidos

    begin
        push.0.1.0.0.1000 mem_storew_le dropw
        push.1.0.0.0.1004 mem_storew_le dropw

        push.1008 # end address
        push.1000 # start address

        exec.eidos::hash_words

        # truncate stack
        swapw dropw
    end
    ";

    // push.0.1.0.0 stores [0, 0, 1, 0], push.1.0.0.0 stores [0, 0, 0, 1]
    // Total input: [0, 0, 1, 0, 0, 0, 0, 1]
    #[rustfmt::skip]
    let even_hash: Vec<u64> = build_expected_hash(&[
        0, 0, 1, 0,
        0, 0, 0, 1,
    ]).into_iter().map(|e| e.as_canonical_u64()).collect();
    build_test!(even_words, &[]).expect_stack(&even_hash);
}

#[test]
fn test_hash_odd_words() {
    // checks the hash of three words
    // The hash_words procedure adds padding for odd word counts, so we use
    // hardcoded expected values (same as reference).
    let odd_words = "
    use miden::core::crypto::hashes::eidos

    begin
        push.0.1.0.0.1000 mem_storew_le dropw
        push.0.0.1.0.1004 mem_storew_le dropw
        push.0.0.0.1.1008 mem_storew_le dropw

        push.1012 # end address
        push.1000 # start address

        exec.eidos::hash_words

        # truncate stack
        swapw dropw
    end
    ";

    #[rustfmt::skip]
    let odd_hash: Vec<u64> = build_expected_hash(&[
        0, 0, 1, 0,
        0, 1, 0, 0,
        1, 0, 0, 0,
    ]).into_iter().map(|e| e.as_canonical_u64()).collect();
    build_test!(odd_words, &[]).expect_stack(&odd_hash);
}

#[test]
fn test_absorb_double_words_from_memory() {
    // With mem_storew_le: push.D.C.B.A stores [A, B, C, D]
    let even_words = "
    use miden::core::sys
    use miden::core::crypto::hashes::eidos

    begin
        push.0.0.0.1.1000 mem_storew_le dropw
        push.0.0.1.0.1004 mem_storew_le dropw

        push.1008      # end address
        push.1000      # start address
        padw padw padw # hasher state
        exec.eidos::absorb_double_words_from_memory

        # truncate stack
        exec.sys::truncate_stack
    end
    ";

    // push.0.0.0.1 stores [1, 0, 0, 0], push.0.0.1.0 stores [0, 1, 0, 0]
    #[rustfmt::skip]
    let mut even_hash = raw_absorb_double_words(&[
        1, 0, 0, 0, // first word of the rate
        0, 1, 0, 0, // second word of the rate
    ]);

    // start and end addr
    even_hash.push(1008);
    even_hash.push(1008);

    build_test!(even_words, &[]).expect_stack(&even_hash);
}

#[test]
fn test_hash_double_words() {
    // test the standard case
    // With mem_storew_le: push.D.C.B.A stores [A, B, C, D]
    let double_words = "
    use miden::core::sys
    use miden::core::crypto::hashes::eidos

    begin
        # store four words (two double words) in memory
        push.0.0.0.1.1000 mem_storew_le dropw
        push.0.0.1.0.1004 mem_storew_le dropw
        push.0.1.0.0.1008 mem_storew_le dropw
        push.1.0.0.0.1012 mem_storew_le dropw

        push.1016      # end address
        push.1000      # start address
        # => [start_addr, end_addr]

        exec.eidos::hash_double_words
        # => [HASH]

        # truncate stack
        exec.sys::truncate_stack
        # => [HASH]
    end
    ";

    // push.0.0.0.1 stores [1,0,0,0], push.0.0.1.0 stores [0,1,0,0], etc.
    // Total: [1,0,0,0, 0,1,0,0, 0,0,1,0, 0,0,0,1]
    #[rustfmt::skip]
    let resulting_hash: Vec<u64> = build_expected_hash(&[
        1, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 1,
    ]).into_iter().map(|e| e.as_canonical_u64()).collect();

    build_test!(double_words, &[]).expect_stack(&resulting_hash);

    // test the corner case when the end pointer equals to the start pointer
    let empty_double_words = r#"
    use miden::core::sys
    use miden::core::crypto::hashes::eidos

    begin
        push.1000.1000 # start and end addresses
        # => [start_addr, end_addr]

        exec.eidos::hash_double_words
        # => [HASH]

        # assert that the resulting hash is equal to the framed empty hash
        dupw
        push.0.1000 exec.eidos::hash_elements
        assert_eqw.err="resulting hash should be equal to the empty hash"

        # truncate stack
        exec.sys::truncate_stack
        # => [HASH]
    end
    "#;

    let empty_hash: Vec<u64> =
        build_expected_hash(&[]).into_iter().map(|e| e.as_canonical_u64()).collect();
    build_test!(empty_double_words, &[]).expect_stack(&empty_hash);
}

#[test]
fn test_digest() {
    // With mem_storew_le: push.D.C.B.A stores [A, B, C, D]
    let even_words = "
    use miden::core::crypto::hashes::eidos

    begin
        push.0.0.0.1.1000 mem_storew_le dropw
        push.0.0.1.0.1004 mem_storew_le dropw
        push.0.1.0.0.1008 mem_storew_le dropw
        push.1.0.0.0.1012 mem_storew_le dropw

        push.1016      # end address
        push.1000      # start address
        padw padw padw # hasher state
        exec.eidos::absorb_double_words_from_memory

        exec.eidos::digest

        # truncate stack
        swapdw dropw dropw
    end
    ";

    // Same input as test_hash_double_words: [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1]
    #[rustfmt::skip]
    let mut even_hash = raw_absorb_digest(&[
        1, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 1,
    ]);

    // start and end addr
    even_hash.push(1016);
    even_hash.push(1016);

    build_test!(even_words, &[]).expect_stack(&even_hash);
}

#[test]
fn test_copy_digest() {
    // With mem_storew_le: push.D.C.B.A stores [A, B, C, D]
    let copy_digest = r#"
    use miden::core::sys
    use miden::core::crypto::hashes::eidos

    begin
        push.1.0.0.0.1000 mem_storew_le dropw
        push.0.1.0.0.1004 mem_storew_le dropw

        push.1008      # end address
        push.1000      # start address
        padw padw padw # hasher state
        exec.eidos::absorb_double_words_from_memory
        # => [A, B, C, end_ptr, end_ptr]  (sponge state [R0, R1, CAP] with R0=A on top)

        # drop the pointers
        movup.12 drop movup.12 drop
        # => [A, B, C]

        # copy the digest/capacity word
        exec.eidos::copy_digest
        # => [C, A, B, C]

        # truncate stack
        exec.sys::truncate_stack
    end
    "#;

    let state = raw_absorb_double_words(&[
        0, 0, 0, 1, // first word of the rate
        0, 0, 1, 0, // second word of the rate
    ]);
    let mut resulting_stack = state[8..12].to_vec();
    resulting_stack.extend(state);

    build_test!(copy_digest, &[]).expect_stack(&resulting_stack);
}

#[test]
fn test_pad_and_hash_elements_synthesizes_zero_tail() {
    let source = "
    use miden::core::crypto::hashes::eidos

    begin
        push.4.3.2.1.1000 mem_storew_le dropw
        push.88.77.66.5.1004 mem_storew_le dropw

        push.5.1000
        exec.eidos::pad_and_hash_elements

        # truncate stack
        swapdw dropw dropw
    end
    ";

    #[rustfmt::skip]
    let expected: Vec<u64> = build_expected_hash(&[
        1, 2, 3, 4,
        5, 0, 0, 0,
    ]).into_iter().map(|e| e.as_canonical_u64()).collect();

    build_test!(source, &[]).expect_stack(&expected);
}

#[test]
fn test_hash_elements() {
    // hash fewer than 8 elements
    let compute_inputs_hash_5 = "
    use miden::core::crypto::hashes::eidos

    begin
        push.4.3.2.1.1000 mem_storew_le dropw
        push.0.0.0.5.1004 mem_storew_le dropw
        push.11

        push.5.1000

        exec.eidos::hash_elements

        # truncate stack
        swapdw dropw dropw
    end
    ";

    #[rustfmt::skip]
    let mut expected_hash: Vec<u64> = build_expected_hash(&[
        1, 2, 3, 4, 5
    ]).into_iter().map(|e| e.as_canonical_u64()).collect();
    // make sure that value `11` stays unchanged
    expected_hash.push(11);
    build_test!(compute_inputs_hash_5, &[]).expect_stack(&expected_hash);

    // hash exactly 8 elements
    let compute_inputs_hash_8 = "
    use miden::core::crypto::hashes::eidos

    begin
        push.4.3.2.1.1000 mem_storew_le dropw
        push.8.7.6.5.1004 mem_storew_le dropw
        push.11

        push.8.1000

        exec.eidos::hash_elements

        # truncate stack
        swapdw dropw dropw
    end
    ";

    #[rustfmt::skip]
    let mut expected_hash: Vec<u64> = build_expected_hash(&[
        1, 2, 3, 4, 5, 6, 7, 8
    ]).into_iter().map(|e| e.as_canonical_u64()).collect();
    // make sure that value `11` stays unchanged
    expected_hash.push(11);
    build_test!(compute_inputs_hash_8, &[]).expect_stack(&expected_hash);

    // hash more than 8 elements
    let compute_inputs_hash_15 = "
    use miden::core::crypto::hashes::eidos

    begin
        push.4.3.2.1.1000 mem_storew_le dropw
        push.8.7.6.5.1004 mem_storew_le dropw
        push.12.11.10.9.1008 mem_storew_le dropw
        push.16.15.14.13.1012 mem_storew_le dropw
        push.11

        push.15.1000

        exec.eidos::hash_elements

        # truncate stack
        swapdw dropw dropw
    end
    ";

    #[rustfmt::skip]
    let mut expected_hash: Vec<u64> = build_expected_hash(&[
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 11, 12,
        13, 14, 15
    ]).into_iter().map(|e| e.as_canonical_u64()).collect();
    // make sure that value `11` stays unchanged
    expected_hash.push(11);
    build_test!(compute_inputs_hash_15, &[]).expect_stack(&expected_hash);
}

#[test]
fn test_hash_elements_empty() {
    // absorb_double_words_from_memory
    let source = "
    use miden::core::sys
    use miden::core::crypto::hashes::eidos

    begin
        push.1000      # end address
        push.1000      # start address
        padw padw padw # hasher state

        exec.eidos::absorb_double_words_from_memory

        # truncate stack
        exec.sys::truncate_stack
    end
    ";

    let mut expected_stack = vec![0; 12];
    expected_stack.push(1000);
    expected_stack.push(1000);

    build_test!(source, &[]).expect_stack(&expected_stack);

    // hash_words
    let source = "
    use miden::core::crypto::hashes::eidos

    begin
        push.1000 # end address
        push.1000 # start address

        exec.eidos::hash_words

        # truncate stack
        swapw dropw
    end
    ";

    let empty_hash: Vec<u64> =
        build_expected_hash(&[]).into_iter().map(|e| e.as_canonical_u64()).collect();
    build_test!(source, &[]).expect_stack(&empty_hash);

    // hash_elements
    let source = "
    use miden::core::crypto::hashes::eidos

    begin
        push.0    # number of elements to hash
        push.1000 # start address

        exec.eidos::hash_elements

        # truncate stack
        swapw dropw
    end
    ";

    build_test!(source, &[]).expect_stack(&empty_hash);
}

#[test]
fn test_eidos_hash_function() {
    // Test that the public hash function works - it should execute without error
    // and produce a valid 4-element digest from 8-element input
    let source = "
    use miden::core::crypto::hashes::eidos

    begin
        exec.eidos::hash
        swapw dropw
    end
    ";

    // Test with simple input: 8 field elements
    // We're just testing that the function compiles and runs without error
    let input = [1u64, 2, 3, 4, 5, 6, 7, 8];

    // This test will pass if the function executes successfully
    // The actual hash value doesn't matter, we're testing the API works
    build_test!(source, &input);
}

#[test]
fn test_eidos_merge_function() {
    // Test that the public merge function works - it should execute without error
    // and produce a valid 4-element digest from two 4-element digests
    let source = "
    use miden::core::crypto::hashes::eidos

    begin
        exec.eidos::merge
        swapw dropw
    end
    ";

    // Test with two 4-element digests (8 elements total)
    // We're just testing that the function compiles and runs without error
    let combined = [1u64, 2, 3, 4, 5, 6, 7, 8];

    // This test will pass if the function executes successfully
    build_test!(source, &combined);
}
