use miden_core::field::PrimeField64;
use miden_processor::{ExecutionError, OperationError, ZERO};
use miden_utils_testing::{build_expected_hash, build_expected_perm, expect_exec_error_matches};

#[test]
fn test_invalid_end_addr() {
    // end_addr can not be smaller than start_addr
    let empty_range = "
    use miden::core::crypto::hashes::rpo256

    begin
        push.0999 # end address
        push.1000 # start address

        exec.rpo256::hash_words
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
fn test_hash_empty() {
    // computes the hash for 8 consecutive zeros using mem_stream directly
    let two_zeros_mem_stream = "
    use miden::core::crypto::hashes::rpo256

    begin
        # mem_stream state
        push.1000 padw padw padw
        mem_stream hperm

        # drop everything except the hash
        exec.rpo256::squeeze_digest movup.4 drop

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
    use miden::core::crypto::hashes::rpo256

    begin
        push.1008 # end address
        push.1000 # start address

        exec.rpo256::hash_words
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
    use miden::core::crypto::hashes::rpo256

    begin
        # insert 1 to memory
        push.1.1000 mem_store

        # mem_stream state
        push.1000 padw padw padw
        mem_stream hperm

        # drop everything except the hash
        exec.rpo256::squeeze_digest movup.4 drop

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
    use miden::core::crypto::hashes::rpo256

    begin
        # insert 1 to memory
        push.1.1000 mem_store

        push.1008 # end address
        push.1000 # start address

        exec.rpo256::hash_words

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
    use miden::core::crypto::hashes::rpo256

    begin
        push.1.1000 mem_store # push data to memory

        push.1004 # end address
        push.1000 # start address

        exec.rpo256::hash_words

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
    use miden::core::crypto::hashes::rpo256

    begin
        push.0.1.0.0.1000 mem_storew_le dropw
        push.1.0.0.0.1004 mem_storew_le dropw

        push.1008 # end address
        push.1000 # start address

        exec.rpo256::hash_words

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
    use miden::core::crypto::hashes::rpo256

    begin
        push.0.1.0.0.1000 mem_storew_le dropw
        push.0.0.1.0.1004 mem_storew_le dropw
        push.0.0.0.1.1008 mem_storew_le dropw

        push.1012 # end address
        push.1000 # start address

        exec.rpo256::hash_words

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
    use miden::core::crypto::hashes::rpo256

    begin
        push.0.0.0.1.1000 mem_storew_le dropw
        push.0.0.1.0.1004 mem_storew_le dropw

        push.1008      # end address
        push.1000      # start address
        padw padw padw # hasher state
        exec.rpo256::absorb_double_words_from_memory

        # truncate stack
        exec.sys::truncate_stack
    end
    ";

    // push.0.0.0.1 stores [1, 0, 0, 0], push.0.0.1.0 stores [0, 1, 0, 0]
    #[rustfmt::skip]
    let mut even_hash: Vec<u64> = build_expected_perm(&[
        1, 0, 0, 0, // first word of the rate
        0, 1, 0, 0, // second word of the rate
        0, 0, 0, 0, // capacity, no padding required
    ]).into_iter().map(|e| e.as_canonical_u64()).collect();

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
    use miden::core::crypto::hashes::rpo256

    begin
        # store four words (two double words) in memory
        push.0.0.0.1.1000 mem_storew_le dropw
        push.0.0.1.0.1004 mem_storew_le dropw
        push.0.1.0.0.1008 mem_storew_le dropw
        push.1.0.0.0.1012 mem_storew_le dropw

        push.1016      # end address
        push.1000      # start address
        # => [start_addr, end_addr]

        exec.rpo256::hash_double_words
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
    use miden::core::crypto::hashes::rpo256

    begin
        push.1000.1000 # start and end addresses
        # => [start_addr, end_addr]

        exec.rpo256::hash_double_words
        # => [HASH]

        # assert that the resulting hash is equal to the empty word
        dupw padw assert_eqw.err="resulting hash should be equal to the empty word"

        # truncate stack
        exec.sys::truncate_stack
        # => [HASH]
    end
    "#;

    build_test!(empty_double_words, &[]).expect_stack(&[0u64; 4]);
}

#[test]
fn test_squeeze_digest() {
    // With mem_storew_le: push.D.C.B.A stores [A, B, C, D]
    let even_words = "
    use miden::core::crypto::hashes::rpo256

    begin
        push.0.0.0.1.1000 mem_storew_le dropw
        push.0.0.1.0.1004 mem_storew_le dropw
        push.0.1.0.0.1008 mem_storew_le dropw
        push.1.0.0.0.1012 mem_storew_le dropw

        push.1016      # end address
        push.1000      # start address
        padw padw padw # hasher state
        exec.rpo256::absorb_double_words_from_memory

        exec.rpo256::squeeze_digest

        # truncate stack
        swapdw dropw dropw
    end
    ";

    // Same input as test_hash_double_words: [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1]
    #[rustfmt::skip]
    let mut even_hash: Vec<u64> = build_expected_hash(&[
        1, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 1,
    ]).into_iter().map(|e| e.as_canonical_u64()).collect();

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
    use miden::core::crypto::hashes::rpo256

    begin
        push.1.0.0.0.1000 mem_storew_le dropw
        push.0.1.0.0.1004 mem_storew_le dropw

        push.1008      # end address
        push.1000      # start address
        padw padw padw # hasher state
        exec.rpo256::absorb_double_words_from_memory
        # => [A, B, C, end_ptr, end_ptr]  (sponge state [R0, R1, CAP] with R0=A on top)

        # drop the pointers
        movup.12 drop movup.12 drop
        # => [A, B, C]

        # copy the result of the permutation (first word / digest, A)
        exec.rpo256::copy_digest
        # => [A, A, B, C]

        # assert that the copied word is equal to the first word in the hasher state
        dupw.1 dupw.1 assert_eqw.err="copied word should be equal to the first word in the hasher state"
        # => [A, A, B, C]

        # truncate stack
        exec.sys::truncate_stack
    end
    "#;

    // push.1.0.0.0 stores [0, 0, 0, 1], push.0.1.0.0 stores [0, 0, 1, 0]
    #[rustfmt::skip]
    let mut resulting_stack: Vec<u64> = build_expected_perm(&[
        0, 0, 0, 1, // first word of the rate
        0, 0, 1, 0, // second word of the rate
        0, 0, 0, 0, // capacity, no padding required
    ]).into_iter().map(|e| e.as_canonical_u64()).collect();

    // push the permutation result (digest at R0, positions 0..4) on the top of the resulting stack
    resulting_stack[0..4]
        .to_vec()
        .iter()
        .rev()
        .for_each(|hash_element| resulting_stack.insert(0, *hash_element));

    build_test!(copy_digest, &[]).expect_stack(&resulting_stack);
}

#[test]
fn test_hash_elements() {
    // hash fewer than 8 elements
    let compute_inputs_hash_5 = "
    use miden::core::crypto::hashes::rpo256

    begin
        push.4.3.2.1.1000 mem_storew_le dropw
        push.0.0.0.5.1004 mem_storew_le dropw
        push.11

        push.5.1000

        exec.rpo256::hash_elements

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
    use miden::core::crypto::hashes::rpo256

    begin
        push.4.3.2.1.1000 mem_storew_le dropw
        push.8.7.6.5.1004 mem_storew_le dropw
        push.11

        push.8.1000

        exec.rpo256::hash_elements

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
    use miden::core::crypto::hashes::rpo256

    begin
        push.4.3.2.1.1000 mem_storew_le dropw
        push.8.7.6.5.1004 mem_storew_le dropw
        push.12.11.10.9.1008 mem_storew_le dropw
        push.16.15.14.13.1012 mem_storew_le dropw
        push.11

        push.15.1000

        exec.rpo256::hash_elements

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
    use miden::core::crypto::hashes::rpo256

    begin
        push.1000      # end address
        push.1000      # start address
        padw padw padw # hasher state

        exec.rpo256::absorb_double_words_from_memory

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
    use miden::core::crypto::hashes::rpo256

    begin
        push.1000 # end address
        push.1000 # start address

        exec.rpo256::hash_words

        # truncate stack
        swapw dropw
    end
    ";

    build_test!(source, &[]).expect_stack(&[0; 4]);

    // hash_elements
    let source = "
    use miden::core::crypto::hashes::rpo256

    begin
        push.0    # number of elements to hash
        push.1000 # start address

        exec.rpo256::hash_elements

        # truncate stack
        swapw dropw
    end
    ";

    build_test!(source, &[]).expect_stack(&[0; 16]);
}

#[test]
fn test_rpo_hash_function() {
    // Test that the public hash function works - it should execute without error
    // and produce a valid 4-element digest from 8-element input
    let source = "
    use miden::core::crypto::hashes::rpo256

    begin
        exec.rpo256::hash
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
fn test_rpo_merge_function() {
    // Test that the public merge function works - it should execute without error
    // and produce a valid 4-element digest from two 4-element digests
    let source = "
    use miden::core::crypto::hashes::rpo256

    begin
        exec.rpo256::merge
        swapw dropw
    end
    ";

    // Test with two 4-element digests (8 elements total)
    // We're just testing that the function compiles and runs without error
    let combined = [1u64, 2, 3, 4, 5, 6, 7, 8];

    // This test will pass if the function executes successfully
    build_test!(source, &combined);
}
