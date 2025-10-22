use miden_air::RowIndex;
use miden_processor::{ExecutionError, ZERO};
use miden_utils_testing::{build_expected_hash, build_expected_perm, expect_exec_error_matches};

#[test]
fn test_invalid_end_addr() {
    // end_addr can not be smaller than start_addr
    let empty_range = "
    use.std::crypto::hashes::rpo

    begin
        push.0999 # end address
        push.1000 # start address

        exec.rpo::hash_memory_words
    end
    ";
    let test = build_test!(empty_range, &[]);

    expect_exec_error_matches!(
        test,
        ExecutionError::FailedAssertion{ clk, err_code, err_msg , label: _, source_file: _ }
        if clk == RowIndex::from(18) && err_code == ZERO && err_msg.is_none()
    );
}

#[test]
fn test_hash_empty() {
    // computes the hash for 8 consecutive zeros using mem_stream directly
    let two_zeros_mem_stream = "
    use.std::crypto::hashes::rpo

    begin
        # mem_stream state
        push.1000 padw padw padw
        mem_stream hperm

        # drop everything except the hash
        exec.rpo::squeeze_digest movup.4 drop

        # truncate stack
        swapw dropw
    end
    ";

    #[rustfmt::skip]
    let zero_hash: Vec<u64> = build_expected_hash(&[
        0, 0, 0, 0,
        0, 0, 0, 0,
    ]).into_iter().map(|e| e.as_int()).collect();
    build_test!(two_zeros_mem_stream, &[]).expect_stack(&zero_hash);

    // checks the hash compute from 8 zero elements is the same when using hash_memory_words
    let two_zeros = "
    use.std::crypto::hashes::rpo

    begin
        push.1008 # end address
        push.1000 # start address

        exec.rpo::hash_memory_words

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
    use.std::crypto::hashes::rpo

    begin
        # insert 1 to memory
        push.1.1000 mem_store

        # mem_stream state
        push.1000 padw padw padw
        mem_stream hperm

        # drop everything except the hash
        exec.rpo::squeeze_digest movup.4 drop

        # truncate stack
        swapw dropw
    end
    ";

    #[rustfmt::skip]
    let one_hash: Vec<u64> = build_expected_hash(&[
        1, 0, 0, 0,
        0, 0, 0, 0,
    ]).into_iter().map(|e| e.as_int()).collect();
    build_test!(one_memstream, &[]).expect_stack(&one_hash);

    // checks the hash of 1 is the same when using hash_memory_words
    // Note: This is testing the hashing of two words, so no padding is added
    // here
    let one_element = "
    use.std::crypto::hashes::rpo

    begin
        # insert 1 to memory
        push.1.1000 mem_store

        push.1008 # end address
        push.1000 # start address

        exec.rpo::hash_memory_words

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
    ]).into_iter().map(|e| e.as_int()).collect();

    // checks the hash of 1 is the same when using hash_memory_words
    let one_element = "
    use.std::crypto::hashes::rpo

    begin
        push.1.1000 mem_store # push data to memory

        push.1004 # end address
        push.1000 # start address

        exec.rpo::hash_memory_words

        # truncate stack
        swapw dropw
    end
    ";

    build_test!(one_element, &[]).expect_stack(&one_hash);
}

#[test]
fn test_hash_even_words() {
    // checks the hash of two words
    let even_words = "
    use.std::crypto::hashes::rpo

    begin
        push.1.0.0.0.1000 mem_storew_be dropw
        push.0.1.0.0.1004 mem_storew_be dropw

        push.1008 # end address
        push.1000 # start address

        exec.rpo::hash_memory_words

        # truncate stack
        swapw dropw
    end
    ";

    #[rustfmt::skip]
    let even_hash: Vec<u64> = build_expected_hash(&[
        1, 0, 0, 0,
        0, 1, 0, 0,
    ]).into_iter().map(|e| e.as_int()).collect();
    build_test!(even_words, &[]).expect_stack(&even_hash);
}

#[test]
fn test_hash_odd_words() {
    // checks the hash of three words
    let odd_words = "
    use.std::crypto::hashes::rpo

    begin
        push.1.0.0.0.1000 mem_storew_be dropw
        push.0.1.0.0.1004 mem_storew_be dropw
        push.0.0.1.0.1008 mem_storew_be dropw

        push.1012 # end address
        push.1000 # start address

        exec.rpo::hash_memory_words

        # truncate stack
        swapw dropw
    end
    ";

    #[rustfmt::skip]
    let odd_hash: Vec<u64> = build_expected_hash(&[
        1, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
    ]).into_iter().map(|e| e.as_int()).collect();
    build_test!(odd_words, &[]).expect_stack(&odd_hash);
}

#[test]
fn test_absorb_double_words_from_memory() {
    let even_words = "
    use.std::sys
    use.std::crypto::hashes::rpo

    begin
        push.1.0.0.0.1000 mem_storew_be dropw
        push.0.1.0.0.1004 mem_storew_be dropw

        push.1008      # end address
        push.1000      # start address
        padw padw padw # hasher state
        exec.rpo::absorb_double_words_from_memory

        # truncate stack
        exec.sys::truncate_stack
    end
    ";

    #[rustfmt::skip]
    let mut even_hash: Vec<u64> = build_expected_perm(&[
        0, 0, 0, 0, // capacity, no padding required
        1, 0, 0, 0, // first word of the rate
        0, 1, 0, 0, // second word of the rate
    ]).into_iter().map(|e| e.as_int()).collect();

    // start and end addr
    even_hash.push(1008);
    even_hash.push(1008);

    build_test!(even_words, &[]).expect_stack(&even_hash);
}

#[test]
fn test_hash_memory_double_words() {
    // test the standard case
    let double_words = "
    use.std::sys
    use.std::crypto::hashes::rpo

    begin
        # store four words (two double words) in memory
        push.1.0.0.0.1000 mem_storew_be dropw
        push.0.1.0.0.1004 mem_storew_be dropw
        push.0.0.1.0.1008 mem_storew_be dropw
        push.0.0.0.1.1012 mem_storew_be dropw

        push.1016      # end address
        push.1000      # start address
        # => [start_addr, end_addr]

        exec.rpo::hash_memory_double_words
        # => [HASH]

        # truncate stack
        exec.sys::truncate_stack
        # => [HASH]
    end
    ";

    #[rustfmt::skip]
    let resulting_hash: Vec<u64> = build_expected_hash(&[
        1, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 1,
    ]).into_iter().map(|e| e.as_int()).collect();

    build_test!(double_words, &[]).expect_stack(&resulting_hash);

    // test the corner case when the end pointer equals to the start pointer
    let empty_double_words = r#"
    use.std::sys
    use.std::crypto::hashes::rpo

    begin
        push.1000.1000 # start and end addresses
        # => [start_addr, end_addr]

        exec.rpo::hash_memory_double_words
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
    let even_words = "
    use.std::crypto::hashes::rpo

    begin
        push.1.0.0.0.1000 mem_storew_be dropw
        push.0.1.0.0.1004 mem_storew_be dropw
        push.0.0.1.0.1008 mem_storew_be dropw
        push.0.0.0.1.1012 mem_storew_be dropw

        push.1016      # end address
        push.1000      # start address
        padw padw padw # hasher state
        exec.rpo::absorb_double_words_from_memory

        exec.rpo::squeeze_digest

        # truncate stack
        swapdw dropw dropw
    end
    ";

    #[rustfmt::skip]
    let mut even_hash: Vec<u64> = build_expected_hash(&[
        1, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 1,
    ]).into_iter().map(|e| e.as_int()).collect();

    // start and end addr
    even_hash.push(1016);
    even_hash.push(1016);

    build_test!(even_words, &[]).expect_stack(&even_hash);
}

#[test]
fn test_copy_digest() {
    let copy_digest = r#"
    use.std::sys
    use.std::crypto::hashes::rpo

    begin
        push.1.0.0.0.1000 mem_storew_be dropw
        push.0.1.0.0.1004 mem_storew_be dropw

        push.1008      # end address
        push.1000      # start address
        padw padw padw # hasher state
        exec.rpo::absorb_double_words_from_memory
        # => [C, B, A, end_ptr, end_ptr]

        # drop the pointers
        movup.12 drop movup.12 drop
        # => [C, B, A]

        # copy the result of the permutation (second word, B)
        exec.rpo::copy_digest
        # => [B, C, B, A]

        # assert that the copied word is equal to the second word in the hasher state
        dupw.2 dupw.1 assert_eqw.err="copied word should be equal to the second word in the hasher state"
        # => [B, C, B, A]

        # truncate stack
        exec.sys::truncate_stack
    end
    "#;

    #[rustfmt::skip]
    let mut resulting_stack: Vec<u64> = build_expected_perm(&[
        0, 0, 0, 0, // capacity, no padding required
        1, 0, 0, 0, // first word of the rate
        0, 1, 0, 0, // second word of the rate
    ]).into_iter().map(|e| e.as_int()).collect();

    // push the permutation result on the top of the resulting stack
    resulting_stack[4..8]
        .to_vec()
        .iter()
        .rev()
        .for_each(|hash_element| resulting_stack.insert(0, *hash_element));

    build_test!(copy_digest, &[]).expect_stack(&resulting_stack);
}

#[test]
fn test_hash_memory() {
    // hash fewer than 8 elements
    let compute_inputs_hash_5 = "
    use.std::crypto::hashes::rpo

    begin
        push.1.2.3.4.1000 mem_storew_be dropw
        push.5.0.0.0.1004 mem_storew_be dropw
        push.11

        push.5.1000

        exec.rpo::hash_memory

        # truncate stack
        swapdw dropw dropw
    end
    ";

    #[rustfmt::skip]
    let mut expected_hash: Vec<u64> = build_expected_hash(&[
        1, 2, 3, 4, 5
    ]).into_iter().map(|e| e.as_int()).collect();
    // make sure that value `11` stays unchanged
    expected_hash.push(11);
    build_test!(compute_inputs_hash_5, &[]).expect_stack(&expected_hash);

    // hash exactly 8 elements
    let compute_inputs_hash_8 = "
    use.std::crypto::hashes::rpo

    begin
        push.1.2.3.4.1000 mem_storew_be dropw
        push.5.6.7.8.1004 mem_storew_be dropw
        push.11

        push.8.1000

        exec.rpo::hash_memory

        # truncate stack
        swapdw dropw dropw
    end
    ";

    #[rustfmt::skip]
    let mut expected_hash: Vec<u64> = build_expected_hash(&[
        1, 2, 3, 4, 5, 6, 7, 8
    ]).into_iter().map(|e| e.as_int()).collect();
    // make sure that value `11` stays unchanged
    expected_hash.push(11);
    build_test!(compute_inputs_hash_8, &[]).expect_stack(&expected_hash);

    // hash more than 8 elements
    let compute_inputs_hash_15 = "
    use.std::crypto::hashes::rpo

    begin
        push.1.2.3.4.1000 mem_storew_be dropw
        push.5.6.7.8.1004 mem_storew_be dropw
        push.9.10.11.12.1008 mem_storew_be dropw
        push.13.14.15.0.1012 mem_storew_be dropw
        push.11

        push.15.1000

        exec.rpo::hash_memory

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
    ]).into_iter().map(|e| e.as_int()).collect();
    // make sure that value `11` stays unchanged
    expected_hash.push(11);
    build_test!(compute_inputs_hash_15, &[]).expect_stack(&expected_hash);
}

#[test]
fn test_hash_memory_empty() {
    // absorb_double_words_from_memory
    let source = "
    use.std::sys
    use.std::crypto::hashes::rpo

    begin
        push.1000      # end address
        push.1000      # start address
        padw padw padw # hasher state

        exec.rpo::absorb_double_words_from_memory

        # truncate stack
        exec.sys::truncate_stack
    end
    ";

    let mut expected_stack = vec![0; 12];
    expected_stack.push(1000);
    expected_stack.push(1000);

    build_test!(source, &[]).expect_stack(&expected_stack);

    // hash_memory_words
    let source = "
    use.std::crypto::hashes::rpo

    begin
        push.1000 # end address
        push.1000 # start address

        exec.rpo::hash_memory_words

        # truncate stack
        swapw dropw
    end
    ";

    build_test!(source, &[]).expect_stack(&[0; 4]);

    // hash_memory
    let source = "
    use.std::crypto::hashes::rpo

    begin
        push.0    # number of elements to hash
        push.1000 # start address

        exec.rpo::hash_memory

        # truncate stack
        swapw dropw
    end
    ";

    build_test!(source, &[]).expect_stack(&[0; 16]);
}
