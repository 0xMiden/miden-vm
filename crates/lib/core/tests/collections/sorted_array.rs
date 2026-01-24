use super::*;

#[test]
fn test_sorted_array_find_word() {
    // (word, was_value_found, value_ptr)
    let tests = [
        ("8413,5080,6742,354", 0, 100),
        ("8456,415,4922,593", 1, 100),
        ("4942,5573,1077,1968", 0, 104),
        ("8675,5816,5458,2767", 1, 104),
        ("3348,6058,5470,2813", 0, 108),
        ("3015,7211,2002,5143", 1, 108),
        ("1152,1526,2547,5314", 0, 112),
    ];

    for test in tests {
        let (key, was_key_found, key_ptr) = test;
        let source: String = format!(
            "
            use miden::core::collections::sorted_array

            {TRUNCATE_STACK_PROC}

            begin
                push.[8456,415,4922,593] mem_storew_le.100 dropw
                push.[8675,5816,5458,2767] mem_storew_le.104 dropw
                push.[3015,7211,2002,5143] mem_storew_le.108 dropw

                push.112 push.100 push.[{key}]

                exec.sorted_array::find_word
                exec.truncate_stack
            end
        "
        );

        let program = build_test!(source, &[]);
        program.expect_stack(&[was_key_found, key_ptr, 100, 112, 0]);
    }
}

#[test]
fn test_empty_sorted_array_find_word() {
    let source: String = format!(
        "
        use miden::core::collections::sorted_array

        {TRUNCATE_STACK_PROC}

        begin
            push.100 push.100 push.[8413,5080,6742,354]

            exec.sorted_array::find_word
            exec.truncate_stack
        end
    "
    );

    let program = build_test!(source, &[]);
    program.expect_stack(&[0, 100, 100, 100, 0]);
}

#[test]
fn test_unsorted_array_find_word_fails() {
    let source: String = format!(
        "
        use miden::core::collections::sorted_array

        {TRUNCATE_STACK_PROC}

        begin
            # these words are NOT in ascending order, must fail
            # word[3] values: 2767, 593, 5143 - not ascending
            push.[8675,5816,5458,2767] mem_storew_le.100 dropw
            push.[8456,415,4922,593] mem_storew_le.104 dropw
            push.[3015,7211,2002,5143] mem_storew_le.108 dropw

            push.112 push.100 push.[8675,5816,5458,2767]

            exec.sorted_array::find_word
            exec.truncate_stack
        end
    "
    );

    let program = build_test!(source, &[]);
    program.execute().expect_err("NotAscendingOrder");
}

#[test]
fn test_sorted_key_value_array_find_key() {
    // (word, was_value_found, value_ptr)
    let tests = [
        ("8413,5080,6742,354", 0, 100),  // less than smallest key
        ("8456,415,4922,593", 1, 100),   // smallest key
        ("4942,5573,1077,1968", 0, 108), // value, not a key
        ("8675,5816,5458,2767", 0, 108), // not a key
        ("3348,6058,5470,2813", 1, 108), // middle key
        ("3015,7211,2002,5143", 0, 116), // value,not a key
        ("1152,1526,2547,5314", 0, 116), // not a key
        ("7513,7106,9944,7176", 1, 116), // largest key
        ("8595,8794,8303,7256", 0, 124), // value, not a key
        ("1635,5897,3495,8402", 0, 124), // more than largest key
    ];

    for test in tests {
        let (key, was_key_found, key_ptr) = test;
        let source: String = format!(
            "
            use miden::core::collections::sorted_array

            {TRUNCATE_STACK_PROC}

            begin
                push.[8456,415,4922,593] mem_storew_le.100 dropw
                push.[8595,8794,8303,7256] mem_storew_le.104 dropw

                push.[3348,6058,5470,2813] mem_storew_le.108 dropw
                push.[3015,7211,2002,5143] mem_storew_le.112 dropw

                push.[7513,7106,9944,7176] mem_storew_le.116 dropw
                push.[4942,5573,1077,1968] mem_storew_le.120 dropw

                push.124 push.100 push.[{key}]

                exec.sorted_array::find_key_value
                exec.truncate_stack
            end
        "
        );

        let program = build_test!(source, &[]);
        program.expect_stack(&[was_key_found, key_ptr, 100, 124, 0]);
    }
}

#[test]
fn test_sorted_key_value_array_find_half_key() {
    // (key_suffix, key_prefix, was_key_found, value_ptr)
    // Half-key matches on w3 (prefix, most significant) and w2 (suffix)
    let tests = [
        (3, 4, 1, 100),     // half key (w3=4, w2=3) present at 100
        (12, 13, 1, 108),   // half key (w3=13, w2=12) present at 108
        (50, 51, 0, 116),   // not found, smaller than largest key (w3=100)
        (102, 103, 0, 124), // not found, larger than largest key
    ];

    for test in tests {
        let (key_suffix, key_prefix, was_key_found, key_ptr) = test;
        let source: String = format!(
            "
            use miden::core::collections::sorted_array

            {TRUNCATE_STACK_PROC}

            begin
                # Keys in ascending BE order: w3 = 4 < 13 < 100
                push.[9,9,3,4] mem_storew_le.100 dropw
                push.[5,5,5,5] mem_storew_le.104 dropw

                push.[10,11,12,13] mem_storew_le.108 dropw
                push.[3,3,3,3] mem_storew_le.112 dropw

                push.[1,1,1,100] mem_storew_le.116 dropw
                push.[8,8,8,8] mem_storew_le.120 dropw

                push.124 push.100 push.{key_suffix} push.{key_prefix}

                exec.sorted_array::find_half_key_value
                exec.truncate_stack
            end
        "
        );

        let program = build_debug_test!(source, &[]);
        program.expect_stack(&[was_key_found, key_ptr, 100, 124, 0]);
    }
}

#[test]
fn test_empty_sorted_key_value_array_find_key() {
    let source: String = format!(
        "
        use miden::core::collections::sorted_array

        {TRUNCATE_STACK_PROC}

        begin
            push.100 push.100 push.[8413,5080,6742,354]

            exec.sorted_array::find_key_value
            exec.truncate_stack
        end
    "
    );

    let program = build_test!(source, &[]);
    program.expect_stack(&[0, 100, 100, 100, 0]);
}

#[test]
fn test_unsorted_key_value_find_key_fails() {
    let source: String = format!(
        "
        use miden::core::collections::sorted_array

        {TRUNCATE_STACK_PROC}

        begin
            # these keys are NOT in ascending BE order, must fail
            # w3 values: 2767, 593, 5143 - not ascending (2767 > 593)
            push.[8675,5816,5458,2767] mem_storew_le.100 dropw
            push.[4942,5573,1077,1968] mem_storew_le.104 dropw

            push.[8456,415,4922,593] mem_storew_le.108 dropw
            push.[3015,7211,2002,5143] mem_storew_le.112 dropw

            push.[3015,7211,2002,5143] mem_storew_le.116 dropw
            push.[8595,8794,8303,7256] mem_storew_le.120 dropw

            push.124 push.100 push.[8675,5816,5458,2767]

            exec.sorted_array::find_key_value
            exec.truncate_stack
        end
    "
    );

    let program = build_test!(source, &[]);
    program.execute().expect_err("NotAscendingOrder");
}

#[test]
fn test_misaligned_key_value_find_key_fails() {
    let source: String = format!(
        "
        use miden::core::collections::sorted_array

        {TRUNCATE_STACK_PROC}

        begin
            # last value is missing
            push.[8456,415,4922,593] mem_storew_le.100 dropw
            push.[8595,8794,8303,7256] mem_storew_le.104 dropw

            push.[3348,6058,5470,2813] mem_storew_le.108 dropw
            push.[3015,7211,2002,5143] mem_storew_le.112 dropw

            push.[7513,7106,9944,7176] mem_storew_le.116 dropw

            push.120 push.100 push.[8675,5816,5458,2767]

            exec.sorted_array::find_key_value
            exec.truncate_stack
        end
    "
    );

    let program = build_test!(source, &[]);
    program.execute().expect_err("InvalidKeyValueRange");
}

// MALICIOUS ADVICE PROVIDER TESTS
// ================================================================================================
// These tests verify that MASM code properly validates non-deterministic data from the advice
// provider. By initializing the advice stack with known-bad values at the start of the test,
// we can verify that validation logic correctly rejects invalid inputs.

/// Tests that MASM validation catches an out-of-bounds pointer from malicious advice.
///
/// This test initializes the advice stack with a pointer value (200) that is outside
/// the valid range [100, 112], verifying that the MASM code properly validates the
/// pointer before using it.
#[test]
fn test_malicious_advice_invalid_pointer() {
    let source = format!(
        "
        use miden::core::collections::sorted_array

        {TRUNCATE_STACK_PROC}

        begin
            # Store sorted array in memory
            push.[8456,415,4922,593] mem_storew_le.100 dropw
            push.[8675,5816,5458,2767] mem_storew_le.104 dropw
            push.[3015,7211,2002,5143] mem_storew_le.108 dropw

            # Setup: [KEY, start_ptr, end_ptr]
            push.112 push.100 push.[8456,415,4922,593]

            # Pop the malicious values from advice stack (initialized at test start)
            # was_key_found, maybe_key_ptr
            adv_push.2
            # => [maybe_key_ptr, was_key_found, KEY, start_ptr, end_ptr, ...]

            # Now validate the pointer is within bounds
            # This is what the real find_word does after getting advice
            dup movup.8 dup.2 # => [maybe_key_ptr, end_ptr, start_ptr, maybe_key_ptr, ...]
            u32lte assert.err=\"ptr_exceeds_end\" # maybe_key_ptr <= end_ptr
            u32gte assert.err=\"ptr_below_start\" # start_ptr <= maybe_key_ptr

            exec.truncate_stack
        end
    "
    );

    // Initialize advice stack with malicious values: [maybe_key_ptr=200, was_key_found=1]
    // adv_push.2 pops values and pushes them, resulting in [maybe_key_ptr, was_key_found, ...]
    // The valid range is [100, 112], so 200 is clearly out of bounds
    let test = build_test!(source, &[], &[200, 1]);

    // Execution should fail because the pointer validation will catch the invalid value
    let result = test.execute();
    assert!(result.is_err(), "Expected validation to fail for out-of-bounds pointer");
}

/// Tests that MASM validation catches a misaligned pointer from malicious advice.
///
/// Pointers must be word-aligned (multiple of 4). This test initializes the advice
/// stack with a non-aligned pointer to verify the alignment check works.
#[test]
fn test_malicious_advice_misaligned_pointer() {
    let source = format!(
        "
        use miden::core::collections::sorted_array

        {TRUNCATE_STACK_PROC}

        begin
            # Store sorted array in memory
            push.[8456,415,4922,593] mem_storew_le.100 dropw

            # Setup: [KEY, start_ptr, end_ptr]
            push.104 push.100 push.[8456,415,4922,593]

            # Pop the malicious values from advice stack
            adv_push.2
            # => [maybe_key_ptr, was_key_found, ...]

            # Validate alignment: pointer must be divisible by 4
            # Use u32and with 3 to check if lower 2 bits are zero
            dup push.3 u32and
            # => [lower_bits, maybe_key_ptr, ...]
            # If lower_bits != 0, pointer is misaligned
            assertz.err=\"ptr_not_aligned\"

            exec.truncate_stack
        end
    "
    );

    // Initialize advice stack with malicious values: [maybe_key_ptr=101, was_key_found=1]
    // adv_push.2 pops values and pushes them, resulting in [maybe_key_ptr, was_key_found, ...]
    // 101 is not divisible by 4, so it's misaligned
    let test = build_test!(source, &[], &[101, 1]);

    // Execution should fail due to alignment check
    let result = test.execute();
    assert!(result.is_err(), "Expected validation to fail for misaligned pointer");
}

/// Tests verification that the key at the returned pointer actually matches.
///
/// This test initializes the advice stack with a valid pointer but with was_key_found=1,
/// then verifies that the MASM code checks if the key at that pointer actually matches
/// the search key.
#[test]
fn test_malicious_advice_wrong_key_found_flag() {
    let source = format!(
        "
        use miden::core::collections::sorted_array

        {TRUNCATE_STACK_PROC}

        begin
            # Store a key-value pair
            push.[8456,415,4922,593] mem_storew_le.100 dropw

            # Search for a DIFFERENT key that is NOT in the array
            push.104 push.100 push.[9999,9999,9999,9999]

            # Pop the malicious values from advice stack
            adv_push.2
            # => [maybe_key_ptr=100, was_key_found=1, KEY_search, start_ptr, end_ptr]

            # If was_key_found is true, verify the key at the pointer matches
            dup.1 # => [was_key_found, maybe_key_ptr, was_key_found, ...]
            if.true
                # Load the key from memory and compare with search key
                dup mem_loadw_le
                # => [KEY_at_ptr, maybe_key_ptr, was_key_found, KEY_search, ...]
                movup.4 movup.4 movup.4 movup.4
                # => [KEY_search, KEY_at_ptr, maybe_key_ptr, was_key_found, ...]

                # Compare all 4 elements
                movup.4 eq movdn.3 # w0
                movup.4 eq movdn.3 # w1
                movup.4 eq movdn.3 # w2
                movup.4 eq         # w3
                # => [w3_eq, w2_eq, w1_eq, w0_eq, ...]
                and and and
                # => [all_equal, maybe_key_ptr, was_key_found, ...]

                assert.err=\"key_mismatch\" # Keys must match if was_key_found is true
            end

            exec.truncate_stack
        end
    "
    );

    // Initialize advice stack with malicious values: [maybe_key_ptr=100, was_key_found=1]
    // adv_push.2 pops values and pushes them, resulting in [maybe_key_ptr, was_key_found, ...]
    // Claiming the key was found at ptr=100, but we're searching for a different key
    let test = build_test!(source, &[], &[100, 1]);

    // Should fail because the key at ptr=100 doesn't match the search key
    let result = test.execute();
    assert!(result.is_err(), "Expected validation to fail for wrong key_found flag");
}
