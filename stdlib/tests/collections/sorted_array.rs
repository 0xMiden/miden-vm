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
            use.std::collections::sorted_array

            {TRUNCATE_STACK_PROC}

            begin
                push.8456.415.4922.593 mem_storew.100 dropw
                push.8675.5816.5458.2767 mem_storew.104 dropw
                push.3015.7211.2002.5143 mem_storew.108 dropw

                push.112 push.100 push.[{key}]

                exec.sorted_array::find_word
                exec.truncate_stack
            end
        "
        );

        let program = build_test!(source, &[]);
        println!("testing {key}");
        program.expect_stack(&[was_key_found, key_ptr, 100, 112, 0]);
    }
}

#[test]
fn test_empty_sorted_array_find_word() {
    let source: String = format!(
        "
        use.std::collections::sorted_array

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
        use.std::collections::sorted_array

        {TRUNCATE_STACK_PROC}

        begin
            # these words are NOT in ascending order, must fail
            push.8675.5816.5458.2767 mem_storew.100 dropw
            push.8456.415.4922.593 mem_storew.104 dropw
            push.3015.7211.2002.5143 mem_storew.108 dropw

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
    // (word, was_key_found, value_ptr)
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
            use.std::collections::sorted_array

            {TRUNCATE_STACK_PROC}

            begin
                push.8456.415.4922.593 mem_storew.100 dropw
                push.8595.8794.8303.7256 mem_storew.104 dropw

                push.3348.6058.5470.2813 mem_storew.108 dropw
                push.3015.7211.2002.5143 mem_storew.112 dropw

                push.7513.7106.9944.7176 mem_storew.116 dropw
                push.4942.5573.1077.1968 mem_storew.120 dropw

                push.124 push.100 push.[{key}]

                exec.sorted_array::find_key_value
                exec.truncate_stack
            end
        "
        );

        let program = build_debug_test!(source, &[]);
        println!("testing {key}");
        program.expect_stack(&[was_key_found, key_ptr, 100, 124, 0]);
    }
}

#[test]
fn test_sorted_key_value_array_find_half_key() {
    // (key_suffix, key_prefix, was_key_found, value_ptr)
    let tests = [
        (3, 4, 1, 100),     // half key present
        (12, 13, 1, 108),   // half key present
        (50, 51, 0, 116),   // not key, smaller than largest key
        (102, 103, 0, 124), // not key, larger than largest key
    ];

    for test in tests {
        let (key_suffix, key_prefix, was_key_found, key_ptr) = test;
        let source: String = format!(
            "
            use.std::collections::sorted_array

            {TRUNCATE_STACK_PROC}

            begin
                push.9.9.3.4 mem_storew.100 dropw
                push.5.5.5.5 mem_storew.104 dropw

                push.10.11.12.13 mem_storew.108 dropw
                push.3.3.3.3 mem_storew.112 dropw

                push.1.1.1.103 mem_storew.116 dropw
                push.8.8.8.8 mem_storew.120 dropw

                push.124 push.100 push.{key_suffix} push.{key_prefix}

                exec.sorted_array::find_half_key_value
                exec.truncate_stack
            end
        "
        );

        let program = build_debug_test!(source, &[]);
        println!("testing prefix {key_prefix}, suffix {key_suffix}");
        program.expect_stack(&[was_key_found, key_ptr, 100, 124, 0]);
    }
}

#[test]
fn test_empty_sorted_key_value_array_find_key() {
    let source: String = format!(
        "
        use.std::collections::sorted_array

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
        use.std::collections::sorted_array

        {TRUNCATE_STACK_PROC}

        begin
            # these keys are NOT in ascending order, must fail
            push.8675.5816.5458.2767 mem_storew.100 dropw
            push.4942.5573.1077.1968 mem_storew.104 dropw

            push.8456.415.4922.593 mem_storew.108 dropw
            push.3015.7211.2002.5143 mem_storew.112 dropw

            push.3015.7211.2002.5143 mem_storew.116 dropw
            push.8595.8794.8303.7256 mem_storew.120 dropw

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
        use.std::collections::sorted_array

        {TRUNCATE_STACK_PROC}

        begin
            # last value is missing
            push.8456.415.4922.593 mem_storew.100 dropw
            push.8595.8794.8303.7256 mem_storew.104 dropw

            push.3348.6058.5470.2813 mem_storew.108 dropw
            push.3015.7211.2002.5143 mem_storew.112 dropw

            push.7513.7106.9944.7176 mem_storew.116 dropw

            push.120 push.100 push.[8675,5816,5458,2767]

            exec.sorted_array::find_key_value
            exec.truncate_stack
        end
    "
    );

    let program = build_test!(source, &[]);
    program.execute().expect_err("InvalidKeyValueRange");
}
