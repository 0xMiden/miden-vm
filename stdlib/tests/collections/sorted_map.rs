use super::*;

#[test]
fn test_array_find_sorted_word() {
    let source: String = format!(
        "
        use.std::collections::sorted_map

        {TRUNCATE_STACK_PROC}

        begin
            push.2.2.2.2 mem_storew.100 dropw
            push.5.5.5.5 mem_storew.104 dropw

            push.4.4.4.4 mem_storew.108 dropw
            push.3.3.3.3 mem_storew.112 dropw

            push.6.6.6.6 mem_storew.116 dropw
            push.1.1.1.1 mem_storew.120 dropw

            push.124 push.100 push.[4,4,4,4]

            exec.sorted_map::find_key
            exec.truncate_stack
        end
    "
    );

    let test = build_test!(source, &[]);
    test.expect_stack(&[1, 108, 100, 124, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}
