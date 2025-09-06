use super::*;

#[test]
fn test_array_find_sorted_word() {
    let source: String = format!(
        "
        use.std::collections::sorted_array

        {TRUNCATE_STACK_PROC}

        begin
            push.2.2.2.2 mem_storew.100 dropw
            push.3.3.3.3 mem_storew.104 dropw
            push.4.4.4.4 mem_storew.108 dropw

            push.112 push.100 push.[3,3,3,3]

            exec.sorted_array::find_word
            exec.truncate_stack
        end
    "
    );
    let test = build_test!(source, &[]);
    test.expect_stack(&[1, 104, 100, 112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}
