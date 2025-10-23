use miden_utils_testing::build_debug_test;

// STACK DEBUGGING TESTS
// ================================================================================================

#[test]
fn test_debug_stack() {
    let stack_inputs = [1, 2, 3, 4]; // 4 is on top
    let source = "
        begin
            # Check 0 handling
            debug.stack.0

            # Print the initial stack
            debug.stack.4
            # => [4, 3, 2, 1]

            # Check overflow by increasing the stack to 28 elements
            repeat.12
                push.42
            end
            # There are 28 items, there should be 8 more elements we don't print
            debug.stack.20
            dropw dropw dropw
            # There are 16 elements, the last 4 should be EMPTY
            debug.stack.20

            # Push an element and print the first 7 elements.
            # The last should be 0 since the stack was padded with zeros until 16
            push.5 debug.stack.7
            # => [5, 4, 3, 2, 1, 0]

            # Shrink stack to 12 elements and print the whole output
            # We should get 16 elements since zeros are pushed until the size is 16
            drop dropw debug.stack
            # => [0, ..., 0]

        end";

    // Execute with debug buffer
    let test = build_debug_test!(source, &stack_inputs);
    let (_stack, output) = test.execute_with_debug_buffer().expect("execution failed");

    insta::assert_snapshot!(output, @r"
    Stack state before step 1:
    ├──  0: 4
    ├──  1: 3
    ├──  2: 2
    ├──  3: 1
    ├──  4: 0
    ├──  5: 0
    ├──  6: 0
    ├──  7: 0
    ├──  8: 0
    ├──  9: 0
    ├── 10: 0
    ├── 11: 0
    ├── 12: 0
    ├── 13: 0
    ├── 14: 0
    └── 15: 0
    Stack state in interval [0, 3] before step 1:
    ├── 0: 4
    ├── 1: 3
    ├── 2: 2
    ├── 3: 1
    └── (12 more items)
    Stack state in interval [0, 19] before step 15:
    ├──  0: 42
    ├──  1: 42
    ├──  2: 42
    ├──  3: 42
    ├──  4: 42
    ├──  5: 42
    ├──  6: 42
    ├──  7: 42
    ├──  8: 42
    ├──  9: 42
    ├── 10: 42
    ├── 11: 42
    ├── 12: 4
    ├── 13: 3
    ├── 14: 2
    ├── 15: 1
    ├── 16: 0
    ├── 17: 0
    ├── 18: 0
    ├── 19: 0
    └── (8 more items)
    Stack state before step 29:
    ├──  0: 4
    ├──  1: 3
    ├──  2: 2
    ├──  3: 1
    ├──  4: 0
    ├──  5: 0
    ├──  6: 0
    ├──  7: 0
    ├──  8: 0
    ├──  9: 0
    ├── 10: 0
    ├── 11: 0
    ├── 12: 0
    ├── 13: 0
    ├── 14: 0
    ├── 15: 0
    ├── 16: EMPTY
    ├── 17: EMPTY
    ├── 18: EMPTY
    └── 19: EMPTY
    Stack state in interval [0, 6] before step 30:
    ├── 0: 5
    ├── 1: 4
    ├── 2: 3
    ├── 3: 2
    ├── 4: 1
    ├── 5: 0
    ├── 6: 0
    └── (10 more items)
    Stack state before step 36:
    ├──  0: 0
    ├──  1: 0
    ├──  2: 0
    ├──  3: 0
    ├──  4: 0
    ├──  5: 0
    ├──  6: 0
    ├──  7: 0
    ├──  8: 0
    ├──  9: 0
    ├── 10: 0
    ├── 11: 0
    ├── 12: 0
    ├── 13: 0
    ├── 14: 0
    └── 15: 0
    ");
}

#[test]
fn test_debug_mem() {
    let stack_inputs = [5, 3, 2, 1];
    let source = "
        begin
            mem_store.0 mem_store.1 mem_store.2 # => [0->1, 1->2, 2->3]

            debug.mem
            debug.mem.2     # => [2->3]
            debug.mem.6     # => EMPTY
            debug.mem.1.2   # => [1->2, 2->3]

            mem_store.4     # => [4->5]
            debug.mem
            debug.mem.2.5   # [3, 0, 5, 0]
            debug.mem.12.14 # [EMPTY, ..., EMPTY]
        end";

    // Execute with debug buffer
    let test = build_debug_test!(source, &stack_inputs);
    let (_stack, output) = test.execute_with_debug_buffer().expect("execution failed");

    insta::assert_snapshot!(output, @r"
    Memory state before step 11 for the context 0:
    ├── 0x00000000: 1
    ├── 0x00000001: 2
    ├── 0x00000002: 3
    └── 0x00000003: 0
    Memory state before step 11 for the context 0 at address 0x00000002: 3
    Memory state before step 11 for the context 0 at address 0x00000006: EMPTY
    Memory state before step 11 for the context 0 in the interval [1, 2]:
    ├── 0x00000001: 2
    └── 0x00000002: 3
    Memory state before step 15 for the context 0:
    ├── 0x00000000: 1
    ├── 0x00000001: 2
    ├── 0x00000002: 3
    ├── 0x00000003: 0
    ├── 0x00000004: 5
    ├── 0x00000005: 0
    ├── 0x00000006: 0
    └── 0x00000007: 0
    Memory state before step 15 for the context 0 in the interval [2, 5]:
    ├── 0x00000002: 3
    ├── 0x00000003: 0
    ├── 0x00000004: 5
    └── 0x00000005: 0
    Memory state before step 15 for the context 0 in the interval [12, 14]:
    ├── 0x0000000c: EMPTY
    ├── 0x0000000d: EMPTY
    └── 0x0000000e: EMPTY
    ");
}

#[test]
fn test_debug_local() {
    let stack_inputs = [5, 3, 2, 1];
    let local_addr_4 = 0x40000006;
    let source = format!(
        "
        proc.test.6
            # Get address of third local to show it has been initialized to an arbitrary value
            locaddr.4 push.{local_addr_4} assert_eq

            loc_store.0 loc_store.1 loc_store.2 # => [0->1, 1->2, 2->3]

            debug.mem

            debug.local
            debug.local.2   # => 3
            debug.local.4   # => 42 (garbage)
            debug.local.1.2 # => [2, 3]


            loc_store.4 # Overwrite previous garbage value => [4->5]
            debug.local
            debug.local.4   # => 5 (not garbage)
            debug.local.6   # => EMPTY (out of bounds)
            debug.local.2.6 # => [3, 0, 5, 0, EMPTY]
        end
        begin
            # Write a garbage value to show it is not 0 by default
            push.42 mem_store.{local_addr_4}
            exec.test
            debug.mem
        end"
    );

    // Execute with debug buffer
    let test = build_debug_test!(source, &stack_inputs);
    let (_stack, output) = test.execute_with_debug_buffer().expect("execution failed");

    insta::assert_snapshot!(output, @r"
    Memory state before step 25 for the context 0:
    ├── 0x40000000: 0
    ├── 0x40000001: 0
    ├── 0x40000002: 1
    ├── 0x40000003: 2
    ├── 0x40000004: 3
    ├── 0x40000005: 0
    ├── 0x40000006: 42
    └── 0x40000007: 0
    State of procedure locals [0, 5] before step 25:
    ├── 0: 1
    ├── 1: 2
    ├── 2: 3
    ├── 3: 0
    ├── 4: 42
    └── 5: 0
    State of procedure local 2 before step 25: 3
    State of procedure local 4 before step 25: 42
    State of procedure locals [1, 2] before step 25:
    ├── 1: 2
    └── 2: 3
    State of procedure locals [0, 5] before step 29:
    ├── 0: 1
    ├── 1: 2
    ├── 2: 3
    ├── 3: 0
    ├── 4: 5
    └── 5: 0
    State of procedure local 4 before step 29: 5
    State of procedure local 6 before step 29: EMPTY
    State of procedure locals [2, 6] before step 29:
    ├── 2: 3
    ├── 3: 0
    ├── 4: 5
    ├── 5: 0
    └── 6: EMPTY
    Memory state before step 34 for the context 0:
    ├── 0x40000000: 0
    ├── 0x40000001: 0
    ├── 0x40000002: 1
    ├── 0x40000003: 2
    ├── 0x40000004: 3
    ├── 0x40000005: 0
    ├── 0x40000006: 5
    └── 0x40000007: 0
    ");
}

#[test]
fn test_debug_adv_stack() {
    let stack_input = [0, 1, 2, 3, 4]; // 4 is on top
    let advice_stack = [8, 7, 6, 5, 4, 3, 2, 1]; // 8 is on top
    let source = "
        begin
            # => [4, 3, 2, 1, 0]
            debug.adv_stack   # => [8..1]
            debug.adv_stack.2 # => [8, 7]
            debug.adv_stack.0 # => [8..1]

            # Check that we can output output EMPTY when too many elements are requested
            debug.adv_stack.10

            padw adv_loadw
            # => [5, 6, 7, 8, 4, 3, 2, 1, 0]
            debug.adv_stack # => [4, 3, 2, 1, 0]
            debug.stack.9
            push.[8, 7, 6, 5] assert_eqw
            # => [4, 3, 2, 1, 0]

            adv_push.1
            # => [4, 4, 3, 2, 1, 0]
            debug.stack.6
            debug.adv_stack # => [3, 2, 1]

            # Check that we popped 4
            assert_eq
            # => [3, 2, 1, 0]

            # Pops the remaining elements one-by-one
            adv_push.3
            # => [1, 2, 3, 3, 2, 1, 0]
            debug.stack.7

            # Check
            push.0 reversew assert_eqw

            # advice stack is empty
            debug.adv_stack
        end";

    // Execute with debug buffer
    let test = build_debug_test!(source, &stack_input, &advice_stack);
    let (_stack, output) = test.execute_with_debug_buffer().expect("execution failed");

    insta::assert_snapshot!(output, @r"
    Advice stack state before step 1:
    ├── 0: 8
    ├── 1: 7
    ├── 2: 6
    ├── 3: 5
    ├── 4: 4
    ├── 5: 3
    ├── 6: 2
    └── 7: 1
    Advice stack state in interval [0, 1] before step 1:
    ├── 0: 8
    ├── 1: 7
    └── (6 more items)
    Advice stack state before step 1:
    ├── 0: 8
    ├── 1: 7
    ├── 2: 6
    ├── 3: 5
    ├── 4: 4
    ├── 5: 3
    ├── 6: 2
    └── 7: 1
    Advice stack state before step 1:
    ├── 0: 8
    ├── 1: 7
    ├── 2: 6
    ├── 3: 5
    ├── 4: 4
    ├── 5: 3
    ├── 6: 2
    ├── 7: 1
    ├── 8: EMPTY
    └── 9: EMPTY
    Advice stack state before step 6:
    ├── 0: 4
    ├── 1: 3
    ├── 2: 2
    └── 3: 1
    Stack state in interval [0, 8] before step 6:
    ├── 0: 5
    ├── 1: 6
    ├── 2: 7
    ├── 3: 8
    ├── 4: 4
    ├── 5: 3
    ├── 6: 2
    ├── 7: 1
    ├── 8: 0
    └── (11 more items)
    Stack state in interval [0, 5] before step 23:
    ├── 0: 4
    ├── 1: 4
    ├── 2: 3
    ├── 3: 2
    ├── 4: 1
    ├── 5: 0
    └── (11 more items)
    Advice stack state before step 23:
    ├── 0: 3
    ├── 1: 2
    └── 2: 1
    Stack state in interval [0, 6] before step 28:
    ├── 0: 1
    ├── 1: 2
    ├── 2: 3
    ├── 3: 3
    ├── 4: 2
    ├── 5: 1
    ├── 6: 0
    └── (12 more items)
    Advice stack empty before step 45.
    ");
}
