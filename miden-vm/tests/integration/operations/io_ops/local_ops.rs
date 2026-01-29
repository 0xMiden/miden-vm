use super::{TRUNCATE_STACK_PROC, build_test};

// PUSHING VALUES ONTO THE STACK (PUSH)
// ================================================================================================

#[test]
fn push_local() {
    let source = "
        @locals(4)
        proc foo
            loc_load.0
        end

        begin
            exec.foo
            movup.5 drop
        end";

    // --- 1 value is pushed & the rest of the stack is unchanged ---------------------------------
    let inputs = [1, 2, 3, 4];
    // In general, there is no guarantee that reading from uninitialized memory will result in ZEROs
    // but in this case since no other operations are executed, we do know it will push a ZERO.
    let final_stack = [0, 1, 2, 3, 4];

    build_test!(source, &inputs).expect_stack(&final_stack);
}

// REMOVING VALUES FROM THE STACK (POP)
// ================================================================================================

#[test]
fn pop_local() {
    // --- test write to local memory -------------------------------------------------------------
    let source = "
        @locals(8)
        proc foo
            loc_store.0
            loc_store.4
            loc_load.0
            loc_load.4
        end
        begin
            exec.foo
            swapw dropw
        end";

    // Stack [1, 2, 4, 3] - after stores and loads, result is [2, 1, 4, 3]
    let test = build_test!(source, &[1, 2, 4, 3]);
    test.expect_stack(&[2, 1, 4, 3]);

    // --- test existing memory is not affected ---------------------------------------------------
    let source = "
        @locals(4)
        proc foo
            loc_store.0
        end
        begin
            mem_store.0
            mem_store.1
            exec.foo
        end";
    let mem_addr = 1;

    let test = build_test!(source, &[1, 2, 3, 4]);
    test.expect_stack_and_memory(&[4], mem_addr, &[2, 0, 0, 0]);
}

// OVERWRITING VALUES ON THE STACK (LOAD)
// ================================================================================================

#[test]
fn loadw_local() {
    let source = "
        @locals(4)
        proc foo
            loc_loadw_be.0
        end
        begin
            exec.foo
        end";

    // --- the top 4 values are overwritten & the rest of the stack is unchanged ------------------
    let inputs = [1, 2, 3, 4, 5, 6, 7, 8];
    // In general, there is no guarantee that reading from uninitialized memory will result in ZEROs
    // but in this case since no other operations are executed, we do know it will load ZEROs.
    let final_stack = [0, 0, 0, 0, 5, 6, 7, 8];

    build_test!(source, &inputs).expect_stack(&final_stack);
}

// SAVING STACK VALUES WITHOUT REMOVING THEM (STORE)
// ================================================================================================

#[test]
fn storew_local() {
    // --- test write to local memory -------------------------------------------------------------
    let source = format!(
        "
        {TRUNCATE_STACK_PROC}

        @locals(8)
        proc foo
            loc_storew_be.0
            swapw
            loc_storew_be.4
            swapw
            padw
            loc_loadw_be.0
            padw
            loc_loadw_be.4
        end
        begin
            exec.foo

            exec.truncate_stack
        end"
    );

    let test = build_test!(source, &[8, 7, 6, 5, 4, 3, 2, 1]);
    test.expect_stack(&[4, 3, 2, 1, 8, 7, 6, 5, 8, 7, 6, 5, 4, 3, 2, 1]);

    // --- test existing memory is not affected ---------------------------------------------------
    let source = "
        @locals(8)
        proc foo
            loc_storew_be.0
        end
        begin
            mem_storew_be.0
            dropw
            mem_storew_be.4
            dropw
            exec.foo
        end";
    let mem_addr = 4;

    let test = build_test!(source, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    test.expect_stack_and_memory(&[9, 10, 11, 12], mem_addr, &[8, 7, 6, 5]);
}

// NESTED PROCEDURES & PAIRED OPERATIONS (push/pop, pushw/popw, loadw/storew)
// ================================================================================================

#[test]
fn inverse_operations() {
    // --- pop and push are inverse operations, so the stack should be left unchanged -------------
    let source = "
        @locals(4)
        proc foo
            loc_store.0
            loc_load.0
        end

        begin
            exec.foo
            movup.5 drop
        end";
    let inputs = [0, 1, 2, 3, 4];
    let final_stack = inputs;

    let test = build_test!(source, &inputs);
    test.expect_stack(&final_stack);

    // --- popw and pushw are inverse operations, so the stack should be left unchanged -----------
    let source = "
        @locals(4)
        proc foo
            loc_storew_be.0
            dropw
            padw
            loc_loadw_be.0
        end

        begin
            exec.foo
            swapw dropw
        end";
    let inputs = [1, 2, 3, 4];
    let final_stack = inputs;

    let test = build_test!(source, &inputs);
    test.expect_stack(&final_stack);

    // --- storew and loadw are inverse operations, so the stack should be left unchanged ---------
    let source = "
        @locals(4)
        proc foo
            loc_storew_be.0
            loc_loadw_be.0
        end

        begin
            exec.foo
        end";
    let inputs = [0, 1, 2, 3, 4];
    let final_stack = inputs;

    let test = build_test!(source, &inputs);
    test.expect_stack(&final_stack);
}

#[test]
fn read_after_write() {
    // --- write to memory first, then test read with push --------------------------------------
    let source = "
        @locals(4)
        proc foo
            loc_storew_be.0
            loc_load.0
        end
        begin
            exec.foo
            movup.5 drop
        end";

    let test = build_test!(source, &[4, 3, 2, 1]);
    test.expect_stack(&[1, 4, 3, 2, 1]);

    // --- write to memory first, then test read with pushw --------------------------------------
    let source = "
        @locals(4)
        proc foo
            loc_storew_be.0
            padw
            loc_loadw_be.0
        end
        begin
            exec.foo
            swapdw dropw dropw
        end";

    let test = build_test!(source, &[1, 2, 3, 4]);
    test.expect_stack(&[1, 2, 3, 4, 1, 2, 3, 4]);

    // --- write to memory first, then test read with loadw --------------------------------------
    let source = "
        @locals(4)
        proc foo
            loc_storew_be.0
            dropw
            loc_loadw_be.0
        end
        begin
            exec.foo
        end";

    let test = build_test!(source, &[1, 2, 3, 4, 5, 6, 7, 8]);
    test.expect_stack(&[1, 2, 3, 4]);
}

#[test]
fn nested_procedures() {
    // --- test nested procedures - pop/push ------------------------------------------------------
    let source = "
        @locals(4)
        proc foo
            loc_store.0
        end

        @locals(4)
        proc bar
            loc_store.0
            exec.foo
            loc_load.0
        end

        begin
            exec.bar
            movup.3 drop
        end";
    let inputs = [3, 2, 1, 0];

    let test = build_test!(source, &inputs);
    test.expect_stack(&[3, 1, 0]);

    // --- test nested procedures - popw/pushw ----------------------------------------------------
    let source = "
        @locals(4)
        proc foo
            loc_storew_be.0
            dropw
        end
        @locals(4)
        proc bar
            loc_storew_be.0
            dropw
            exec.foo
            padw
            loc_loadw_be.0
        end
        begin
            exec.bar
            swapw dropw
        end";
    let inputs = [0, 1, 2, 3, 4, 5, 6, 7];

    let test = build_test!(source, &inputs);
    test.expect_stack(&[0, 1, 2, 3]);

    // --- test nested procedures - storew/loadw --------------------------------------------------
    let source = "
        @locals(4)
        proc foo
            push.0 push.0
            loc_storew_be.0
        end
        @locals(4)
        proc bar
            loc_storew_be.0
            exec.foo
            loc_loadw_be.0
        end
        begin
            exec.bar
            movup.7 movup.7 drop drop
        end";
    let inputs = [0, 1, 2, 3];

    let test = build_test!(source, &inputs);
    test.expect_stack(&[0, 1, 2, 3, 2, 3]);
}

#[test]
fn free_memory_pointer() {
    // ensure local procedure memory doesn't overwrite memory from outer scope
    let source = "
        @locals(8)
        proc bar
            loc_store.0
            loc_store.4
        end
        begin
            mem_store.0
            mem_store.1
            mem_store.2
            mem_store.3
            exec.bar
            mem_load.3
            mem_load.2
            mem_load.1
            mem_load.0

            movupw.2 dropw
        end";
    let inputs = [7, 6, 5, 4, 3, 2, 1];

    let test = build_test!(source, &inputs);
    test.expect_stack(&[7, 6, 5, 4, 1]);
}

// WORD ALIGNMENT
// ================================================================================================

#[test]
fn locaddr_word_alignment_non_multiple_of_four() {
    // Test for issue #2348: locaddr.0 should be word-aligned even when
    // number of proc locals is not a multiple of 4
    let source = "
        @locals(5)
        proc foo
            loc_storew_be.0
        end
        begin
            exec.foo
        end";

    build_test!(source, &[]).execute().unwrap();
}
