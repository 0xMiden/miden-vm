use super::{Felt, TRUNCATE_STACK_PROC, ToElements, apply_permutation, build_op_test, build_test};

// LOADING SINGLE ELEMENT ONTO THE STACK (MLOAD)
// ================================================================================================

#[test]
fn mem_load() {
    let addr = 1;
    let asm_op = "mem_load";

    // --- read from uninitialized memory - address provided via the stack ------------------------
    let test = build_op_test!(asm_op, &[addr]);
    test.expect_stack(&[0]);

    // --- read from uninitialized memory - address provided as a parameter -----------------------
    let asm_op = format!("{asm_op}.{addr}");
    let test = build_op_test!(&asm_op);
    test.expect_stack(&[0]);

    // --- the rest of the stack is unchanged -----------------------------------------------------
    let test = build_op_test!(&asm_op, &[1, 2, 3, 4]);
    test.expect_stack(&[0, 4, 3, 2, 1]);
}

// SAVING A SINGLE ELEMENT INTO MEMORY (MSTORE)
// ================================================================================================

#[test]
fn mem_store() {
    let asm_op = "mem_store";
    let addr = 0_u32;

    // --- address provided via the stack ---------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, addr as u64]);
    test.expect_stack_and_memory(&[3, 2, 1], addr, &[4, 0, 0, 0]);

    // --- address provided as a parameter --------------------------------------------------------
    let asm_op = format!("{asm_op}.{addr}");
    let test = build_op_test!(&asm_op, &[1, 2, 3, 4]);
    test.expect_stack_and_memory(&[3, 2, 1], addr, &[4, 0, 0, 0]);
}

// LOADING A WORD FROM MEMORY (MLOADW)
// ================================================================================================

#[test]
fn mem_loadw() {
    let addr = 4;
    let asm_op = "mem_loadw";

    // --- read from uninitialized memory - address provided via the stack ------------------------
    let test = build_op_test!(asm_op, &[addr, 5, 6, 7, 8]);
    test.expect_stack(&[0, 0, 0, 0]);

    // --- read from uninitialized memory - address provided as a parameter -----------------------
    let asm_op = format!("{asm_op}.{addr}");

    let test = build_op_test!(asm_op, &[5, 6, 7, 8]);
    test.expect_stack(&[0, 0, 0, 0]);

    // --- the rest of the stack is unchanged -----------------------------------------------------

    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8]);
    test.expect_stack(&[0, 0, 0, 0, 4, 3, 2, 1]);
}

// SAVING A WORD INTO MEMORY (MSTOREW)
// ================================================================================================

#[test]
fn mem_storew() {
    let asm_op = "mem_storew";
    let addr = 0_u32;

    // --- address provided via the stack ---------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, addr as u64]);
    test.expect_stack_and_memory(&[4, 3, 2, 1], addr, &[1, 2, 3, 4]);

    // --- address provided as a parameter --------------------------------------------------------
    let asm_op = format!("{asm_op}.{addr}");
    let test = build_op_test!(&asm_op, &[1, 2, 3, 4]);
    test.expect_stack_and_memory(&[4, 3, 2, 1], addr, &[1, 2, 3, 4]);

    // --- the rest of the stack is unchanged -----------------------------------------------------
    let test = build_op_test!(&asm_op, &[0, 1, 2, 3, 4]);
    test.expect_stack_and_memory(&[4, 3, 2, 1, 0], addr, &[1, 2, 3, 4]);
}

// LOADING A WORD FROM MEMORY WITH ENDIANNESS (MEM_LOADW_BE/LE)
// ================================================================================================

#[test]
fn mem_loadw_be() {
    let asm_op = "mem_loadw_be";
    let addr = 0_u32;

    // mem_loadw_be loads from uninitialized memory (all zeros) and applies big-endian ordering

    // --- address provided via the stack ---------------------------------------------------------
    let test = build_op_test!(asm_op, &[addr as u64, 5, 6, 7, 8]);
    test.expect_stack_and_memory(&[0, 0, 0, 0], addr, &[0, 0, 0, 0]);

    // --- address provided as a parameter --------------------------------------------------------
    let asm_op = format!("{asm_op}.{addr}");
    let test = build_op_test!(&asm_op, &[5, 6, 7, 8]);
    test.expect_stack_and_memory(&[0, 0, 0, 0], addr, &[0, 0, 0, 0]);

    // --- the rest of the stack is unchanged -----------------------------------------------------
    let test = build_op_test!(&asm_op, &[1, 2, 3, 4, 5, 6, 7, 8]);
    test.expect_stack_and_memory(&[0, 0, 0, 0, 4, 3, 2, 1], addr, &[0, 0, 0, 0]);
}

#[test]
fn mem_loadw_le() {
    let asm_op = "mem_loadw_le";
    let addr = 0_u32;

    // mem_loadw_le should behave exactly like standard mem_loadw (little-endian/reversed order)

    // --- address provided via the stack ---------------------------------------------------------
    let test = build_op_test!(asm_op, &[addr as u64, 5, 6, 7, 8]);
    test.expect_stack_and_memory(&[0, 0, 0, 0], addr, &[0, 0, 0, 0]);

    // --- address provided as a parameter --------------------------------------------------------
    let asm_op = format!("{asm_op}.{addr}");
    let test = build_op_test!(&asm_op, &[5, 6, 7, 8]);
    test.expect_stack_and_memory(&[0, 0, 0, 0], addr, &[0, 0, 0, 0]);

    // --- the rest of the stack is unchanged -----------------------------------------------------
    let test = build_op_test!(&asm_op, &[1, 2, 3, 4, 5, 6, 7, 8]);
    test.expect_stack_and_memory(&[0, 0, 0, 0, 4, 3, 2, 1], addr, &[0, 0, 0, 0]);
}

// STORING A WORD TO MEMORY WITH ENDIANNESS (MEM_STOREW_BE/LE)
// ================================================================================================

#[test]
fn mem_storew_be() {
    let asm_op = "mem_storew_be";
    let addr = 0_u32;

    // mem_storew_be should store in big-endian (memory) order
    // Input stack: [1, 2, 3, 4] -> Memory: [4, 3, 2, 1], Stack: [1, 2, 3, 4] (preserves original
    // order on stack)

    // --- address provided via the stack ---------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, addr as u64]);
    test.expect_stack_and_memory(&[1, 2, 3, 4], addr, &[4, 3, 2, 1]);

    // --- address provided as a parameter --------------------------------------------------------
    let asm_op = format!("{asm_op}.{addr}");
    let test = build_op_test!(&asm_op, &[1, 2, 3, 4]);
    test.expect_stack_and_memory(&[1, 2, 3, 4], addr, &[4, 3, 2, 1]);

    // --- the rest of the stack is unchanged -----------------------------------------------------
    let test = build_op_test!(&asm_op, &[0, 1, 2, 3, 4]);
    test.expect_stack_and_memory(&[1, 2, 3, 4, 0], addr, &[4, 3, 2, 1]);
}

#[test]
fn mem_storew_le() {
    let asm_op = "mem_storew_le";
    let addr = 0_u32;

    // mem_storew_le should behave exactly like standard mem_storew (little-endian/reversed order)

    // --- address provided via the stack ---------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, addr as u64]);
    test.expect_stack_and_memory(&[4, 3, 2, 1], addr, &[1, 2, 3, 4]);

    // --- address provided as a parameter --------------------------------------------------------
    let asm_op = format!("{asm_op}.{addr}");
    let test = build_op_test!(&asm_op, &[1, 2, 3, 4]);
    test.expect_stack_and_memory(&[4, 3, 2, 1], addr, &[1, 2, 3, 4]);

    // --- the rest of the stack is unchanged -----------------------------------------------------
    let test = build_op_test!(&asm_op, &[0, 1, 2, 3, 4]);
    test.expect_stack_and_memory(&[4, 3, 2, 1, 0], addr, &[1, 2, 3, 4]);
}

// ENDIANNESS ROUNDTRIP TESTS
// ================================================================================================

#[test]
fn mem_endianness_roundtrip() {
    // Test that we can store and load consistently with different endianness instructions

    // Test BE roundtrip: store BE, load BE should preserve order
    let test = build_op_test!("mem_storew_be.0 mem_loadw_be.0", &[1, 2, 3, 4]);
    test.expect_stack(&[4, 3, 2, 1]);

    // Test LE roundtrip: store LE, load LE should preserve order
    let test = build_op_test!("mem_storew_le.0 mem_loadw_le.0", &[1, 2, 3, 4]);
    test.expect_stack(&[4, 3, 2, 1]);

    // Test mixed endianness: store BE, load LE should reverse order
    let test = build_op_test!("mem_storew_be.0 mem_loadw_le.0", &[1, 2, 3, 4]);
    test.expect_stack(&[1, 2, 3, 4]);

    // Test mixed endianness: store LE, load BE should reverse order
    let test = build_op_test!("mem_storew_le.0 mem_loadw_be.0", &[1, 2, 3, 4]);
    test.expect_stack(&[1, 2, 3, 4]);

    // Test store_le and load
    let test = build_op_test!("mem_storew_le.0 mem_loadw.0", &[1, 2, 3, 4]);
    test.expect_stack(&[4, 3, 2, 1]);

    // Test store and load_le
    let test = build_op_test!("mem_storew.0 mem_loadw_le.0", &[1, 2, 3, 4]);
    test.expect_stack(&[4, 3, 2, 1]);

    // Sanity check that the last two match with primitive store/load
    let test = build_op_test!("mem_storew.0 mem_loadw.0", &[1, 2, 3, 4]);
    test.expect_stack(&[4, 3, 2, 1]);
}

// STREAMING ELEMENTS FROM MEMORY (MSTREAM)
// ================================================================================================

#[test]
fn mem_stream() {
    let source = format!(
        "
        {TRUNCATE_STACK_PROC}

        begin
            push.4
            mem_storew
            dropw
            push.0
            mem_storew
            dropw
            push.12.11.10.9.8.7.6.5.4.3.2.1
            mem_stream

            exec.truncate_stack
        end"
    );

    let inputs = [1, 2, 3, 4, 5, 6, 7, 8];

    // the state is built by replacing the values on the top of the stack with the values in memory
    // addresses `[0..8)`. Thus, the first 8 elements on the stack will be 1
    // through 8 (in stack order, with 8 at stack[0]), and the remaining 4 are untouched (i.e., 9,
    // 10, 11, 12).
    let state: [Felt; 12] =
        [12_u64, 11, 10, 9, 1, 2, 3, 4, 5, 6, 7, 8].to_elements().try_into().unwrap();

    // to get the final state of the stack, reverse the above state and push the expected address
    // to the end (the address will be 2 since 0 + 2 = 2).
    let mut final_stack = state.iter().map(|&v| v.as_int()).collect::<Vec<u64>>();
    final_stack.reverse();
    final_stack.push(8);

    let test = build_test!(source, &inputs);
    test.expect_stack(&final_stack);
}

#[test]
fn mem_stream_with_hperm() {
    let source = format!(
        "
        {TRUNCATE_STACK_PROC}

        begin
            push.4
            mem_storew
            dropw
            push.0
            mem_storew
            dropw
            push.12.11.10.9.8.7.6.5.4.3.2.1
            mem_stream hperm

            exec.truncate_stack
        end"
    );

    let inputs = [1, 2, 3, 4, 5, 6, 7, 8];

    // the state of the hasher is the first 12 elements of the stack (in reverse order). the state
    // is built by replacing the values on the top of the stack with the values in memory addresses
    // 0 and 1 (i.e., 1 through 8). Thus, the first 8 elements on the stack will be 1 through 8 (in
    // stack order, with 8 at stack[0]), and the remaining 4 are untouched (i.e., 9, 10, 11, 12).
    let mut state: [Felt; 12] =
        [12_u64, 11, 10, 9, 1, 2, 3, 4, 5, 6, 7, 8].to_elements().try_into().unwrap();

    // apply a hash permutation to the state
    apply_permutation(&mut state);

    // to get the final state of the stack, reverse the hasher state and push the expected address
    // to the end (the address will be 2 since 0 + 2 = 2).
    let mut final_stack = state.iter().map(|&v| v.as_int()).collect::<Vec<u64>>();
    final_stack.reverse();
    final_stack.push(8);

    let test = build_test!(source, &inputs);
    test.expect_stack(&final_stack);
}

// PAIRED OPERATIONS
// ================================================================================================

#[test]
fn inverse_operations() {
    // --- pop and push are inverse operations, so the stack should be left unchanged -------------
    let source = "
        begin
            push.0
            mem_store
            mem_store.1
            push.1
            mem_load
            mem_load.0

            movup.6 movup.6 drop drop
        end";

    let inputs = [0, 1, 2, 3, 4];
    let mut final_stack = inputs;
    final_stack.reverse();

    let test = build_test!(source, &inputs);
    test.expect_stack(&final_stack);

    // --- storew and loadw are inverse operations, so the stack should be left unchanged ---------
    let source = "
        begin
            push.0
            mem_storew
            mem_storew.4
            push.4
            mem_loadw
            mem_loadw.0
        end";

    let inputs = [0, 1, 2, 3, 4];
    let mut final_stack = inputs;
    final_stack.reverse();

    let test = build_test!(source, &inputs);
    test.expect_stack(&final_stack);
}

#[test]
fn read_after_write() {
    // --- write to memory first, then test read with push --------------------------------------
    let test = build_op_test!("mem_storew.0 mem_load.0", &[1, 2, 3, 4]);
    test.expect_stack(&[1, 4, 3, 2, 1]);

    // --- write to memory first, then test read with pushw --------------------------------------
    let test = build_op_test!("mem_storew.0 push.0.0.0.0 mem_loadw.0", &[1, 2, 3, 4]);
    test.expect_stack(&[4, 3, 2, 1, 4, 3, 2, 1]);

    // --- write to memory first, then test read with loadw --------------------------------------
    let test = build_op_test!("mem_storew.0 dropw mem_loadw.0", &[1, 2, 3, 4, 5, 6, 7, 8]);
    test.expect_stack(&[8, 7, 6, 5]);
}
