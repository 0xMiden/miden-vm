use miden_utils_testing::PrimeField64;

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
    let asm_op = "mem_loadw_be";

    // --- read from uninitialized memory - address provided via the stack ------------------------
    let test = build_op_test!(asm_op, &[addr, 5, 6, 7, 8]);
    test.expect_stack(&[0, 0, 0, 0]);

    // --- read from uninitialized memory - address provided as a parameter -----------------------
    let asm_op = format!("mem_loadw_be.{addr}");

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
    let asm_op = "mem_storew_be";
    let addr = 0_u32;

    // --- address provided via the stack ---------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, addr as u64]);
    test.expect_stack_and_memory(&[4, 3, 2, 1], addr, &[1, 2, 3, 4]);

    // --- address provided as a parameter --------------------------------------------------------
    let asm_op = format!("mem_storew_be.{addr}");
    let test = build_op_test!(&asm_op, &[1, 2, 3, 4]);
    test.expect_stack_and_memory(&[4, 3, 2, 1], addr, &[1, 2, 3, 4]);

    // --- the rest of the stack is unchanged -----------------------------------------------------
    let test = build_op_test!(&asm_op, &[0, 1, 2, 3, 4]);
    test.expect_stack_and_memory(&[4, 3, 2, 1, 0], addr, &[1, 2, 3, 4]);
}

// LOADING A WORD FROM MEMORY WITH ENDIANNESS (MEM_LOADW_BE/LE)
// ================================================================================================

#[test]
fn mem_loadw_be_le() {
    const ADDR: u32 = 4;
    const INPUT_BE_IMM: [u64; 8] = [5, 6, 7, 8, 1, 2, 3, 4]; // reversed
    const INPUT_BE: [u64; 9] = [5, 6, 7, 8, 1, 2, 3, 4, ADDR as u64]; // reversed
    const OUTPUT_BE: [u64; 8] = [0, 0, 0, 0, 8, 7, 6, 5];
    const MEM_EMPTY: [u64; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

    // Classic
    {
        let asm_op = "mem_loadw_be";
        let test = build_op_test!(asm_op, &INPUT_BE);
        test.expect_stack_and_memory(&OUTPUT_BE, 0, &MEM_EMPTY);

        let asm_op = format!("mem_loadw_be.{ADDR}");
        let test = build_op_test!(&asm_op, &INPUT_BE_IMM);
        test.expect_stack_and_memory(&OUTPUT_BE, 0, &MEM_EMPTY);
    }

    // Big-endian (equivalent to classic)
    {
        let asm_op = "mem_loadw_be";
        let test = build_op_test!(asm_op, &INPUT_BE);
        test.expect_stack_and_memory(&OUTPUT_BE, 0, &MEM_EMPTY);

        let asm_op = format!("mem_loadw_be.{ADDR}");
        let test = build_op_test!(&asm_op, &INPUT_BE_IMM);
        test.expect_stack_and_memory(&OUTPUT_BE, 0, &MEM_EMPTY);
    }

    // Little-endian
    {
        let asm_op = "mem_loadw_le";
        let test = build_op_test!(asm_op, &INPUT_BE);
        test.expect_stack_and_memory(&OUTPUT_BE, 0, &MEM_EMPTY);

        let asm_op = format!("mem_loadw_le.{ADDR}");
        let test = build_op_test!(&asm_op, &INPUT_BE_IMM);
        test.expect_stack_and_memory(&OUTPUT_BE, 0, &MEM_EMPTY);
    }
}

// STORING A WORD TO MEMORY WITH ENDIANNESS (MEM_STOREW_BE/LE)
// ================================================================================================

#[test]
fn mem_storew_be_le() {
    const ADDR: u32 = 4;
    const INPUT_BE_IMM: [u64; 8] = [5, 6, 7, 8, 1, 2, 3, 4]; // reversed
    const INPUT_BE: [u64; 9] = [5, 6, 7, 8, 1, 2, 3, 4, ADDR as u64]; // reversed
    const OUTPUT_BE: [u64; 8] = [4, 3, 2, 1, 8, 7, 6, 5];
    const MEM_BE: [u64; 8] = [0, 0, 0, 0, 4, 3, 2, 1];
    const MEM_LE: [u64; 8] = [0, 0, 0, 0, 1, 2, 3, 4];

    // mem_storew_be
    {
        let asm_op = "mem_storew_be";
        let test = build_op_test!(asm_op, &INPUT_BE);
        test.expect_stack_and_memory(&OUTPUT_BE, 0, &MEM_LE);

        let asm_op = format!("mem_storew_be.{ADDR}");
        let test = build_op_test!(asm_op, &INPUT_BE_IMM);
        test.expect_stack_and_memory(&OUTPUT_BE, 0, &MEM_LE);
    }

    // mem_storew_be
    {
        let asm_op = "mem_storew_be";
        let test = build_op_test!(asm_op, &INPUT_BE);
        test.expect_stack_and_memory(&OUTPUT_BE, 0, &MEM_LE);

        let asm_op = format!("mem_storew_be.{ADDR}");
        let test = build_op_test!(asm_op, &INPUT_BE_IMM);
        test.expect_stack_and_memory(&OUTPUT_BE, 0, &MEM_LE);
    }

    // mem_storew_le
    {
        let asm_op = "mem_storew_le";
        let test = build_op_test!(asm_op, &INPUT_BE);
        test.expect_stack_and_memory(&OUTPUT_BE, 0, &MEM_BE);

        let asm_op = format!("mem_storew_le.{ADDR}");
        let test = build_op_test!(asm_op, &INPUT_BE_IMM);
        test.expect_stack_and_memory(&OUTPUT_BE, 0, &MEM_BE);
    }
}

// ENDIANNESS ROUNDTRIP TESTS
// ================================================================================================

#[test]
fn mem_endianness_roundtrip() {
    const ADDR: u32 = 4;
    const INPUT_BE: [u64; 8] = [5, 6, 7, 8, 1, 2, 3, 4]; // reversed
    const OUTPUT_BE: [u64; 8] = [4, 3, 2, 1, 8, 7, 6, 5];
    const OUTPUT_LE: [u64; 8] = [1, 2, 3, 4, 8, 7, 6, 5];
    const MEM_LE: [u64; 8] = [0, 0, 0, 0, 1, 2, 3, 4];
    const MEM_BE: [u64; 8] = [0, 0, 0, 0, 4, 3, 2, 1];

    // Sanity check for input/output constants
    {
        let ops = "nop";
        let test = build_op_test!(ops, &INPUT_BE);
        test.expect_stack(&OUTPUT_BE);
    }

    // Round trip with same ordering only affects memory
    {
        // Classic
        let ops = format!("mem_storew_be.{ADDR} mem_loadw_be.{ADDR}");
        let test = build_op_test!(ops, &INPUT_BE);
        test.expect_stack_and_memory(&OUTPUT_BE, 0, &MEM_LE);

        // Big-endian (equivalent to classic)
        let ops = format!("mem_storew_be.{ADDR} mem_loadw_be.{ADDR}");
        let test = build_op_test!(ops, &INPUT_BE);
        test.expect_stack_and_memory(&OUTPUT_BE, 0, &MEM_LE);

        // Little-endian
        let ops = format!("mem_storew_le.{ADDR} mem_loadw_le.{ADDR}");
        let test = build_op_test!(ops, &INPUT_BE);
        test.expect_stack_and_memory(&OUTPUT_BE, 0, &MEM_BE);
    }

    // Using opposite orderings reverses the top word on the stack
    {
        let ops = format!("mem_storew_be.{ADDR} mem_loadw_le.{ADDR}");
        let test = build_op_test!(ops, &INPUT_BE);
        test.expect_stack_and_memory(&OUTPUT_LE, 0, &MEM_LE);

        let ops = format!("mem_storew_le.{ADDR} mem_loadw_be.{ADDR}");
        let test = build_op_test!(ops, &INPUT_BE);
        test.expect_stack_and_memory(&OUTPUT_LE, 0, &MEM_BE);
    }
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
            mem_storew_be
            dropw
            push.0
            mem_storew_be
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
    let mut final_stack = state.iter().map(|&v| v.as_canonical_u64()).collect::<Vec<u64>>();
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
            mem_storew_be
            dropw
            push.0
            mem_storew_be
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
    let mut final_stack = state.iter().map(|&v| v.as_canonical_u64()).collect::<Vec<u64>>();
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
            mem_storew_be
            mem_storew_be.4
            push.4
            mem_loadw_be
            mem_loadw_be.0
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
    let test = build_op_test!("mem_storew_be.0 mem_load.0", &[1, 2, 3, 4]);
    test.expect_stack(&[1, 4, 3, 2, 1]);

    // --- write to memory first, then test read with pushw --------------------------------------
    let test = build_op_test!("mem_storew_be.0 push.0.0.0.0 mem_loadw_be.0", &[1, 2, 3, 4]);
    test.expect_stack(&[4, 3, 2, 1, 4, 3, 2, 1]);

    // --- write to memory first, then test read with loadw --------------------------------------
    let test = build_op_test!("mem_storew_be.0 dropw mem_loadw_be.0", &[1, 2, 3, 4, 5, 6, 7, 8]);
    test.expect_stack(&[8, 7, 6, 5]);
}
