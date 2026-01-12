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
    test.expect_stack(&[0, 1, 2, 3, 4]);
}

// SAVING A SINGLE ELEMENT INTO MEMORY (MSTORE)
// ================================================================================================

#[test]
fn mem_store() {
    let asm_op = "mem_store";
    let addr = 0_u32;

    // --- address provided via the stack ---------------------------------------------------------
    let test = build_op_test!(asm_op, &[addr as u64, 4, 3, 2, 1]);
    test.expect_stack_and_memory(&[3, 2, 1], addr, &[4, 0, 0, 0]);

    // --- address provided as a parameter --------------------------------------------------------
    let asm_op = format!("{asm_op}.{addr}");
    let test = build_op_test!(&asm_op, &[4, 3, 2, 1]);
    test.expect_stack_and_memory(&[3, 2, 1], addr, &[4, 0, 0, 0]);
}

// LOADING A WORD FROM MEMORY (MLOADW)
// ================================================================================================

#[test]
fn mem_loadw() {
    let addr = 4;
    let asm_op = "mem_loadw_le";

    // --- read from uninitialized memory - address provided via the stack ------------------------
    let test = build_op_test!(asm_op, &[addr, 5, 6, 7, 8]);
    test.expect_stack(&[0, 0, 0, 0]);

    // --- read from uninitialized memory - address provided as a parameter -----------------------
    let asm_op = format!("mem_loadw_le.{addr}");

    let test = build_op_test!(asm_op, &[5, 6, 7, 8]);
    test.expect_stack(&[0, 0, 0, 0]);

    // --- the rest of the stack is unchanged -----------------------------------------------------

    let test = build_op_test!(asm_op, &[5, 6, 7, 8, 1, 2, 3, 4]);
    test.expect_stack(&[0, 0, 0, 0, 1, 2, 3, 4]);
}

// SAVING A WORD INTO MEMORY (MSTOREW)
// ================================================================================================

#[test]
fn mem_storew() {
    let asm_op = "mem_storew_le";
    let addr = 0_u32;

    // --- address provided via the stack ---------------------------------------------------------
    let test = build_op_test!(asm_op, &[addr as u64, 1, 2, 3, 4]);
    test.expect_stack_and_memory(&[1, 2, 3, 4], addr, &[1, 2, 3, 4]);

    // --- address provided as a parameter --------------------------------------------------------
    let asm_op = format!("mem_storew_le.{addr}");
    let test = build_op_test!(&asm_op, &[1, 2, 3, 4]);
    test.expect_stack_and_memory(&[1, 2, 3, 4], addr, &[1, 2, 3, 4]);

    // --- the rest of the stack is unchanged -----------------------------------------------------
    let test = build_op_test!(&asm_op, &[1, 2, 3, 4, 0]);
    test.expect_stack_and_memory(&[1, 2, 3, 4, 0], addr, &[1, 2, 3, 4]);
}

// LOADING A WORD FROM MEMORY WITH ENDIANNESS (MEM_LOADW_BE/LE)
// ================================================================================================

#[test]
fn mem_loadw_be_le() {
    const ADDR: u32 = 4;
    const INPUT_IMM: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const INPUT_ADDR: [u64; 9] = [ADDR as u64, 1, 2, 3, 4, 5, 6, 7, 8];
    const OUTPUT: [u64; 8] = [0, 0, 0, 0, 5, 6, 7, 8];
    const MEM_EMPTY: [u64; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

    // Classic
    {
        let asm_op = "mem_loadw_be";
        let test = build_op_test!(asm_op, &INPUT_ADDR);
        test.expect_stack_and_memory(&OUTPUT, 0, &MEM_EMPTY);

        let asm_op = format!("mem_loadw_be.{ADDR}");
        let test = build_op_test!(&asm_op, &INPUT_IMM);
        test.expect_stack_and_memory(&OUTPUT, 0, &MEM_EMPTY);
    }

    // Big-endian (equivalent to classic)
    {
        let asm_op = "mem_loadw_be";
        let test = build_op_test!(asm_op, &INPUT_ADDR);
        test.expect_stack_and_memory(&OUTPUT, 0, &MEM_EMPTY);

        let asm_op = format!("mem_loadw_be.{ADDR}");
        let test = build_op_test!(&asm_op, &INPUT_IMM);
        test.expect_stack_and_memory(&OUTPUT, 0, &MEM_EMPTY);
    }

    // Little-endian
    {
        let asm_op = "mem_loadw_le";
        let test = build_op_test!(asm_op, &INPUT_ADDR);
        test.expect_stack_and_memory(&OUTPUT, 0, &MEM_EMPTY);

        let asm_op = format!("mem_loadw_le.{ADDR}");
        let test = build_op_test!(&asm_op, &INPUT_IMM);
        test.expect_stack_and_memory(&OUTPUT, 0, &MEM_EMPTY);
    }
}

// STORING A WORD TO MEMORY WITH ENDIANNESS (MEM_STOREW_BE/LE)
// ================================================================================================

#[test]
fn mem_storew_be_le() {
    const ADDR: u32 = 4;
    // Stack [1,2,3,4,5,6,7,8] with 1 on top - word to store is [1,2,3,4]
    const INPUT_IMM: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    // Stack [ADDR,1,2,3,4,5,6,7,8] with ADDR on top - word to store is [1,2,3,4]
    const INPUT_ADDR: [u64; 9] = [ADDR as u64, 1, 2, 3, 4, 5, 6, 7, 8];
    const OUTPUT: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const MEM_BE: [u64; 8] = [0, 0, 0, 0, 4, 3, 2, 1];
    const MEM_LE: [u64; 8] = [0, 0, 0, 0, 1, 2, 3, 4];

    // mem_storew_be
    {
        let asm_op = "mem_storew_be";
        let test = build_op_test!(asm_op, &INPUT_ADDR);
        test.expect_stack_and_memory(&OUTPUT, 0, &MEM_BE);

        let asm_op = format!("mem_storew_be.{ADDR}");
        let test = build_op_test!(asm_op, &INPUT_IMM);
        test.expect_stack_and_memory(&OUTPUT, 0, &MEM_BE);
    }

    // mem_storew_be (duplicate)
    {
        let asm_op = "mem_storew_be";
        let test = build_op_test!(asm_op, &INPUT_ADDR);
        test.expect_stack_and_memory(&OUTPUT, 0, &MEM_BE);

        let asm_op = format!("mem_storew_be.{ADDR}");
        let test = build_op_test!(asm_op, &INPUT_IMM);
        test.expect_stack_and_memory(&OUTPUT, 0, &MEM_BE);
    }

    // mem_storew_le
    {
        let asm_op = "mem_storew_le";
        let test = build_op_test!(asm_op, &INPUT_ADDR);
        test.expect_stack_and_memory(&OUTPUT, 0, &MEM_LE);

        let asm_op = format!("mem_storew_le.{ADDR}");
        let test = build_op_test!(asm_op, &INPUT_IMM);
        test.expect_stack_and_memory(&OUTPUT, 0, &MEM_LE);
    }
}

// ENDIANNESS ROUNDTRIP TESTS
// ================================================================================================

#[test]
fn mem_endianness_roundtrip() {
    const ADDR: u32 = 4;
    // Stack [1,2,3,4,5,6,7,8] with 1 on top
    const INPUT: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const OUTPUT: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const OUTPUT_REVERSED_WORD: [u64; 8] = [4, 3, 2, 1, 5, 6, 7, 8];
    const MEM_BE: [u64; 8] = [0, 0, 0, 0, 4, 3, 2, 1];
    const MEM_LE: [u64; 8] = [0, 0, 0, 0, 1, 2, 3, 4];

    // Sanity check for input/output constants
    {
        let ops = "nop";
        let test = build_op_test!(ops, &INPUT);
        test.expect_stack(&OUTPUT);
    }

    // Round trip with same ordering only affects memory
    {
        // Classic (big-endian)
        let ops = format!("mem_storew_be.{ADDR} mem_loadw_be.{ADDR}");
        let test = build_op_test!(ops, &INPUT);
        test.expect_stack_and_memory(&OUTPUT, 0, &MEM_BE);

        // Big-endian (equivalent to classic)
        let ops = format!("mem_storew_be.{ADDR} mem_loadw_be.{ADDR}");
        let test = build_op_test!(ops, &INPUT);
        test.expect_stack_and_memory(&OUTPUT, 0, &MEM_BE);

        // Little-endian
        let ops = format!("mem_storew_le.{ADDR} mem_loadw_le.{ADDR}");
        let test = build_op_test!(ops, &INPUT);
        test.expect_stack_and_memory(&OUTPUT, 0, &MEM_LE);
    }

    // Using opposite orderings reverses the top word on the stack
    {
        let ops = format!("mem_storew_be.{ADDR} mem_loadw_le.{ADDR}");
        let test = build_op_test!(ops, &INPUT);
        test.expect_stack_and_memory(&OUTPUT_REVERSED_WORD, 0, &MEM_BE);

        let ops = format!("mem_storew_le.{ADDR} mem_loadw_be.{ADDR}");
        let test = build_op_test!(ops, &INPUT);
        test.expect_stack_and_memory(&OUTPUT_REVERSED_WORD, 0, &MEM_LE);
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
            push.0
            mem_storew_le
            dropw
            push.4
            mem_storew_le
            dropw
            push.12.11.10.9.8.7.6.5.4.3.2.1
            mem_stream

            exec.truncate_stack
        end"
    );

    // Stack [1, 2, 3, 4, 5, 6, 7, 8] with 1 on top
    let inputs = [1, 2, 3, 4, 5, 6, 7, 8];

    // the state is built by replacing the values on the top of the stack with the values in memory
    // Memory stores words at addresses 0 and 4 which are loaded into the rate portion.
    // Due to BE storage and load, the values are reversed when loaded back.
    let mut final_stack: Vec<u64> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    final_stack.push(8); // address after reading 2 words (8 elements)

    let test = build_test!(source, &inputs);
    test.expect_stack(&final_stack);
}

#[test]
fn mem_stream_with_hperm() {
    let source = format!(
        "
        {TRUNCATE_STACK_PROC}

        begin
            push.0
            mem_storew_le
            dropw
            push.4
            mem_storew_le
            dropw
            push.12.11.10.9.8.7.6.5.4.3.2.1
            mem_stream hperm

            exec.truncate_stack
        end"
    );

    let inputs = [1, 2, 3, 4, 5, 6, 7, 8];

    let mut state: [Felt; 12] =
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].to_elements().try_into().unwrap();

    // apply a hash permutation to the state
    apply_permutation(&mut state);

    // Hasher state order matches stack order
    let mut final_stack = state.iter().map(|&v| v.as_canonical_u64()).collect::<Vec<u64>>();
    final_stack.push(8); // address after reading 2 words (8 elements)

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
    let final_stack = inputs;

    let test = build_test!(source, &inputs);
    test.expect_stack(&final_stack);

    // --- storew and loadw are inverse operations, so the stack should be left unchanged ---------
    let source = "
        begin
            push.0
            mem_storew_le
            mem_storew_le.4
            push.4
            mem_loadw_le
            mem_loadw_le.0
        end";

    let inputs = [0, 1, 2, 3, 4];
    let final_stack = inputs;

    let test = build_test!(source, &inputs);
    test.expect_stack(&final_stack);
}

#[test]
fn read_after_write() {
    // --- write to memory first, then test read with push --------------------------------------
    // Stack [1, 2, 3, 4] with 1 on top - stores to memory, then reads back mem[0]
    let test = build_op_test!("mem_storew_le.0 mem_load.0", &[1, 2, 3, 4]);
    test.expect_stack(&[1, 1, 2, 3, 4]);

    // --- write to memory first, then test read with pushw --------------------------------------
    // Stack [1, 2, 3, 4] - store then load whole word back
    let test = build_op_test!("mem_storew_le.0 padw mem_loadw_le.0", &[1, 2, 3, 4]);
    test.expect_stack(&[1, 2, 3, 4, 1, 2, 3, 4]);

    // --- write to memory first, then test read with loadw --------------------------------------
    // Stack [1, 2, 3, 4, 5, 6, 7, 8] - store first word, drop it, load it back
    let test = build_op_test!("mem_storew_le.0 dropw mem_loadw_le.0", &[1, 2, 3, 4, 5, 6, 7, 8]);
    test.expect_stack(&[1, 2, 3, 4]);
}
